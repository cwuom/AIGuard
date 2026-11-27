package guard

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"aiguard/internal/core"
)

const (
	// 自动检测时：游戏/加速器退出后再等这么久才退出游戏模式，避免重开游戏、切换房间时来回切换
	gameLingerMs = 60000
	// 进出游戏模式会重载内核配置，TUN 可能短暂重建，这段时间不按「TUN 丢失」熔断
	gameExitGraceMs = 15000
	appHistoryLimit = 300
	// 游戏模式中查杀 AI 程序的间隔
	gameScanMs = 1500
)

func (g *Guardian) gameScanInterval() int64 {
	if g.gameActive {
		return gameScanMs
	}
	return 5000
}

// updateGame 每秒在 tick 里调用：扫描进程、决定是否处于游戏模式；游戏模式中持续关闭 AI 程序并把新出现的拉黑
func (g *Guardian) updateGame(ctx context.Context, now int64) {
	s := g.settings
	var scan *AppScan
	// 即将手动进入游戏模式时立即扫一遍，进入的同时就能拉黑并关闭正在运行的 AI 程序
	entering := s.GameMode && !g.gameActive
	if (s.GameAutoDetect || s.GameMode || g.gameActive) && (entering || elapsed(now, g.lastAppScan, g.gameScanInterval())) {
		g.lastAppScan = &now
		extraAI, extraGame := s.ExtraAIProcesses, s.ExtraGameProcesses
		result := outside(g, func() AppScan { return g.options.System.ScanApps(extraAI, extraGame) })
		if !g.active(ctx) || !g.settings.Enabled || g.suspended {
			return
		}
		scan = &result
		g.rememberApps(result)
		if found := append(append([]string{}, result.Accelerators...), result.Games...); len(found) > 0 {
			g.gameSeenAt = &now
			g.gameDetected = strings.Join(found[:min(len(found), 2)], "、")
		}
	}
	s = g.settings
	want, reason := false, ""
	switch {
	case s.GameMode:
		want, reason = true, core.GameReasonManual
	case s.GameAutoDetect && g.gameSeenAt != nil && now-*g.gameSeenAt < gameLingerMs:
		want, reason = true, "检测到 "+g.gameDetected
	}
	if want != g.gameActive {
		g.setGame(ctx, want, reason, scan)
		return
	}
	g.gameReason = reason
	if g.gameActive && scan != nil {
		g.addGameApps(*scan)
		if scan.AIRunning || len(scan.AI) > 0 {
			g.closeAIForGame()
		}
	}
}

// rememberApps 记下见过的 AI 程序路径：下次进游戏模式时它们没在运行也会先被禁止联网
func (g *Guardian) rememberApps(scan AppScan) {
	changed := false
	for _, exe := range scan.AI {
		if indexFold(g.appHistory, exe) < 0 {
			g.appHistory = append(g.appHistory, exe)
			changed = true
		}
	}
	if !changed {
		return
	}
	g.appHistory = g.appHistory[max(0, len(g.appHistory)-appHistoryLimit):]
	if g.options.Paths.AppHistory != "" {
		if err := writeJSON(g.options.Paths.AppHistory, g.appHistory); err != nil {
			g.writeLog("[warning] AI 程序记录写入失败：" + err.Error())
		}
	}
}

func indexFold(list []string, s string) int {
	for i, v := range list {
		if strings.EqualFold(v, s) {
			return i
		}
	}
	return -1
}

// merge 把 add 里没有的路径加进 list，返回是否有新增
func merge(list *[]string, add ...[]string) bool {
	changed := false
	for _, a := range add {
		for _, p := range a {
			if p != "" && indexFold(*list, p) < 0 {
				*list = append(*list, p)
				changed = true
			}
		}
	}
	if changed {
		slices.Sort(*list)
	}
	return changed
}

func (g *Guardian) setGame(ctx context.Context, on bool, reason string, scan *AppScan) {
	g.gameActive, g.gameReason = on, reason
	g.gameFlag.Store(on)
	g.runtime.Game = on
	g.blockApps, g.tunOnlyApps = nil, nil
	if on {
		merge(&g.blockApps, g.appHistory)
		if scan != nil {
			merge(&g.blockApps, scan.AI)
			merge(&g.tunOnlyApps, scan.Known, scan.Browsers)
		}
		g.tunLostSince = nil
	}
	g.gameExitAt = new(g.mono())
	// 防火墙没换成功就放弃进入：AI 程序还没被封死，不能宣称已进入游戏模式
	if err := g.applyProtection(); err != nil && on {
		g.gameActive, g.gameReason, g.runtime.Game, g.blockApps, g.tunOnlyApps = false, "", false, nil, nil
		g.gameFlag.Store(false)
		g.applyProtection()
		g.log(core.EventCritical, "游戏模式没能开启：防火墙规则写入失败（"+err.Error()+"），保持正常防护")
		return
	}
	if on {
		g.log(core.EventWarning, fmt.Sprintf("已进入游戏模式（%s）：AI 服务一律禁止，AI 程序全部关闭且禁止联网（已拉黑 %d 个），其余流量直连", reason, len(g.blockApps)))
		g.closeAIForGame()
		g.reloadCore(ctx, "进入游戏模式")
	} else {
		g.log(core.EventInfo, "已退出游戏模式，恢复全局防泄漏")
		g.reloadCore(ctx, "退出游戏模式")
	}
}

// addGameApps 把游戏模式中新出现的 AI 程序与浏览器加进名单
func (g *Guardian) addGameApps(scan AppScan) {
	ai := merge(&g.blockApps, scan.AI)
	browsers := merge(&g.tunOnlyApps, scan.Browsers)
	if ai || browsers {
		g.applyProtection()
	}
}

// closeAIForGame 关闭全部 AI 程序：游戏模式下 AI 服务一律禁止，不看「熔断时关闭」的开关
func (g *Guardian) closeAIForGame() {
	extra := g.settings.ExtraAIProcesses
	g.launch(func(ctx context.Context) {
		stillWanted := func() bool { return ctx.Err() == nil && g.gameFlag.Load() }
		closed := outside(g, func() []string {
			g.appIO.Lock()
			defer g.appIO.Unlock()
			if !stillWanted() {
				return nil
			}
			return g.options.System.CloseApps(KindAI, extra, stillWanted)
		})
		if len(closed) > 0 {
			g.log(core.EventWarning, "游戏模式：已关闭 "+strings.Join(closed, "、")+"（游戏模式下 AI 服务一律禁止）")
		}
	})
}

// aiRanges 把 AI 名单里的 IPv4 段换成前缀，游戏模式防火墙用
func aiRanges(s core.GuardSettings) []netip.Prefix {
	var out []netip.Prefix
	for _, cidr := range core.AIIPv4Ranges(s.DisabledAICategories) {
		if p, err := netip.ParsePrefix(cidr); err == nil && p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out
}

// leaveGame 在关闭守护时清掉游戏模式状态（防火墙与内核由关闭流程自己处理）
func (g *Guardian) leaveGame() {
	g.gameActive, g.gameReason, g.gameSeenAt = false, "", nil
	g.gameFlag.Store(false)
	g.runtime.Game = false
	g.blockApps, g.tunOnlyApps = nil, nil
}
