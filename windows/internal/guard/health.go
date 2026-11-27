package guard

import (
	"context"
	"slices"
	"strings"
	"time"

	"aiguard/internal/core"
	"aiguard/internal/winsys"
)

func (g *Guardian) tick(ctx context.Context) {
	now := g.mono()
	if g.captiveUntil != nil && now >= *g.captiveUntil && !g.suspended {
		g.captiveUntil = nil
		g.log(core.EventInfo, "Wi-Fi 登录模式结束，恢复正常出站")
		g.engine.Update(g.fuseConfig(), now)
		g.applyProtection()
		g.reloadCore(ctx, "Wi-Fi 登录结束")
	}
	g.detectSuspend(now)
	// 唤醒通知可能丢失（例如睡眠中途失败）：强制断网 15 秒后还没收到就按已唤醒处理，避免永久断网
	if g.suspended && now-g.suspendedAt > 15000 {
		g.log(core.EventWarning, "没有收到唤醒通知，按已唤醒处理")
		g.resumeLocked()
	}
	if !g.settings.Enabled || g.suspended || !g.active(ctx) {
		return
	}
	if g.wantCore && !g.options.Core.Running() && g.nextRestartAt != nil && now >= *g.nextRestartAt {
		g.startCore(ctx)
	}
	if g.options.Core.Running() {
		epoch := g.epoch
		_, ok := outside2(g, func() (string, bool) { return g.api.Version(ctx) })
		if !g.current(ctx, epoch) {
			return
		}
		g.apiUp = ok
		if ok {
			g.apiFailures = 0
		} else {
			g.apiFailures++
			if g.apiFailures >= 5 {
				g.log(core.EventWarning, "代理内核没有响应，已强制重启")
				g.apiFailures = 0
				g.stopCore()
				g.options.Core.NoteRestart()
				g.startCore(ctx)
			}
		}
	} else {
		g.apiUp = false
	}
	if !g.settings.Enabled || g.suspended || !g.active(ctx) {
		return
	}
	g.updateGame(ctx, now)
	if !g.settings.Enabled || g.suspended || !g.active(ctx) {
		return
	}
	if g.coreStartedAt != nil && now-*g.coreStartedAt > 60000 && g.apiUp {
		g.restartBackoffMs = 1000
	}
	ifaces, route, ok := g.readInterfaces(ctx)
	if !ok {
		return
	}
	g.updateTun(ifaces)
	coreUp := g.options.Core.Running() && g.apiFailures < 2
	g.tunUp = coreUp && g.tunLUID != 0 && g.tunLUID == route
	// 游戏模式下加速器可能接管部分路由，TUN 不是默认路由也不熔断（AI 程序已被封死，浏览器只能经 TUN）；
	// 进出游戏模式重载配置时 TUN 可能短暂重建，也不算丢失
	tunOK := g.tunUp || (coreUp && (g.gameActive || (g.gameExitAt != nil && now-*g.gameExitAt < gameExitGraceMs)))
	g.engine.Handle(core.Health{CoreUp: coreUp, TunUp: tunOK}, g.mono())
	fp := winsys.Fingerprint(ifaces)
	changed := g.lastFingerprint != nil && fp != *g.lastFingerprint
	g.lastFingerprint = &fp
	if changed && !g.networkChanged(ctx, winsys.Primary(ifaces, route)) {
		return
	}
	if g.gameActive {
		g.tunLostSince = nil
	} else if g.checkTun(ctx, now, coreUp) {
		return
	}

	ipv6Interval := int64(30000)
	if g.engine.Snapshot().Tripped {
		ipv6Interval = 5000
	}
	if elapsed(now, g.lastIPv6Check, ipv6Interval) {
		g.lastIPv6Check = &now
		epoch := g.epoch
		leaking := outside(g, func() bool { return g.options.System.IPv6Reachable(2 * time.Second) })
		if !g.current(ctx, epoch) {
			return
		}
		if leaking && (g.ipv6Blocked == nil || *g.ipv6Blocked) {
			g.log(core.EventCritical, "IPv6 能直连公网，已熔断")
		}
		g.ipv6Blocked = new(!leaking)
		g.engine.Handle(core.IPv6{Leaking: leaking}, g.mono())
	}

	verifyInterval := int64(5000)
	if now-g.bootedAt < 120000 {
		verifyInterval = 1000
	}
	if elapsed(now, g.lastFirewallVerify, verifyInterval) {
		g.lastFirewallVerify = &now
		issue := g.options.Firewall.Verify()
		if issue != "" && !g.hookWarningShown {
			g.log(core.EventCritical, issue)
		}
		g.hookWarningShown = issue != ""
	}
	g.applyProtection()
	g.applyGates(ctx, false)
	g.closeAppsIfNeeded()

	if !g.settings.Enabled || g.suspended || !g.active(ctx) {
		return
	}
	if elapsed(now, g.lastSlowWork, 30000) {
		g.lastSlowWork = &now
		g.slowWork(ctx)
	}
	if !g.settings.Enabled || g.suspended || !g.active(ctx) {
		return
	}
	if g.lastSubscriptionCheck == nil {
		g.lastSubscriptionCheck = &now
	} else if now-*g.lastSubscriptionCheck > 600000 {
		g.lastSubscriptionCheck = &now
		g.autoRefreshSubscription(ctx)
	}
}

func (g *Guardian) checkTun(ctx context.Context, now int64, coreUp bool) bool {
	if !coreUp || g.tunUp {
		g.tunLostSince = nil
		if g.tunUp && g.lastAutoRestart != nil && now-*g.lastAutoRestart > 120000 {
			g.autoRestartCount = 0
		}
		return false
	}
	if g.tunLostSince == nil {
		g.tunLostSince = &now
	}
	if g.autoRestartCount >= 5 {
		if g.autoRestartCount == 5 {
			g.autoRestartCount++
			g.log(core.EventCritical, "TUN 路由一直被占用，已停止自动重启。请关闭其他 VPN/代理后点「重启内核」")
		}
		return false
	}
	settled := g.lastCoreTransition == nil || now-*g.lastCoreTransition > 20000
	cooldown := min(int64(60000)<<g.autoRestartCount, 600000)
	cooled := g.lastAutoRestart == nil || now-*g.lastAutoRestart > cooldown
	if now-*g.tunLostSince >= 8000 && settled && cooled {
		g.autoRestartCount++
		g.restartCore(ctx, "TUN 路由被破坏（可能是其他 VPN 或代理模块抢占了路由），自动重建")
		return true
	}
	return false
}

func (g *Guardian) detectSuspend(now int64) {
	up := g.options.Clock.Unbiased()
	if g.lastTickMono != nil && (now-*g.lastTickMono)-(up-g.lastTickUnbiased) > 10000 {
		g.fetcher.ResetAll(g.ctx)
		g.epoch++
		g.lastIPv6Check = nil
		// 睡过一觉却没收到睡眠通知（或 Suspend 已被兜底解除）：与 macOS 一致，唤醒一律按换网熔断重新验证
		if g.settings.Enabled && !g.suspended {
			g.engine.Handle(core.NetworkChanged{}, now)
			g.applyProtection()
			g.log(core.EventWarning, "检测到系统刚从睡眠中唤醒，重新验证线路")
		}
	}
	g.lastTickMono = &now
	g.lastTickUnbiased = up
}

func (g *Guardian) readInterfaces(ctx context.Context) ([]winsys.Iface, uint64, bool) {
	epoch := g.epoch
	ifaces, route := outside2(g, func() ([]winsys.Iface, uint64) {
		ifaces, _ := g.options.System.Interfaces()
		return ifaces, g.options.System.DefaultRouteLUID()
	})
	return ifaces, route, g.current(ctx, epoch)
}

func (g *Guardian) updateTun(ifaces []winsys.Iface) {
	g.tunLUID, g.tunInterface = 0, ""
	if tun := winsys.FindTun(ifaces); tun != nil {
		g.tunLUID, g.tunInterface = tun.LUID, tun.Alias
	}
}

func (g *Guardian) networkChanged(ctx context.Context, primary string) bool {
	g.primaryInterface = primary
	if !g.settings.Enabled {
		return false
	}
	g.epoch++
	epoch := g.epoch
	g.engine.Handle(core.NetworkChanged{}, g.mono())
	g.applyProtection()
	if primary == "" {
		primary = "无网络"
	}
	g.log(core.EventInfo, "网络已切换（"+primary+"），重新验证线路")
	g.fetcher.ResetAll(ctx)
	g.lastIPv6Check = nil
	g.syncSystemNetwork(false)
	if g.settings.Enabled && !g.suspended {
		g.flushConnections(ctx)
	}
	return g.current(ctx, epoch)
}

func (g *Guardian) syncSystemNetwork(finishingDisable bool) {
	g.mu.Unlock()
	g.networkIO.Lock()
	g.mu.Lock()
	defer g.networkIO.Unlock()
	if !g.active(g.ctx) && !(finishingDisable && !g.settings.Enabled) {
		return
	}
	s := g.settings
	epoch := g.epoch
	failed, changed := outside2(g, func() ([]string, bool) {
		ifaces, _ := g.options.System.Interfaces()
		var failed []string
		if s.Enabled && s.DisableSystemIPv6 {
			failed = g.options.System.DisableIPv6(ifaces)
		} else {
			g.options.System.RestoreIPv6()
		}
		changed := false
		if s.Enabled && s.LockSystemDNS {
			changed, _ = g.options.System.LockDNS(ifaces)
		} else {
			g.options.System.RestoreDNS()
		}
		return failed, changed
	})
	if !g.current(g.ctx, epoch) || s.Enabled != g.settings.Enabled || s.DisableSystemIPv6 != g.settings.DisableSystemIPv6 || s.LockSystemDNS != g.settings.LockSystemDNS {
		return
	}
	if len(failed) > 0 {
		g.log(core.EventWarning, "以下网卡的 IPv6 无法关闭，仅靠防火墙封锁："+strings.Join(failed, "、"))
	}
	if changed {
		g.log(core.EventInfo, "已把各网卡 DNS 锁定到内核（关闭守护时恢复）")
	}
}

func (g *Guardian) slowWork(ctx context.Context) {
	clear(g.appliedGates)
	g.applyGates(ctx, false)
	if !g.settings.Enabled || g.suspended || !g.active(ctx) {
		return
	}
	epoch := g.epoch
	withTunnels := !g.gameActive
	found := outside(g, func() []string { return g.options.System.ScanConflicts(withTunnels) })
	if !g.current(ctx, epoch) {
		return
	}
	if !slices.Equal(found, g.conflicts) {
		g.conflicts = found
		if len(found) > 0 {
			g.log(core.EventWarning, "检测到其他代理软件："+strings.Join(found, "、")+"，可能抢占路由")
		}
	}
	if g.runtime.HasSubscription && g.apiUp {
		group, _ := outside2(g, func() (*core.GroupInfo, bool) { return g.api.Group(ctx, core.GroupProxy) })
		if !g.current(ctx, epoch) {
			return
		}
		g.nodeCount = nil
		if group != nil {
			count := 0
			for _, name := range group.All {
				if name != core.GroupAuto {
					count++
				}
			}
			g.nodeCount = &count
		}
		if g.lastAllowRefresh == nil || g.mono()-*g.lastAllowRefresh > 600000 {
			g.refreshAllowList(ctx)
		}
	}
	g.recheckDNS(ctx)
	g.persistEvents()
}

func (g *Guardian) recheckDNS(ctx context.Context) {
	now := g.mono()
	if !g.settings.Enabled || !g.settings.LockSystemDNS || !elapsed(now, g.lastDNSCheck, 60000) {
		return
	}
	g.mu.Unlock()
	g.networkIO.Lock()
	g.mu.Lock()
	defer g.networkIO.Unlock()
	if !g.settings.Enabled || !g.settings.LockSystemDNS || g.suspended || !g.active(ctx) {
		return
	}
	g.lastDNSCheck = &now
	epoch := g.epoch
	changed := outside(g, func() bool {
		ifaces, _ := g.options.System.Interfaces()
		changed, _ := g.options.System.LockDNS(ifaces)
		return changed
	})
	if changed && g.current(ctx, epoch) && g.settings.Enabled && g.settings.LockSystemDNS {
		g.log(core.EventWarning, "网卡 DNS 被改动，已重新锁定（否则 DNS 会绕过内核）")
	}
}
