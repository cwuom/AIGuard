package guard

import (
	"context"
	"fmt"
	"strings"
	"time"

	"aiguard/internal/core"
	"aiguard/internal/wfpolicy"
)

func (g *Guardian) desiredPolicy() wfpolicy.Policy {
	if !g.settings.Enabled {
		return wfpolicy.Policy{Kind: wfpolicy.None}
	}
	s := g.engine.Snapshot()
	// 游戏模式下 AI 本来就全部拒绝，熔断不再断整机网络；用户手动熔断除外
	manual := s.Tripped && (g.engine.IsLatched() || (s.Reason != nil && s.Reason.Type == core.ReasonManual))
	if g.gameActive && !manual {
		return wfpolicy.Policy{Kind: wfpolicy.Game, TunLUID: g.tunLUID, Block: g.blockApps, TunOnly: g.tunOnlyApps}
	}
	if s.Tripped {
		if s.Hard {
			return wfpolicy.Policy{Kind: wfpolicy.Lockdown}
		}
		return wfpolicy.Policy{Kind: wfpolicy.Whitelist, TunLUID: g.tunLUID, AllowTun: g.softGatesConfirmed, Allow: g.allowIPs}
	}
	kind := wfpolicy.Basic
	if g.settings.LeakGuard {
		kind = wfpolicy.LeakGuard
	}
	return wfpolicy.Policy{Kind: kind, TunLUID: g.tunLUID}
}

func (g *Guardian) desiredGates() map[string]string {
	s := g.engine.Snapshot()
	proxy, cn, direct := core.GroupProxy, "DIRECT", "DIRECT"
	if s.Tripped || !g.runtime.HasSubscription {
		proxy = "REJECT"
	}
	if s.Tripped && s.Hard {
		cn, direct = "REJECT", "REJECT"
	} else if !s.Tripped && g.runtime.HasSubscription && g.settings.Routing == core.RoutingGlobal {
		cn = core.GroupProxy
	}
	return map[string]string{core.GroupGateAI: proxy, core.GroupGateMain: proxy, core.GroupGateCN: cn, core.GroupGateDirect: direct}
}

func (g *Guardian) noteFirewallResult(err error) {
	if err != nil && !g.firewallFailing {
		message := "防火墙规则加载失败：" + err.Error()
		g.lastError = &message
		g.log(core.EventCritical, message+"，仅剩内核闸门一层防护")
	} else if err == nil && g.firewallFailing {
		g.log(core.EventInfo, "防火墙规则已恢复正常")
	}
	g.firewallFailing = err != nil
}

func (g *Guardian) applyFirewall(p wfpolicy.Policy, force bool) error {
	err := g.options.Firewall.Apply(p, force)
	g.noteFirewallResult(err)
	return err
}

func (g *Guardian) applyProtection() error {
	s := g.engine.Snapshot()
	changed := s.Tripped != g.lastTripped
	if changed {
		g.lastTripped = s.Tripped
		g.gateGeneration++
		g.softGatesConfirmed = false
	}
	err := g.applyFirewall(g.desiredPolicy(), false)
	g.trippedFlag.Store(g.settings.Enabled && s.Tripped)
	if changed {
		if s.Tripped {
			action := "（只放行大陆白名单）"
			if s.Hard {
				action = "（全部断网）"
			}
			g.log(core.EventCritical, "已熔断："+s.Reason.Title()+action)
		} else {
			g.appsClosedThisTrip = false
			g.armedOnce = true
			g.nodeDownLogged = false
			if g.effectiveMode() == core.ModeProxy {
				g.log(core.EventInfo, "已恢复：线路与出口验证通过")
			} else {
				g.log(core.EventInfo, "已恢复：内核与 TUN 就绪，AI 保持阻断")
			}
		}
		g.launch(func(ctx context.Context) { g.applyGates(ctx, s.Tripped) })
	}
	g.closeAppsIfNeeded()
	return err
}

func (g *Guardian) closeEligible() bool {
	s := g.engine.Snapshot()
	if !s.Tripped || s.Reason == nil || !g.armedOnce || !g.settings.Enabled || !g.settings.CloseAppsOnFuse {
		return false
	}
	if s.Reason.IsPrecautionary() && !g.settings.CloseAppsOnGuardTrips {
		return false
	}
	if (s.Reason.Type == core.ReasonCoreDown || s.Reason.Type == core.ReasonTunLost) && !elapsed(g.mono(), g.lastCoreTransition, 20000) {
		return false
	}
	return s.Reason.Type != core.ReasonCoreDown || !g.options.Core.Running() || g.apiFailures >= 3
}

func (g *Guardian) closeAppsIfNeeded() {
	if !g.closeEligible() {
		return
	}
	now := g.mono()
	kinds := KindAI
	if !g.appsClosedThisTrip {
		g.appsClosedThisTrip = true
		kinds |= KindBrowser
	} else if !elapsed(now, g.lastAIScan, 3000) {
		return
	}
	g.lastAIScan = &now
	g.killApps(kinds, "熔断", true)
}

func (g *Guardian) killApps(kinds AppKind, reason string, requireTripped bool) {
	extra := g.settings.ExtraAIProcesses
	g.launch(func(ctx context.Context) {
		stillWanted := func() bool { return ctx.Err() == nil && (!requireTripped || g.trippedFlag.Load()) }
		closed := outside(g, func() []string {
			g.appIO.Lock()
			defer g.appIO.Unlock()
			if !stillWanted() {
				return nil
			}
			return g.options.System.CloseApps(kinds, extra, stillWanted)
		})
		if len(closed) > 0 {
			g.log(core.EventWarning, reason+"：已关闭 "+strings.Join(closed, "、"))
		}
	})
}

func (g *Guardian) applyGates(ctx context.Context, flush bool) {
	if !g.apiUp || g.suspended || !g.active(ctx) {
		return
	}
	// a delayed write must finish before a later pass can confirm a restrictive policy
	g.mu.Unlock()
	g.gateIO.Lock()
	g.mu.Lock()
	defer g.gateIO.Unlock()
	for round := range 3 {
		stale := false
		for _, group := range []string{core.GroupGateAI, core.GroupGateCN, core.GroupGateDirect, core.GroupGateMain} {
			if !g.apiUp || g.suspended || !g.active(ctx) {
				return
			}
			target := g.desiredGates()[group]
			if g.appliedGates[group] == target {
				continue
			}
			generation, epoch := g.gateGeneration, g.epoch
			ok := outside(g, func() bool { return g.api.Select(ctx, group, target) })
			if generation != g.gateGeneration || !g.current(ctx, epoch) || target != g.desiredGates()[group] {
				delete(g.appliedGates, group)
				stale = true
			} else if ok {
				g.appliedGates[group] = target
			}
		}
		if !stale {
			break
		}
		if round == 2 {
			g.writeLog("[warning] 闸门三轮写入仍未与期望一致，下一轮健康检查重试")
		}
	}
	if !g.apiUp || g.suspended || !g.active(ctx) {
		return
	}
	if flush {
		g.flushConnections(ctx)
	}
	if !g.softGatesReady() {
		return
	}
	generation, epoch := g.gateGeneration, g.epoch
	if g.flushConnections(ctx) && generation == g.gateGeneration && g.current(ctx, epoch) && g.softGatesReady() {
		g.softGatesConfirmed = true
		g.applyProtection()
	}
}

func (g *Guardian) softGatesReady() bool {
	s := g.engine.Snapshot()
	return g.settings.Enabled && g.apiUp && !g.suspended && s.Tripped && !s.Hard && !g.softGatesConfirmed &&
		g.coreTransitions == 0 && g.appliedGates[core.GroupGateAI] == "REJECT" && g.appliedGates[core.GroupGateMain] == "REJECT"
}

func (g *Guardian) beginCoreTransition() {
	g.coreTransitions++
	g.lastCoreTransition = new(g.mono())
	g.epoch++
	g.gateGeneration++
	g.softGatesConfirmed = false
	clear(g.appliedGates)
	g.applyProtection()
}

func (g *Guardian) startCore(ctx context.Context) {
	if !g.bootReady || !g.settings.Enabled || g.suspended || !g.active(ctx) {
		return
	}
	g.wantCore = true
	g.nextRestartAt = nil
	g.beginCoreTransition()
	g.startCoreProcess(ctx)
	g.coreTransitions--
	if g.active(ctx) && g.settings.Enabled && !g.suspended {
		g.applyProtection()
		g.applyGates(ctx, false)
	}
}

func (g *Guardian) startCoreProcess(ctx context.Context) {
	if err := g.writeCoreConfig(); err != nil {
		g.lastError = new(err.Error())
		g.log(core.EventCritical, "配置生成失败："+err.Error())
		if !regularFile(g.options.Paths.CoreConfig) {
			return
		}
	}
	g.coreRun++
	run := g.coreRun
	g.options.Core.OnExit(func(code int) {
		go func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.active(g.ctx) && run == g.coreRun {
				g.coreExited(code)
			}
		}()
	})
	if err := g.options.Core.Start(); err != nil {
		message := "内核启动失败：" + err.Error()
		g.lastError = &message
		g.log(core.EventCritical, message)
		g.nextRestartAt = new(g.mono() + g.restartBackoffMs)
		return
	}
	g.coreStartedAt = new(g.mono())
	epoch := g.epoch
	for range 40 {
		_, ok := outside2(g, func() (string, bool) { return g.api.Version(ctx) })
		if !g.current(ctx, epoch) || run != g.coreRun {
			return
		}
		if ok {
			g.apiUp = true
			return
		}
		if !outside(g, func() bool { return wait(ctx, 150*time.Millisecond) }) || !g.current(ctx, epoch) {
			return
		}
	}
}

func (g *Guardian) writeCoreConfig() error {
	yaml := core.BuildMihomoConfig(g.settings, g.runtime, g.captiveUntil != nil, g.primaryInterface)
	return g.options.Core.WriteConfig(yaml)
}

func (g *Guardian) stopCore() {
	g.coreRun++
	g.epoch++
	g.gateGeneration++
	g.softGatesConfirmed = false
	clear(g.appliedGates)
	g.apiUp, g.tunUp = false, false
	g.coreStartedAt = nil
	g.options.Core.Stop()
}

func (g *Guardian) coreExited(code int) {
	g.apiUp, g.tunUp = false, false
	g.epoch++
	g.gateGeneration++
	g.softGatesConfirmed = false
	clear(g.appliedGates)
	if !g.wantCore || !g.settings.Enabled {
		return
	}
	g.options.Core.NoteRestart()
	g.log(core.EventWarning, fmt.Sprintf("代理内核意外退出（退出码 %d），%d 秒后自动重启", code, g.restartBackoffMs/1000))
	g.engine.Handle(core.Health{}, g.mono())
	g.applyProtection()
	g.nextRestartAt = new(g.mono() + g.restartBackoffMs)
	g.restartBackoffMs = min(2*g.restartBackoffMs, 30000)
}

func (g *Guardian) reloadCore(ctx context.Context, reason string) bool {
	g.mu.Unlock()
	g.configIO.Lock()
	g.mu.Lock()
	defer g.configIO.Unlock()
	if !g.wantCore || !g.settings.Enabled || !g.active(ctx) {
		return true
	}
	g.beginCoreTransition()
	ok := g.reloadCoreConfig(g.ctx, reason)
	g.coreTransitions--
	if ok && g.active(g.ctx) {
		g.applyGates(g.ctx, false)
	}
	return ok
}

func (g *Guardian) reloadCoreConfig(ctx context.Context, reason string) bool {
	if err := g.writeCoreConfig(); err != nil {
		g.lastError = new(err.Error())
		g.log(core.EventCritical, "新配置未生效："+err.Error())
		g.configApplyPending = true
		return false
	}
	g.configApplyPending = false
	// a reload belongs to the process even if the network epoch changes
	run := g.coreRun
	reloaded := g.options.Core.Running() && outside(g, func() bool { return g.api.ReloadConfig(ctx, g.options.Paths.CoreConfig) })
	if !g.active(g.ctx) || run != g.coreRun || !g.settings.Enabled || g.suspended {
		return true
	}
	if reloaded {
		g.log(core.EventInfo, "代理配置已更新（"+reason+"）")
	} else {
		message := "配置热更新失败，改为重启内核（" + reason + "）"
		if detail := g.api.LastReloadError(ctx); detail != nil {
			message += "：" + *detail
		}
		g.log(core.EventWarning, message)
		g.stopCore()
		g.startCore(ctx)
	}
	clear(g.appliedGates)
	g.flushConnections(ctx)
	return true
}

func (g *Guardian) restartCore(ctx context.Context, reason string) {
	if g.restarting || !g.active(ctx) || !g.settings.Enabled || g.suspended {
		return
	}
	g.restarting = true
	defer func() { g.restarting = false }()
	g.log(core.EventWarning, "重启内核："+reason)
	if g.settings.CloseAppsOnFuse {
		g.killApps(KindAI, "重启内核前清场", false)
	}
	g.engine.CoreRestarted(g.mono())
	g.applyProtection()
	g.stopCore()
	g.options.Core.NoteRestart()
	g.apiFailures = 0
	g.tunLostSince = nil
	g.lastAutoRestart = new(g.mono())
	g.fetcher.Reset(ctx, &g.runtime.ProbePort)
	g.lastResolvedNode = ""
	g.startCore(g.ctx)
}
