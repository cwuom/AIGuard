package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"aiguard/internal/core"
)

func (g *Guardian) Handle(ctx context.Context, raw []byte) []byte {
	var envelope core.IpcEnvelope
	if len(raw) > core.MaxMessageBytes {
		return encodeResponse(core.FailureResponse("请求格式错误：消息超过 4 MiB 上限"))
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return encodeResponse(core.FailureResponse("请求格式错误：" + limitRunes(err.Error(), 120)))
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.active(g.ctx) {
		return encodeResponse(core.FailureResponse("守护服务正在停止"))
	}
	if ctx.Err() != nil {
		return encodeResponse(core.FailureResponse("请求已取消"))
	}
	g.work.Add(1)
	defer g.work.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(g.ctx, cancel)
	defer stop()
	return encodeResponse(g.handleRequest(ctx, envelope.Request))
}

func limitRunes(value string, limit int) string {
	for i := range value {
		if limit == 0 {
			return value[:i]
		}
		limit--
	}
	return value
}

func encodeResponse(res core.IpcResponse) []byte {
	raw, err := json.Marshal(res)
	if err != nil {
		raw, _ = json.Marshal(core.FailureResponse("响应编码失败"))
	}
	return raw
}

func (g *Guardian) handleRequest(ctx context.Context, req core.Request) core.IpcResponse {
	switch req.Type {
	case core.RequestStatus:
		return g.statusResponse()
	case core.RequestGetSettings:
		return core.IpcResponse{OK: true, Settings: &g.settings}
	case core.RequestUpdateSettings:
		failure := g.updateSettings(ctx, *req.Settings)
		res := g.statusResponse()
		res.OK, res.Error, res.Settings = failure == nil, failure, &g.settings
		return res
	case core.RequestImportSubscription, core.RequestRefreshSubscription, core.RequestRemoveSubscription:
		return g.handleSubscription(ctx, req)
	case core.RequestTripFuse:
		g.engine.Handle(core.ManualTrip{}, g.mono())
		g.applyProtection()
		return g.statusResponse()
	case core.RequestRestoreNetwork:
		g.engine.Handle(core.ManualRestore{Force: req.Force}, g.mono())
		if req.Force {
			g.log(core.EventWarning, "用户强制恢复网络（跳过线路验证）")
		}
		g.applyProtection()
		return g.statusResponse()
	case core.RequestCaptiveLogin:
		minutes := min(max(req.Minutes, 1), 10)
		g.captiveUntil = new(g.mono() + int64(minutes)*60000)
		g.log(core.EventInfo, fmt.Sprintf("Wi-Fi 登录模式：%d 分钟内直连，AI 仍被阻断", minutes))
		g.engine.Update(g.fuseConfig(), g.mono())
		g.applyProtection()
		g.reloadCore(ctx, "Wi-Fi 登录")
		return g.statusResponse()
	case core.RequestEndCaptiveLogin:
		if g.captiveUntil != nil {
			g.captiveUntil = new(g.mono())
			g.tick(ctx)
		}
		return g.statusResponse()
	case core.RequestControllerInfo:
		return core.IpcResponse{OK: true, Controller: &core.ControllerInfo{BaseURL: g.options.ControllerURL, Secret: g.runtime.Secret}}
	case core.RequestEvents:
		after := req.After
		if after >= g.nextEventID {
			after = 0
		}
		events := make([]core.GuardEvent, 0, len(g.events))
		for _, event := range g.events {
			if event.ID > after {
				events = append(events, event)
			}
		}
		return core.IpcResponse{OK: true, Events: &events, EventsGeneration: &g.eventsGeneration}
	case core.RequestClearEvents:
		if err := writeJSON(g.options.Paths.Events, []core.GuardEvent{}); err != nil {
			return core.FailureResponse("事件记录没能写入磁盘，未清空")
		}
		g.events = nil
		g.eventsDirty = false
		g.eventsGeneration = eventGeneration()
		g.writeLog("[info] 用户清空了事件记录")
		return core.IpcResponse{OK: true, EventsGeneration: &g.eventsGeneration}
	case core.RequestFlushConnections:
		g.flushConnections(ctx)
		return core.DefaultIpcResponse()
	case core.RequestRestartCore:
		if !g.settings.Enabled {
			return core.FailureResponse("守护已关闭")
		}
		if g.restarting {
			return core.FailureResponse("内核正在重启")
		}
		g.autoRestartCount = 0
		g.restartCore(ctx, "用户手动重启")
		if !g.apiUp {
			return core.FailureResponse("内核没有启动成功，查看「事件」里的原因")
		}
		return g.statusResponse()
	}
	return core.FailureResponse("请求格式错误：未知请求类型")
}

func (g *Guardian) handleSubscription(ctx context.Context, req core.Request) core.IpcResponse {
	g.mu.Unlock()
	g.subscriptionIO.Lock()
	g.mu.Lock()
	defer g.subscriptionIO.Unlock()
	if !g.active(ctx) {
		return core.FailureResponse("请求已取消")
	}
	switch req.Type {
	case core.RequestImportSubscription:
		return g.importSubscription(ctx, req.URL)
	case core.RequestRefreshSubscription:
		return g.refreshSubscription(ctx, true)
	default:
		os.Remove(g.options.Paths.ProviderFile)
		os.Remove(g.options.Paths.ProviderFile + ".bak")
		g.settings.Subscription = nil
		g.runtime.HasSubscription = false
		g.saveSettings()
		g.engine.Update(g.fuseConfig(), g.mono())
		g.applyProtection()
		g.reloadCore(ctx, "移除订阅")
		g.log(core.EventInfo, "订阅已移除，进入直连阻断模式")
		return g.statusResponse()
	}
}

func (g *Guardian) updateSettings(ctx context.Context, incoming core.GuardSettings) *string {
	old := g.settings
	next := incoming.Sanitized()
	next.Subscription = old.Subscription
	g.settings = next
	g.enabled.Store(next.Enabled)
	if old.Enabled != next.Enabled {
		g.epoch++
	}
	g.saveSettings()
	g.engine.Update(g.fuseConfig(), g.mono())

	configChanged := old.Mode != next.Mode || old.DirectOnlyMainland != next.DirectOnlyMainland ||
		!slices.Equal(old.DisabledAICategories, next.DisabledAICategories) || !slices.Equal(old.CustomAIDomains, next.CustomAIDomains) ||
		!slices.Equal(old.CustomDirectDomains, next.CustomDirectDomains) || !slices.Equal(old.CustomProxyDomains, next.CustomProxyDomains) ||
		!slices.Equal(old.ForbiddenRegions, next.ForbiddenRegions)
	if configChanged {
		g.configApplyPending = true
	}
	if !slices.Equal(old.DisabledAICategories, next.DisabledAICategories) {
		g.options.WFContext.AIRanges = aiRanges(next)
		g.options.Firewall.SetContext(g.options.WFContext)
		if g.gameActive {
			g.applyFirewall(g.desiredPolicy(), true)
		}
	}
	disabling := old.Enabled && !next.Enabled
	if old.Enabled != next.Enabled || old.DisableSystemIPv6 != next.DisableSystemIPv6 || old.LockSystemDNS != next.LockSystemDNS {
		g.syncSystemNetwork(disabling)
	}
	// an accepted disable owns network restoration even if shutdown already stopped the core
	if disabling && !g.settings.Enabled {
		g.log(core.EventWarning, "守护已关闭：防火墙、TUN、系统 DNS 锁定全部撤销，AI 不再受保护")
		g.wantCore = false
		g.leaveGame()
		if !g.stopping {
			g.stopCore()
		}
		g.engine.Handle(core.Reset{}, g.mono())
		if g.applyProtection() == nil && g.suspended {
			g.noteFirewallResult(g.options.Firewall.ReleaseForcedLockdown())
			g.suspended = false
		}
		return nil
	}
	if !g.active(g.ctx) {
		return present("请求已取消")
	}
	if old.Enabled != next.Enabled {
		if next.Enabled && g.settings.Enabled {
			g.log(core.EventInfo, "守护已开启")
			g.engine = core.NewFuseEngine(g.fuseConfig(), g.mono(), true)
			g.applyProtection()
			if !g.wantCore || !g.options.Core.Running() {
				g.startCore(g.ctx)
			}
		}
		return nil
	}
	g.applyProtection()
	if old.Routing != next.Routing && g.settings.Routing == next.Routing {
		if next.Routing == core.RoutingSmart {
			g.log(core.EventInfo, "已切换到智能分流")
		} else {
			g.log(core.EventInfo, "已切换到全局代理")
		}
	}
	var failure *string
	if g.configApplyPending && !g.reloadCore(g.ctx, "设置变更") {
		detail := "配置写入失败"
		if g.lastError != nil {
			detail = *g.lastError
		}
		failure = new("设置已保存，但新规则没能生效（" + detail + "），内核仍按旧规则运行")
	}
	g.applyGates(ctx, false)
	return failure
}

func (g *Guardian) statusResponse() core.IpcResponse {
	status := g.snapshotStatus()
	return core.IpcResponse{OK: true, Status: &status}
}

func (g *Guardian) snapshotStatus() core.GuardStatus {
	dnsLocked, ipv6Count := outside2(g, func() (bool, int) {
		return g.options.System.DNSLocked(), g.options.System.IPv6DisabledCount()
	})
	snap := g.engine.Snapshot()
	mono, wall := g.mono(), g.wall()
	phase := core.PhaseProtected
	switch {
	case !g.settings.Enabled:
		phase = core.PhaseDisabled
	case snap.Tripped:
		phase = core.PhaseTripped
	case !g.apiUp:
		phase = core.PhaseError
		if g.wantCore {
			phase = core.PhaseStarting
		}
	case g.firewallFailing || g.hookWarningShown:
		phase = core.PhaseError
	}
	status := core.GuardStatus{
		Version: g.options.Version, Protocol: core.ProtocolVersion, Phase: phase,
		EffectiveMode: g.effectiveMode(), Routing: g.settings.Routing, Fuse: snap, FuseLatched: g.engine.IsLatched(),
		CoreRunning: g.apiUp, CoreVersion: present(g.coreVersion), CoreRestarts: g.options.Core.Restarts(),
		TunUp: g.tunUp, TunInterface: present(g.tunInterface), FirewallPolicy: string(g.options.Firewall.Current().Kind),
		IPv6Blocked: g.ipv6Blocked, IPv6DisabledInterfaces: ipv6Count, SystemDNSLocked: g.settings.Enabled && g.settings.LockSystemDNS && dnsLocked,
		Exit: g.exitStatus, HeartbeatAlive: g.heartbeatAlive, Latency: append([]core.LatencySample{}, g.latency[max(0, len(g.latency)-60):]...),
		PrimaryInterface: present(g.primaryInterface), Conflicts: append([]string{}, g.conflicts...),
		Subscription: g.settings.Subscription, LastError: g.lastError, NodeCount: g.nodeCount, UpdatedAt: wall,
		GameMode: g.settings.Enabled && g.gameActive, GameBlockedApps: len(g.blockApps),
	}
	if status.GameMode {
		status.GameReason = present(g.gameReason)
	}
	if snap.Since != nil {
		status.FuseSince = new(wall - (mono - *snap.Since))
	}
	if snap.HoldUntil != nil && *snap.HoldUntil > mono {
		status.FuseHoldRemainingMs = new(*snap.HoldUntil - mono)
	}
	if g.captiveUntil != nil {
		status.CaptiveUntil = new(wall + (*g.captiveUntil - mono))
	}
	return status
}
