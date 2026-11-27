package guard

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"aiguard/internal/core"
)

type probeFetcher interface {
	Fetch(context.Context, string, *int, int64, int, map[string]string) (*core.FetchResult, bool)
	Heartbeat(context.Context, int, int64) (*core.ExitTrace, bool)
	IPInfo(context.Context, int, int64) (*core.ExitTrace, bool)
	ExitTrace(context.Context, int) (*core.ExitTrace, bool)
	ResolveDirect(context.Context, string, int) ([]string, bool)
	Reset(context.Context, *int)
	ResetAll(context.Context)
}

func (g *Guardian) heartbeat(ctx context.Context) time.Duration {
	interval := time.Duration(g.settings.ProbeIntervalSeconds) * time.Second
	if !g.settings.Enabled || !g.apiUp || g.effectiveMode() != core.ModeProxy || g.switchingNode || g.suspended {
		g.heartbeatAlive = false
		return time.Second
	}
	const retry = 200 * time.Millisecond
	epoch := g.epoch
	resolved, leaf := g.resolvedNode(ctx)
	if !g.current(ctx, epoch) {
		return retry
	}
	port := g.runtime.ProbePort
	if resolved != g.lastResolvedNode {
		if resolved != "" && g.lastResolvedNode != "" {
			g.log(core.EventInfo, "出口节点切换："+g.lastResolvedNode+" → "+resolved)
		}
		g.lastResolvedNode = resolved
		g.fetcher.Reset(ctx, &port)
		g.epoch++
	}
	epoch = g.epoch
	if !g.engine.Snapshot().Tripped && resolved != "" {
		alive, known := outside2(g, func() (bool, bool) { return g.api.IsAlive(ctx, leaf) })
		if !g.current(ctx, epoch) {
			return retry
		}
		if known && !alive && !g.engine.Snapshot().Tripped {
			if !g.nodeDownLogged {
				g.log(core.EventCritical, "当前节点「"+leaf+"」无法连接")
			}
			g.nodeDownLogged = true
			g.heartbeatAlive = false
			g.engine.Handle(core.Probe{}, g.mono())
			g.addLatency(nil)
			g.applyProtection()
			g.applyGates(ctx, false)
			return min(interval, time.Second)
		}
	}
	g.nodeDownLogged = false
	timeout := int64(g.settings.LatencyThresholdMs)
	start := g.mono()
	trace, _ := outside2(g, func() (*core.ExitTrace, bool) { return g.fetcher.Heartbeat(ctx, port, timeout) })
	if !g.current(ctx, epoch) || !g.settings.Enabled {
		return retry
	}
	if trace == nil {
		remaining := timeout - (g.mono() - start)
		trace, _ = outside2(g, func() (*core.ExitTrace, bool) { return g.fetcher.IPInfo(ctx, port, remaining) })
		if !g.current(ctx, epoch) || !g.settings.Enabled {
			return retry
		}
	}
	g.heartbeatAlive = trace != nil
	var ms *int
	if trace == nil {
		g.forceAutoHealthCheck()
	} else {
		ms = new(int(g.mono() - start))
	}
	g.engine.Handle(core.Probe{MS: ms}, g.mono())
	if trace != nil {
		if old := g.exitStatus.Trace; old != nil && old.IP != trace.IP {
			g.log(core.EventWarning, "出口 IP 变化："+old.IP+"（"+old.Country+"）→ "+trace.IP+"（"+trace.Country+"）")
		}
		g.exitStatus = core.ExitStatus{Trace: trace, CheckedAt: new(g.wall())}
		g.engine.Handle(core.Geo{Country: &trace.Country}, g.mono())
	} else {
		g.exitStatus.Error = new("心跳失败")
	}
	g.addLatency(ms)
	g.applyProtection()
	g.applyGates(ctx, false)
	if g.current(ctx, epoch) && trace != nil && slices.Contains(g.settings.ForbiddenRegions, trace.Country) && g.settings.AutoSwitchUnsafeNode {
		g.findSafeNode(ctx, trace.Country)
	}
	if g.engine.Snapshot().Tripped {
		return min(interval, time.Second)
	}
	return interval
}

func (g *Guardian) addLatency(ms *int) {
	g.latency = append(g.latency, core.LatencySample{At: g.wall(), MS: ms})
	if len(g.latency) > 120 {
		g.latency = g.latency[len(g.latency)-120:]
	}
}

func (g *Guardian) resolvedNode(ctx context.Context) (string, string) {
	epoch := g.epoch
	info, _ := outside2(g, func() (*core.GroupInfo, bool) { return g.api.Group(ctx, core.GroupProxy) })
	if !g.current(ctx, epoch) || info == nil || info.Now == nil {
		return "", ""
	}
	node := *info.Now
	if node != core.GroupAuto {
		return node, node
	}
	auto, _ := outside2(g, func() (*core.GroupInfo, bool) { return g.api.Group(ctx, core.GroupAuto) })
	if auto == nil || auto.Now == nil {
		return "", ""
	}
	return core.GroupAuto + "/" + *auto.Now, *auto.Now
}

func (g *Guardian) forceAutoHealthCheck() {
	now := g.mono()
	if !elapsed(now, g.lastForcedCheck, 20000) {
		return
	}
	g.lastForcedCheck = &now
	epoch := g.epoch
	g.launch(func(ctx context.Context) {
		if !g.current(ctx, epoch) {
			return
		}
		group, _ := outside2(g, func() (*core.GroupInfo, bool) { return g.api.Group(ctx, core.GroupProxy) })
		if g.current(ctx, epoch) && group != nil && group.Now != nil && *group.Now == core.GroupAuto {
			outside2(g, func() (map[string]int, bool) {
				return g.api.GroupDelay(ctx, core.GroupAuto, core.TestURL, 3000)
			})
		}
	})
}

func (g *Guardian) findSafeNode(ctx context.Context, badCountry string) {
	if g.switchingNode || !g.active(ctx) {
		return
	}
	g.switchingNode = true
	defer func() { g.switchingNode = false }()
	epoch := g.epoch
	group, _ := outside2(g, func() (*core.GroupInfo, bool) { return g.api.Group(ctx, core.GroupProxy) })
	if !g.current(ctx, epoch) || group == nil {
		return
	}
	g.log(core.EventWarning, "出口落在"+core.RegionName(badCountry)+"（禁区），正在寻找出口安全的节点")
	type candidate struct {
		name string
		ms   int
	}
	candidates := make([]string, 0, 16)
	for _, name := range group.All {
		if name != core.GroupAuto && (group.Now == nil || name != *group.Now) {
			candidates = append(candidates, name)
			if len(candidates) == 16 {
				break
			}
		}
	}
	ranked := outside(g, func() []candidate {
		return parallel(candidates, func(name string) candidate {
			ms, _ := g.api.Delay(ctx, name, core.TestURL, 3000)
			return candidate{name, ms}
		})
	})
	if !g.current(ctx, epoch) {
		return
	}
	ranked = slices.DeleteFunc(ranked, func(c candidate) bool { return c.ms <= 0 })
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].ms < ranked[j].ms })
	port := g.runtime.ProbePort
	for _, c := range ranked[:min(6, len(ranked))] {
		selected := outside(g, func() bool { return g.api.Select(ctx, core.GroupProxy, c.name) })
		if !g.current(ctx, epoch) {
			return
		}
		if !selected {
			continue
		}
		g.epoch++
		epoch = g.epoch
		g.fetcher.Reset(ctx, &port)
		trace, _ := outside2(g, func() (*core.ExitTrace, bool) { return g.fetcher.ExitTrace(ctx, port) })
		if !g.current(ctx, epoch) {
			return
		}
		if trace != nil && !slices.Contains(g.settings.ForbiddenRegions, trace.Country) {
			g.lastResolvedNode = c.name
			g.exitStatus = core.ExitStatus{Trace: trace, CheckedAt: new(g.wall())}
			g.log(core.EventInfo, "已自动切换到「"+c.name+"」（"+core.RegionName(trace.Country)+"）")
			g.engine.Handle(core.Geo{Country: &trace.Country}, g.mono())
			return
		}
	}
	outside(g, func() bool { return g.api.Select(ctx, core.GroupProxy, core.GroupAuto) })
	if g.current(ctx, epoch) {
		g.log(core.EventCritical, "没有找到出口安全的节点，继续保持熔断")
	}
}

func parallel[T, R any](items []T, call func(T) R) []R {
	results := make([]R, len(items))
	var work sync.WaitGroup
	for i, item := range items {
		work.Go(func() { results[i] = call(item) })
	}
	work.Wait()
	return results
}
