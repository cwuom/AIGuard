package guard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"

	"aiguard/internal/core"
)

const subscriptionUA = "clash.meta mihomo/1.19 AIGuard-Windows"

var fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")

func (g *Guardian) refreshAllowList(ctx context.Context) {
	data, err := os.ReadFile(g.options.Paths.ProviderFile)
	if err != nil {
		return
	}
	hosts := core.ServerHosts(string(data))
	if sub := g.settings.Subscription; sub != nil && sub.Host() != "" {
		hosts = append(hosts, sub.Host())
	}
	slices.Sort(hosts)
	hosts = slices.Compact(hosts)
	port, epoch := g.runtime.DirectProbePort, g.epoch
	ips := outside(g, func() []netip.Addr {
		seen := make(map[netip.Addr]bool)
		for batch := range slices.Chunk(hosts[:min(2000, len(hosts))], 16) {
			if ctx.Err() != nil {
				break
			}
			lists := parallel(batch, func(host string) []string {
				if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
					return []string{host}
				}
				list, _ := g.fetcher.ResolveDirect(ctx, host, port)
				return list
			})
			for _, list := range lists {
				for _, raw := range list {
					if ip, err := netip.ParseAddr(raw); err == nil && ip.Is4() && !fakeIPRange.Contains(ip) {
						seen[ip] = true
					}
				}
			}
		}
		out := make([]netip.Addr, 0, len(seen))
		for ip := range seen {
			out = append(out, ip)
		}
		slices.SortFunc(out, func(a, b netip.Addr) int { return strings.Compare(a.String(), b.String()) })
		return out
	})
	if !g.current(ctx, epoch) {
		return
	}
	g.lastAllowRefresh = new(g.mono())
	if len(ips) > 0 {
		g.allowIPs = ips
		g.applyProtection()
	}
}

func (g *Guardian) downloadSubscription(ctx context.Context, url string) (core.ParsedSubscription, core.SubscriptionInfo, error) {
	var ports []*int
	if g.apiUp {
		ports = append(ports, new(g.runtime.DirectProbePort))
		if g.runtime.HasSubscription {
			ports = append(ports, new(g.runtime.ProbePort))
		}
	}
	ports = append(ports, nil)
	var lastErr error
	for _, port := range ports {
		result, ok := outside2(g, func() (*core.FetchResult, bool) {
			return g.fetcher.Fetch(ctx, url, port, 20000, 16<<20, map[string]string{"User-Agent": subscriptionUA})
		})
		if ctx.Err() != nil {
			return core.ParsedSubscription{}, core.SubscriptionInfo{}, ctx.Err()
		}
		switch {
		case !ok:
			lastErr = core.ErrEmptySubscription
		case result.Code != http.StatusOK:
			lastErr = core.SubscriptionHTTPError(result.Code)
		default:
			parsed, err := core.ParseSubscription(result.Body)
			if err == nil {
				return parsed, core.SubscriptionInfo{
					URL: url, Name: core.ProfileName(result.Headers), LastUpdated: new(g.wall()), NodeCount: parsed.NodeCount,
					Usage: core.ParseSubscriptionUsage(result.Headers["subscription-userinfo"]),
				}, nil
			}
			lastErr = err
		}
		source := "系统网络"
		if port != nil {
			source = fmt.Sprintf("入站 %d", *port)
		}
		g.writeLog("订阅下载失败（" + source + "）：" + lastErr.Error())
	}
	return core.ParsedSubscription{}, core.SubscriptionInfo{}, lastErr
}

func (g *Guardian) installSubscription(ctx context.Context, parsed core.ParsedSubscription, info core.SubscriptionInfo) error {
	provider := g.options.Paths.ProviderFile
	backup := provider + ".bak"
	if old, err := os.ReadFile(provider); err == nil {
		if err := writeAtomic(backup, old); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeAtomic(provider, []byte(parsed.ProviderContent)); err != nil {
		return err
	}
	g.settings.Subscription = &info
	g.saveSettings()
	g.epoch++
	if !g.runtime.HasSubscription {
		g.runtime.HasSubscription = true
		g.engine.Update(g.fuseConfig(), g.mono())
		g.applyProtection()
		g.reloadCore(ctx, "导入订阅")
	} else if g.apiUp && g.active(ctx) {
		outside(g, func() bool { return g.api.ReloadProvider(ctx, core.GroupProvider) })
	}
	if !g.active(ctx) {
		return ctx.Err()
	}
	if g.apiUp {
		run := g.coreRun
		count, ok := outside2(g, func() (int, bool) { return g.api.ProviderCount(ctx, core.GroupProvider) })
		if ok && g.active(ctx) && run == g.coreRun {
			if count == 0 {
				if old, err := os.ReadFile(backup); err == nil {
					if err := writeAtomic(provider, old); err != nil {
						return err
					}
					outside(g, func() bool { return g.api.ReloadProvider(ctx, core.GroupProvider) })
				}
				return core.ErrNoSubscriptionNodes
			}
			actual := *g.settings.Subscription
			actual.NodeCount = count
			g.settings.Subscription = &actual
			g.saveSettings()
		}
	}
	if !g.active(ctx) {
		return ctx.Err()
	}
	g.refreshAllowList(ctx)
	return nil
}

func (g *Guardian) importSubscription(ctx context.Context, raw string) core.IpcResponse {
	url := core.ValidateSubscriptionURL(raw)
	if url == nil {
		return core.FailureResponse(core.ErrInvalidSubscriptionURL.Error())
	}
	parsed, info, err := g.downloadSubscription(ctx, url.String())
	if err == nil && g.active(ctx) {
		err = g.installSubscription(ctx, parsed, info)
	}
	if !g.active(ctx) {
		return core.FailureResponse("请求已取消")
	}
	if err != nil {
		g.log(core.EventWarning, "订阅导入失败："+err.Error())
		return core.FailureResponse(err.Error())
	}
	name := info.MaskedURL()
	if info.Name != nil {
		name = *info.Name
	}
	g.log(core.EventInfo, fmt.Sprintf("订阅已导入：%s，%d 个节点", name, g.settings.Subscription.NodeCount))
	return g.statusResponse()
}

func (g *Guardian) refreshSubscription(ctx context.Context, manual bool) core.IpcResponse {
	sub := g.settings.Subscription
	if sub == nil {
		return core.FailureResponse("还没有导入订阅")
	}
	parsed, info, err := g.downloadSubscription(ctx, sub.URL)
	if err == nil && g.active(ctx) {
		if info.Name == nil {
			info.Name = sub.Name
		}
		err = g.installSubscription(ctx, parsed, info)
	}
	if !g.active(ctx) {
		return core.FailureResponse("请求已取消")
	}
	if err != nil {
		failed := *sub
		failed.LastError = new(err.Error())
		g.settings.Subscription = &failed
		g.saveSettings()
		level := core.EventInfo
		if manual {
			level = core.EventWarning
		}
		g.log(level, "订阅更新失败（继续使用旧节点）："+err.Error())
		return core.FailureResponse(err.Error())
	}
	g.log(core.EventInfo, fmt.Sprintf("订阅已更新，%d 个节点", g.settings.Subscription.NodeCount))
	return g.statusResponse()
}

func (g *Guardian) autoRefreshSubscription(ctx context.Context) {
	g.mu.Unlock()
	g.subscriptionIO.Lock()
	g.mu.Lock()
	defer g.subscriptionIO.Unlock()
	sub := g.settings.Subscription
	if sub != nil && g.settings.Enabled && g.active(ctx) &&
		(sub.LastUpdated == nil || g.wall()-*sub.LastUpdated > int64(g.settings.SubscriptionUpdateHours)*3600000) {
		g.refreshSubscription(ctx, false)
	}
}
