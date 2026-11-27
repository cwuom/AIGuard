//go:build windows

package winsys

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Interfaces 列出全部 IPv4 网卡
func Interfaces() ([]Iface, error) {
	list, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeGateways|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast)
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(list))
	for _, a := range list {
		if a.IfType == winipcfg.IfTypeSoftwareLoopback {
			continue
		}
		i := Iface{
			LUID:        uint64(a.LUID),
			GUID:        a.AdapterName(),
			Alias:       a.FriendlyName(),
			Description: a.Description(),
			Up:          a.OperStatus == winipcfg.IfOperStatusUp,
		}
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			if ip := u.Address.IP(); ip != nil && ip.To4() != nil {
				i.IPv4 = append(i.IPv4, ip.String())
			}
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := g.Address.IP(); ip != nil && ip.To4() != nil {
				i.Gateways = append(i.Gateways, ip.String())
			}
		}
		i.Tunnel = strings.EqualFold(i.Alias, TunAlias) || IsTunnelDriver(i.Description) ||
			a.IfType == winipcfg.IfTypeTunnel || a.IfType == winipcfg.IfTypePPP
		physicalType := a.IfType == winipcfg.IfTypeEthernetCSMACD || a.IfType == winipcfg.IfTypeIEEE80211 ||
			a.IfType == winipcfg.IfTypeWwanpp || a.IfType == winipcfg.IfTypeWwanpp2
		// Hyper-V / WSL 的 vEthernet 也是以太网类型，但它不是上网接口
		virtual := strings.HasPrefix(strings.ToLower(i.Alias), "vethernet") || strings.Contains(strings.ToLower(i.Description), "hyper-v")
		i.Physical = physicalType && !i.Tunnel && !virtual
		out = append(out, i)
	}
	return out, nil
}

// DefaultRouteLUID 返回去往公网的最佳路由所在网卡；查不到时返回 0
func DefaultRouteLUID() uint64 {
	var index uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &index); err != nil {
		return 0
	}
	luid, err := winipcfg.LUIDFromIndex(index)
	if err != nil {
		return 0
	}
	return uint64(luid)
}

// IPv6Reachable 主动尝试直连公网 IPv6；连得上说明防火墙的 IPv6 封锁失效
func IPv6Reachable(timeout time.Duration) bool {
	targets := []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result := make(chan bool, len(targets))
	for _, t := range targets {
		go func(addr string) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp6", addr)
			if err == nil {
				c.Close()
			}
			result <- err == nil
		}(t)
	}
	for range targets {
		if <-result {
			return true
		}
	}
	return false
}

// ParseIPv4List 把字符串地址换成 netip.Addr，非法地址跳过
func ParseIPv4List(list []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range list {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			out = append(out, a)
		}
	}
	return out
}
