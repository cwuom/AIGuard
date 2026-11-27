// Package winsys 是 Windows 平台层：网卡与路由、DNS/IPv6 锁定、进程枚举与关闭、冲突软件扫描。
// 本文件是平台无关的纯逻辑，可在任意系统上测试；系统调用都在 *_windows.go 里。
package winsys

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// TunAlias 是 mihomo 创建的 wintun 网卡名，与 core.TUN_DEVICE 一致
const TunAlias = "AIGuard"

// TunDNS 是 TUN 网段里由 mihomo dns-hijack 接管的地址，各网卡的 DNS 锁到这里
const TunDNS = "198.18.0.2"

// Iface 是一块网卡的快照
type Iface struct {
	LUID  uint64
	GUID  string
	Alias string
	// Description 是驱动描述（如 "Wintun Userspace Tunnel"），用来识别其他 VPN 的虚拟网卡
	Description string
	IPv4        []string
	Gateways    []string
	Up          bool
	// Physical 为 true 表示以太网/Wi-Fi/USB 网卡等真实上网接口
	Physical bool
	// Tunnel 为 true 表示 wintun/TAP/WireGuard 一类的隧道网卡
	Tunnel bool
}

// Fingerprint 汇总真实网卡的地址与网关：变化即视为换网（换 Wi-Fi、IP 变化、插拔网线）
func Fingerprint(list []Iface) string {
	var parts []string
	for _, i := range list {
		if !i.Up || !i.Physical || len(i.IPv4) == 0 {
			continue
		}
		ips := slices.Clone(i.IPv4)
		gws := slices.Clone(i.Gateways)
		slices.Sort(ips)
		slices.Sort(gws)
		parts = append(parts, fmt.Sprintf("%s=%s>%s", i.GUID, strings.Join(ips, ","), strings.Join(gws, ",")))
	}
	slices.Sort(parts)
	return strings.Join(parts, ";")
}

// Primary 返回有默认网关的真实网卡名，供界面展示与登录模式的 DHCP DNS 使用
func Primary(list []Iface, defaultLUID uint64) string {
	for _, i := range list {
		if i.LUID == defaultLUID && i.Physical && i.Up {
			return i.Alias
		}
	}
	for _, i := range list {
		if i.Physical && i.Up && len(i.Gateways) > 0 {
			return i.Alias
		}
	}
	return ""
}

// FindTun 按网卡名找 AIGuard 的 TUN
func FindTun(list []Iface) *Iface {
	for idx := range list {
		if strings.EqualFold(list[idx].Alias, TunAlias) && list[idx].Up {
			return &list[idx]
		}
	}
	return nil
}

var tunDrivers = regexp.MustCompile(`(?i)wintun|wireguard|tap-windows|tap adapter|openvpn|tun2socks|sing-?tun|clash|mihomo|v2ray|xray|letsvpn|astrill|zerotier`)

// IsTunnelDriver 判断驱动描述是否属于隧道类虚拟网卡
func IsTunnelDriver(description string) bool { return tunDrivers.MatchString(description) }

// ForeignTuns 返回正在运行的其他隧道网卡（其他 VPN/代理会和我们抢默认路由）
func ForeignTuns(list []Iface) []string {
	var out []string
	for _, i := range list {
		if i.Up && i.Tunnel && !strings.EqualFold(i.Alias, TunAlias) {
			out = append(out, i.Alias)
		}
	}
	return out
}

// conflictProcesses 是其他代理/VPN 软件的进程名（小写），检测到就提示用户退出。
// 只列真正会接管路由的界面与内核：Clash Verge 的 clash-verge-service.exe 是常驻的系统服务，
// 退出 Clash Verge 后它仍在后台空转，不接管路由，列进来会误报
var conflictProcesses = map[string]string{
	"clash-verge.exe":        "Clash Verge",
	"verge-mihomo.exe":       "Clash Verge",
	"verge-mihomo-alpha.exe": "Clash Verge",
	"clash for windows.exe":  "Clash for Windows",
	"clash-win64.exe":        "Clash",
	"clash.exe":              "Clash",
	"clash-meta.exe":         "Clash Meta",
	"mihomo.exe":             "mihomo",
	"flclash.exe":            "FlClash",
	"flclashcore.exe":        "FlClash",
	"v2rayn.exe":             "v2rayN",
	"v2ray.exe":              "v2ray",
	"xray.exe":               "Xray",
	"sing-box.exe":           "sing-box",
	"hiddify.exe":            "Hiddify",
	"hiddifycli.exe":         "Hiddify",
	"nekoray.exe":            "NekoRay",
	"nekobox.exe":            "NekoBox",
	"karing.exe":             "Karing",
	"shadowsocks.exe":        "Shadowsocks",
	"shadowsocksr.exe":       "ShadowsocksR",
	"letsvpn.exe":            "LetsVPN",
	"letspro.exe":            "LetsVPN",
	"astrill.exe":            "Astrill",
	"openvpn.exe":            "OpenVPN",
	"openvpn-gui.exe":        "OpenVPN",
	"wireguard.exe":          "WireGuard",
	"proxifier.exe":          "Proxifier",
	"netch.exe":              "Netch",
}

// ConflictName 返回进程对应的冲突软件名，不是冲突软件时返回空串
func ConflictName(exeBase string) string { return conflictProcesses[strings.ToLower(exeBase)] }

var guidPattern = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// ValidGUID 校验网卡 GUID 格式；GUID 会拼进 PowerShell 命令，只接受标准格式
func ValidGUID(s string) bool { return guidPattern.MatchString(s) }

// ParseNameServers 解析注册表 NameServer 值（逗号或空格分隔）
func ParseNameServers(v string) []string {
	f := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	return slices.DeleteFunc(f, func(s string) bool { return s == "" })
}
