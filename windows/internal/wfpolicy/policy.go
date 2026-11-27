// Package wfpolicy 把防火墙策略翻译成平台无关的 WFP 过滤规则描述，对应 macOS 的 PFRulesBuilder 与 Android 的 FirewallBuilder。
// 这里只做纯计算，真正写入 WFP 的是 internal/wfp（仅 Windows）。
//
// 规则全部放在 AIGuard 自己的子层里：同一子层内权重最高的匹配规则决定结果，所以放行写高权重、兜底拦截写最低权重。
// 子层只能「多拦」不能「多放」：其他子层（Windows 防火墙、mihomo 的 strict-route）的拦截仍然生效。
package wfpolicy

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Kind 与 macOS/Android 的策略名一致，界面按名字展示
type Kind string

const (
	// None 不加载任何规则
	None Kind = "none"
	// LeakGuard 平时：普通进程只能经 TUN 出站，绕过 TUN 直连外网一律拒绝
	LeakGuard Kind = "leakGuard"
	// Basic 关闭防泄漏层时仍保留 IPv6 封锁与 DNS 防泄漏
	Basic Kind = "basic"
	// Whitelist 熔断（大陆白名单）：只能连大陆 IP；内核与服务额外可连节点/订阅服务器
	Whitelist Kind = "whitelist"
	// Lockdown 熔断（全部断网）：只留回环、局域网、DHCP，以及内核与服务自身
	Lockdown Kind = "lockdown"
	// Game 游戏模式（黑名单）：AI 程序完全禁止联网，浏览器只能经 TUN（AI 网站在内核里按名单拒绝），
	// AI 服务的 IP 段禁止直连，其余程序（游戏、加速器）放行
	Game Kind = "game"
)

// Policy 是守护服务想要的防火墙状态
type Policy struct {
	Kind Kind
	// TunLUID 是 AIGuard TUN 网卡的 LUID；0 表示 TUN 还没起来，此时不放行任何 TUN 流量
	TunLUID uint64
	// AllowTun 只对 Whitelist 有效：内核闸门确认 REJECT 之后才放行进入 TUN 的流量
	AllowTun bool
	// Allow 只对 Whitelist 有效：内核与服务可以连的节点/订阅服务器 IPv4
	Allow []netip.Addr
	// Block 只对 Game 有效：完全禁止联网的 AI 程序路径
	Block []string
	// TunOnly 只对 Game 有效：只能经 TUN 出站的程序路径（浏览器）
	TunOnly []string
}

// Equal 用于判断策略是否变化，变化才需要重写规则
func (p Policy) Equal(o Policy) bool {
	return p.Kind == o.Kind && p.TunLUID == o.TunLUID && p.AllowTun == o.AllowTun && slices.Equal(p.Allow, o.Allow) &&
		slices.Equal(p.Block, o.Block) && slices.Equal(p.TunOnly, o.TunOnly)
}

// Restrictive 表示熔断类策略（睡眠前强制断网也算）
func (p Policy) Restrictive() bool { return p.Kind == Whitelist || p.Kind == Lockdown }

// Context 是生成规则需要的本机参数
type Context struct {
	// CoreExe、ServiceExe、UIExe 是绝对路径，写入 WFP 前会换成 App ID
	CoreExe    string
	ServiceExe string
	UIExe      string
	// ControllerPort 是 mihomo 控制接口：只允许服务与界面连接
	ControllerPort uint16
	// ProbePorts 是带认证的探测入站：只允许服务连接
	ProbePorts []uint16
	// BootstrapDNS 是内核自己的明文 DNS，内核可以直接发往这些地址的 53 端口
	BootstrapDNS []netip.Addr
	// CNRanges 是大陆 IPv4 段，只在 Whitelist 下使用
	CNRanges []netip.Prefix
	// AIRanges 是 AI 服务的 IPv4 段，只在 Game 下使用
	AIRanges []netip.Prefix
}

// Field 是规则条件的种类
type Field int

const (
	// FieldApp 按程序路径匹配（ALE_APP_ID），同一规则里多个 App 条件之间是「或」
	FieldApp Field = iota
	// FieldRemotePrefix 按目标地址段匹配，多个之间是「或」
	FieldRemotePrefix
	// FieldRemotePort 按目标端口匹配，多个之间是「或」
	FieldRemotePort
	// FieldLocalPort 按本地端口匹配
	FieldLocalPort
	// FieldProtocol 按 IP 协议号匹配
	FieldProtocol
	// FieldLocalInterface 按出站网卡 LUID 匹配
	FieldLocalInterface
	// FieldLoopback 匹配回环流量（FWP_CONDITION_FLAG_IS_LOOPBACK）
	FieldLoopback
)

// Cond 是一个条件；不同 Field 之间是「与」，相同 Field 之间是「或」（WFP 的语义）
type Cond struct {
	Field  Field
	App    string
	Prefix netip.Prefix
	Port   uint16
	Proto  uint8
	LUID   uint64
}

// Action 是规则的动作
type Action int

const (
	Permit Action = iota
	Block
)

// Family 区分 ALE_AUTH_CONNECT_V4 / V6 层
type Family int

const (
	V4 Family = iota
	V6
)

// Rule 是一条 WFP 过滤规则的平台无关描述
type Rule struct {
	Name   string
	Family Family
	// Weight 是子层内的优先级（0..15），越大越先匹配
	Weight uint8
	Action Action
	Conds  []Cond
}

const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// 权重从高到低：控制端口保护 > 回环 > TUN > 内核 DNS > 拦截明文 DNS > 局域网/DHCP > 内核与服务 > 大陆 IP > 兜底拦截
const (
	wControlAllow uint8 = 15
	wControlBlock uint8 = 14
	wLoopback     uint8 = 13
	wTun          uint8 = 12
	wCoreDNS      uint8 = 11
	wBlockDNS     uint8 = 10
	wLAN          uint8 = 9
	wSelf         uint8 = 8
	wCN           uint8 = 7
	// 游戏模式：AI 程序拦截高于 TUN 与局域网放行（只给回环），浏览器拦截低于 TUN 放行（只剩 TUN）
	wGameBlockAI uint8 = 12
	wGameTun     uint8 = 11
	wGameBrowser uint8 = 6
	wGameAIRange uint8 = 5
	wBlockAll    uint8 = 1
	// 每条规则最多这么多个地址条件：WFP 没有公开单条过滤器的条件上限，分小块更稳
	chunk    = 100
	maxAllow = 512
	// App ID 条件是几百字节的设备路径，单条规则放少一点
	appChunk       = 24
	maxBlock       = 1000
	loopbackPrefix = "127.0.0.0/8"
)

// LAN 是局域网、链路本地、组播与广播
var LAN = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

var lan6 = []netip.Prefix{
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func apps(paths ...string) []Cond {
	var out []Cond
	for _, p := range paths {
		if p != "" {
			out = append(out, Cond{Field: FieldApp, App: p})
		}
	}
	return out
}

func prefixes(list []netip.Prefix) []Cond {
	out := make([]Cond, 0, len(list))
	for _, p := range list {
		out = append(out, Cond{Field: FieldRemotePrefix, Prefix: p})
	}
	return out
}

func ports(list ...uint16) []Cond {
	out := make([]Cond, 0, len(list))
	for _, p := range list {
		out = append(out, Cond{Field: FieldRemotePort, Port: p})
	}
	return out
}

func join(parts ...[]Cond) []Cond {
	var out []Cond
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Build 生成策略对应的全部规则；None 返回 nil，由调用方拆除。
// 缺少必要参数（程序路径）时宁可少放行，也不能拼出一条匹配所有程序的放行规则
func Build(p Policy, c Context) ([]Rule, error) {
	switch p.Kind {
	case None:
		return nil, nil
	case LeakGuard, Basic, Whitelist, Lockdown, Game:
	default:
		return nil, fmt.Errorf("未知的防火墙策略 %q", p.Kind)
	}
	if c.ServiceExe == "" || c.CoreExe == "" {
		return nil, fmt.Errorf("缺少服务或内核路径，无法生成防火墙规则")
	}
	var r []Rule
	add := func(name string, f Family, w uint8, a Action, conds ...[]Cond) {
		r = append(r, Rule{Name: name, Family: f, Weight: w, Action: a, Conds: join(conds...)})
	}
	loop := []Cond{{Field: FieldRemotePrefix, Prefix: netip.MustParsePrefix(loopbackPrefix)}}

	// 控制端口与探测入站：本机其他程序连不上，避免借道绕过闸门或拿到控制权
	if c.ControllerPort != 0 {
		add("控制端口：服务与界面", V4, wControlAllow, Permit, loop, ports(c.ControllerPort), apps(c.ServiceExe, c.UIExe))
		add("控制端口：其他程序拒绝", V4, wControlBlock, Block, loop, ports(c.ControllerPort))
	}
	if len(c.ProbePorts) > 0 {
		add("探测入站：服务", V4, wControlAllow, Permit, loop, ports(c.ProbePorts...), apps(c.ServiceExe))
		add("探测入站：其他程序拒绝", V4, wControlBlock, Block, loop, ports(c.ProbePorts...))
	}
	add("回环", V4, wLoopback, Permit, []Cond{{Field: FieldLoopback}})

	passTun := p.Kind == LeakGuard || p.Kind == Basic || (p.Kind == Whitelist && p.AllowTun)
	if passTun && p.TunLUID != 0 {
		add("TUN", V4, wTun, Permit, []Cond{{Field: FieldLocalInterface, LUID: p.TunLUID}})
	}

	if p.Kind == Game {
		buildGame(p, c, add)
		return r, nil
	}

	// DNS 防泄漏：明文 DNS 只能进 TUN；内核自己只能发往引导 DNS 与局域网（酒店 DHCP DNS）
	var dnsTargets []netip.Prefix
	for _, a := range c.BootstrapDNS {
		if a.Is4() {
			dnsTargets = append(dnsTargets, netip.PrefixFrom(a, 32))
		}
	}
	dnsTargets = append(dnsTargets, LAN...)
	add("内核 DNS", V4, wCoreDNS, Permit, apps(c.CoreExe), ports(53), prefixes(dnsTargets))
	add("拦截明文 DNS/DoT", V4, wBlockDNS, Block, ports(53, 853))

	if p.Kind != Basic {
		add("局域网", V4, wLAN, Permit, prefixes(LAN))
		add("DHCP", V4, wLAN, Permit, []Cond{{Field: FieldProtocol, Proto: ProtoUDP}, {Field: FieldLocalPort, Port: 68}}, ports(67))

		switch p.Kind {
		case LeakGuard, Lockdown:
			// 内核要连节点（含熔断时探测恢复），服务要在系统网络下载订阅
			add("内核与服务", V4, wSelf, Permit, apps(c.CoreExe, c.ServiceExe))
		case Whitelist:
			var allow []netip.Prefix
			seen := map[netip.Addr]bool{}
			for _, a := range p.Allow {
				if a.Is4() && !seen[a] && len(allow) < maxAllow {
					seen[a] = true
					allow = append(allow, netip.PrefixFrom(a, 32))
				}
			}
			for i := 0; i < len(allow); i += chunk {
				end := min(i+chunk, len(allow))
				add(fmt.Sprintf("熔断例外：节点与订阅服务器 %d", i/chunk+1), V4, wSelf, Permit, apps(c.CoreExe, c.ServiceExe), prefixes(allow[i:end]))
			}
			cn := validCN(c.CNRanges)
			for i := 0; i < len(cn); i += chunk {
				end := min(i+chunk, len(cn))
				add(fmt.Sprintf("大陆 IP %d", i/chunk+1), V4, wCN, Permit, prefixes(cn[i:end]))
			}
		}
		add("兜底拦截", V4, wBlockAll, Block)
	}

	// IPv6：内核不用 IPv6，除回环、链路本地与组播外全部拒绝
	add("IPv6 回环", V6, wLoopback, Permit, []Cond{{Field: FieldLoopback}})
	add("IPv6 链路本地与组播", V6, wLAN, Permit, prefixes(lan6))
	add("IPv6 兜底拦截", V6, wBlockAll, Block)
	return r, nil
}

// buildGame 生成游戏模式规则：没有兜底拦截，游戏与加速器可以走任何网卡；系统 DNS 不拦（加速器可能要用）。
// 回环（权重 13）高于一切拦截，界面与本机工具不受影响
func buildGame(p Policy, c Context, add func(string, Family, uint8, Action, ...[]Cond)) {
	add("局域网", V4, wLAN, Permit, prefixes(LAN))
	add("DHCP", V4, wLAN, Permit, []Cond{{Field: FieldProtocol, Proto: ProtoUDP}, {Field: FieldLocalPort, Port: 68}}, ports(67))
	add("内核与服务", V4, wSelf, Permit, apps(c.CoreExe, c.ServiceExe))
	if p.TunLUID != 0 {
		add("TUN", V4, wGameTun, Permit, []Cond{{Field: FieldLocalInterface, LUID: p.TunLUID}})
	}
	ai := gameApps(p.Block, c)
	for i := 0; i < len(ai); i += appChunk {
		cond := apps(ai[i:min(i+appChunk, len(ai))]...)
		add(fmt.Sprintf("游戏模式：AI 程序禁止联网 %d", i/appChunk+1), V4, wGameBlockAI, Block, cond)
		add(fmt.Sprintf("游戏模式：AI 程序禁止联网（IPv6）%d", i/appChunk+1), V6, wGameBlockAI, Block, cond)
	}
	browsers := gameApps(p.TunOnly, c)
	for i := 0; i < len(browsers); i += appChunk {
		cond := apps(browsers[i:min(i+appChunk, len(browsers))]...)
		add(fmt.Sprintf("游戏模式：浏览器只能经 TUN %d", i/appChunk+1), V4, wGameBrowser, Block, cond)
	}
	ranges := validCN(c.AIRanges)
	for i := 0; i < len(ranges); i += chunk {
		add(fmt.Sprintf("游戏模式：AI 服务地址禁止直连 %d", i/chunk+1), V4, wGameAIRange, Block, prefixes(ranges[i:min(i+chunk, len(ranges))]))
	}
	// IPv6 与平时一样整体封锁（内核不走 IPv6）
	add("IPv6 回环", V6, wLoopback, Permit, []Cond{{Field: FieldLoopback}})
	add("IPv6 链路本地与组播", V6, wLAN, Permit, prefixes(lan6))
	add("IPv6 兜底拦截", V6, wBlockAll, Block)
}

// gameApps 去重并去掉空路径与自己的程序（空路径会变成「匹配所有程序」），最多 maxBlock 个
func gameApps(list []string, c Context) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range list {
		key := strings.ToLower(a)
		if a == "" || seen[key] || strings.EqualFold(a, c.CoreExe) || strings.EqualFold(a, c.ServiceExe) || strings.EqualFold(a, c.UIExe) || len(out) >= maxBlock {
			continue
		}
		seen[key] = true
		out = append(out, a)
	}
	return out
}

// validCN 只保留合法、去重的 IPv4 段；零长度前缀会放行全部地址，必须丢掉
func validCN(list []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, p := range list {
		p = p.Masked()
		if !p.IsValid() || !p.Addr().Is4() || p.Bits() < 4 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// ParseCNTable 解析 cn4.txt（每行一个 IPv4 段），非法行跳过
func ParseCNTable(text string) []netip.Prefix {
	var out []netip.Prefix
	start := 0
	for i := 0; i <= len(text); i++ {
		if i < len(text) && text[i] != '\n' {
			continue
		}
		line := text[start:i]
		start = i + 1
		for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == ' ') {
			line = line[:len(line)-1]
		}
		if line == "" || line[0] == '#' {
			continue
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			out = append(out, p)
		}
	}
	return validCN(out)
}
