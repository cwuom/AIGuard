package wfpolicy

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
)

var ctx = Context{
	CoreExe:        `C:\Program Files\AIGuard\core\mihomo.exe`,
	ServiceExe:     `C:\Program Files\AIGuard\aiguard-service.exe`,
	UIExe:          `C:\Program Files\AIGuard\AIGuard.exe`,
	ControllerPort: 19097,
	ProbePorts:     []uint16{17892, 17893},
	BootstrapDNS:   []netip.Addr{netip.MustParseAddr("223.5.5.5"), netip.MustParseAddr("119.29.29.29")},
	CNRanges:       cnRanges(600),
}

func cnRanges(n int) []netip.Prefix {
	var out []netip.Prefix
	for i := range n {
		out = append(out, netip.MustParsePrefix(fmt.Sprintf("1.%d.%d.0/24", i/256, i%256)))
	}
	return out
}

func build(t *testing.T, p Policy) []Rule {
	t.Helper()
	r, err := Build(p, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func find(rules []Rule, name string) *Rule {
	for i := range rules {
		if rules[i].Name == name {
			return &rules[i]
		}
	}
	return nil
}

func has(rules []Rule, name string) bool { return find(rules, name) != nil }

// 按 WFP 子层语义模拟：权重最高的匹配规则决定结果，没有匹配就放行（交给其他子层）
type pkt struct {
	family   Family
	app      string
	remote   netip.Addr
	port     uint16
	local    uint16
	proto    uint8
	luid     uint64
	loopback bool
}

func matches(r Rule, p pkt) bool {
	if r.Family != p.family {
		return false
	}
	byField := map[Field][]Cond{}
	for _, c := range r.Conds {
		byField[c.Field] = append(byField[c.Field], c)
	}
	for f, conds := range byField {
		ok := false
		for _, c := range conds {
			switch f {
			case FieldApp:
				ok = ok || strings.EqualFold(c.App, p.app)
			case FieldRemotePrefix:
				ok = ok || c.Prefix.Contains(p.remote)
			case FieldRemotePort:
				ok = ok || c.Port == p.port
			case FieldLocalPort:
				ok = ok || c.Port == p.local
			case FieldProtocol:
				ok = ok || c.Proto == p.proto
			case FieldLocalInterface:
				ok = ok || c.LUID == p.luid
			case FieldLoopback:
				ok = ok || p.loopback
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func verdict(rules []Rule, p pkt) Action {
	best := -1
	action := Permit
	for _, r := range rules {
		if int(r.Weight) > best && matches(r, p) {
			best = int(r.Weight)
			action = r.Action
		}
	}
	return action
}

const tun = 0x55

var (
	browser = `C:\Program Files\Google\Chrome\Application\chrome.exe`
	google  = netip.MustParseAddr("142.250.1.1")
	cnIP    = netip.MustParseAddr("1.0.5.9")
	router  = netip.MustParseAddr("192.168.1.1")
	node    = netip.MustParseAddr("45.1.2.3")
)

func TestNoneHasNoRules(t *testing.T) {
	if r := build(t, Policy{Kind: None}); r != nil {
		t.Fatalf("None 应该没有规则：%v", r)
	}
}

func TestUnknownKindAndMissingPathsFail(t *testing.T) {
	if _, err := Build(Policy{Kind: "open"}, ctx); err == nil {
		t.Fatal("未知策略必须报错")
	}
	c := ctx
	c.CoreExe = ""
	if _, err := Build(Policy{Kind: LeakGuard, TunLUID: tun}, c); err == nil {
		t.Fatal("缺少内核路径必须报错，不能生成放行所有程序的规则")
	}
}

func TestLeakGuardOnlyTunReachesInternet(t *testing.T) {
	r := build(t, Policy{Kind: LeakGuard, TunLUID: tun})
	cases := []struct {
		name string
		p    pkt
		want Action
	}{
		{"经 TUN 出站", pkt{app: browser, remote: google, port: 443, proto: ProtoTCP, luid: tun}, Permit},
		{"绕过 TUN 直连", pkt{app: browser, remote: google, port: 443, proto: ProtoTCP, luid: 7}, Block},
		{"内核直连节点", pkt{app: ctx.CoreExe, remote: node, port: 443, proto: ProtoTCP, luid: 7}, Permit},
		{"服务直连", pkt{app: ctx.ServiceExe, remote: node, port: 443, proto: ProtoTCP, luid: 7}, Permit},
		{"局域网", pkt{app: browser, remote: router, port: 80, proto: ProtoTCP, luid: 7}, Permit},
		{"DHCP", pkt{app: `C:\Windows\System32\svchost.exe`, remote: netip.MustParseAddr("255.255.255.255"), port: 67, local: 68, proto: ProtoUDP, luid: 7}, Permit},
		{"明文 DNS 发往路由器", pkt{app: `C:\Windows\System32\svchost.exe`, remote: router, port: 53, proto: ProtoUDP, luid: 7}, Block},
		{"DoT 直连", pkt{app: browser, remote: google, port: 853, proto: ProtoTCP, luid: 7}, Block},
		{"DNS 经 TUN", pkt{app: `C:\Windows\System32\svchost.exe`, remote: netip.MustParseAddr("198.18.0.2"), port: 53, proto: ProtoUDP, luid: tun}, Permit},
		{"内核引导 DNS", pkt{app: ctx.CoreExe, remote: netip.MustParseAddr("223.5.5.5"), port: 53, proto: ProtoUDP, luid: 7}, Permit},
		{"内核明文 DNS 发往境外", pkt{app: ctx.CoreExe, remote: netip.MustParseAddr("8.8.8.8"), port: 53, proto: ProtoUDP, luid: 7}, Block},
		{"界面连控制端口", pkt{app: ctx.UIExe, remote: netip.MustParseAddr("127.0.0.1"), port: 19097, proto: ProtoTCP, loopback: true}, Permit},
		{"其他程序连控制端口", pkt{app: browser, remote: netip.MustParseAddr("127.0.0.1"), port: 19097, proto: ProtoTCP, loopback: true}, Block},
		{"界面连探测入站", pkt{app: ctx.UIExe, remote: netip.MustParseAddr("127.0.0.1"), port: 17892, proto: ProtoTCP, loopback: true}, Block},
		{"服务连探测入站", pkt{app: ctx.ServiceExe, remote: netip.MustParseAddr("127.0.0.1"), port: 17893, proto: ProtoTCP, loopback: true}, Permit},
		{"其他回环", pkt{app: browser, remote: netip.MustParseAddr("127.0.0.1"), port: 1053, proto: ProtoUDP, loopback: true}, Permit},
		{"IPv6 公网", pkt{family: V6, app: browser, remote: netip.MustParseAddr("2606:4700::1"), port: 443, proto: ProtoTCP, luid: 7}, Block},
		{"IPv6 内核也拦", pkt{family: V6, app: ctx.CoreExe, remote: netip.MustParseAddr("2606:4700::1"), port: 443, proto: ProtoTCP, luid: 7}, Block},
		{"IPv6 链路本地", pkt{family: V6, app: browser, remote: netip.MustParseAddr("fe80::1"), port: 5353, proto: ProtoUDP, luid: 7}, Permit},
		{"IPv6 回环", pkt{family: V6, app: browser, remote: netip.MustParseAddr("::1"), port: 80, proto: ProtoTCP, loopback: true}, Permit},
	}
	for _, c := range cases {
		if got := verdict(r, c.p); got != c.want {
			t.Errorf("%s：得到 %v，期望 %v", c.name, got, c.want)
		}
	}
}

func TestTunNotUpMeansNoTunPermit(t *testing.T) {
	r := build(t, Policy{Kind: LeakGuard})
	if has(r, "TUN") {
		t.Fatal("TUN 未就绪时不能有 TUN 放行规则")
	}
	if verdict(r, pkt{app: browser, remote: google, port: 443, luid: 0}) != Block {
		t.Fatal("TUN 未就绪时外网必须被拦")
	}
}

func TestBasicKeepsDNSAndIPv6Only(t *testing.T) {
	r := build(t, Policy{Kind: Basic, TunLUID: tun})
	if has(r, "兜底拦截") || has(r, "局域网") {
		t.Fatal("Basic 不应拦截普通 IPv4")
	}
	if verdict(r, pkt{app: browser, remote: google, port: 443, luid: 7}) != Permit {
		t.Fatal("Basic 下普通 IPv4 应放行")
	}
	if verdict(r, pkt{app: browser, remote: router, port: 53, proto: ProtoUDP, luid: 7}) != Block {
		t.Fatal("Basic 仍要拦明文 DNS")
	}
	if verdict(r, pkt{family: V6, app: browser, remote: netip.MustParseAddr("2606:4700::1"), port: 443}) != Block {
		t.Fatal("Basic 仍要拦 IPv6")
	}
}

func TestWhitelistBeforeGateConfirmed(t *testing.T) {
	r := build(t, Policy{Kind: Whitelist, TunLUID: tun, Allow: []netip.Addr{node}})
	cases := []struct {
		name string
		p    pkt
		want Action
	}{
		{"闸门确认前 TUN 不放行", pkt{app: browser, remote: netip.MustParseAddr("198.18.0.9"), port: 443, luid: tun}, Block},
		{"大陆 IP 直连", pkt{app: browser, remote: cnIP, port: 443, luid: 7}, Permit},
		{"境外直连", pkt{app: browser, remote: google, port: 443, luid: 7}, Block},
		{"内核连节点", pkt{app: ctx.CoreExe, remote: node, port: 443, luid: 7}, Permit},
		{"服务连订阅服务器", pkt{app: ctx.ServiceExe, remote: node, port: 443, luid: 7}, Permit},
		{"浏览器不能借节点例外", pkt{app: browser, remote: node, port: 443, luid: 7}, Block},
		{"内核连其他境外", pkt{app: ctx.CoreExe, remote: google, port: 443, luid: 7}, Block},
	}
	for _, c := range cases {
		if got := verdict(r, c.p); got != c.want {
			t.Errorf("%s：得到 %v，期望 %v", c.name, got, c.want)
		}
	}
}

func TestWhitelistAfterGateConfirmed(t *testing.T) {
	r := build(t, Policy{Kind: Whitelist, TunLUID: tun, AllowTun: true})
	if verdict(r, pkt{app: browser, remote: netip.MustParseAddr("198.18.0.9"), port: 443, luid: tun}) != Permit {
		t.Fatal("闸门确认后进入 TUN 的流量由内核按域名把关")
	}
	if verdict(r, pkt{app: browser, remote: google, port: 443, luid: 7}) != Block {
		t.Fatal("境外直连仍要拦")
	}
}

func TestLockdown(t *testing.T) {
	r := build(t, Policy{Kind: Lockdown, TunLUID: tun})
	if has(r, "TUN") {
		t.Fatal("全部断网不放行 TUN")
	}
	if verdict(r, pkt{app: browser, remote: cnIP, port: 443, luid: 7}) != Block {
		t.Fatal("全部断网连大陆也拦")
	}
	if verdict(r, pkt{app: ctx.CoreExe, remote: node, port: 443, luid: 7}) != Permit {
		t.Fatal("内核要能探测节点")
	}
	if verdict(r, pkt{app: browser, remote: router, port: 80, luid: 7}) != Permit {
		t.Fatal("局域网保留")
	}
}

func TestCNRangesChunkedAndSanitized(t *testing.T) {
	c := ctx
	c.CNRanges = append(cnRanges(600), netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("1.0.0.0/24"), netip.MustParsePrefix("2001:db8::/32"))
	r, err := Build(Policy{Kind: Whitelist, TunLUID: tun}, c)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	chunks := 0
	for _, rule := range r {
		if strings.HasPrefix(rule.Name, "大陆 IP") {
			chunks++
			total += len(rule.Conds)
			if len(rule.Conds) > chunk {
				t.Fatalf("单条规则条件过多：%d", len(rule.Conds))
			}
			for _, cond := range rule.Conds {
				if cond.Prefix.Bits() == 0 || !cond.Prefix.Addr().Is4() {
					t.Fatalf("混入了非法段 %v", cond.Prefix)
				}
			}
		}
	}
	if total != 600 || chunks != 6 {
		t.Fatalf("大陆段数量 %d、分块 %d，期望 600、6", total, chunks)
	}
	if verdict(r, pkt{app: browser, remote: google, port: 443, luid: 7}) != Block {
		t.Fatal("0.0.0.0/0 被丢弃后境外仍应被拦")
	}
}

func TestAllowListCapAndIPv4Only(t *testing.T) {
	var allow []netip.Addr
	for i := range maxAllow + 50 {
		allow = append(allow, netip.MustParseAddr(fmt.Sprintf("45.%d.%d.1", i/256, i%256)))
	}
	allow = append(allow, netip.MustParseAddr("2001:db8::1"), allow[0])
	r := build(t, Policy{Kind: Whitelist, TunLUID: tun, Allow: allow})
	n := 0
	for _, rule := range r {
		if !strings.HasPrefix(rule.Name, "熔断例外：节点与订阅服务器") {
			continue
		}
		apps, addrs := 0, 0
		for _, c := range rule.Conds {
			switch c.Field {
			case FieldApp:
				apps++
			case FieldRemotePrefix:
				addrs++
				if !c.Prefix.Addr().Is4() || c.Prefix.Bits() != 32 {
					t.Fatalf("例外地址必须是单个 IPv4：%v", c.Prefix)
				}
			}
		}
		// 每一块都必须带程序条件，否则就成了对所有程序放行
		if apps != 2 || addrs == 0 || addrs > chunk {
			t.Fatalf("%s：程序条件 %d、地址条件 %d", rule.Name, apps, addrs)
		}
		n += addrs
	}
	if n != maxAllow {
		t.Fatalf("例外地址 %d 条，期望上限 %d", n, maxAllow)
	}
}

func TestEmptyAllowListAddsNoException(t *testing.T) {
	r := build(t, Policy{Kind: Whitelist, TunLUID: tun})
	if has(r, "熔断例外：节点与订阅服务器 1") {
		t.Fatal("没有例外地址时不能生成只按程序匹配的放行规则")
	}
	if verdict(r, pkt{app: ctx.CoreExe, remote: google, port: 443, luid: 7}) != Block {
		t.Fatal("没有例外时内核也不能连境外")
	}
}

func TestEveryRuleHasValidWeight(t *testing.T) {
	for _, k := range []Kind{LeakGuard, Basic, Whitelist, Lockdown} {
		for _, rule := range build(t, Policy{Kind: k, TunLUID: tun, AllowTun: true, Allow: []netip.Addr{node}}) {
			if rule.Weight > 15 {
				t.Fatalf("%s/%s 权重越界", k, rule.Name)
			}
			if rule.Action == Permit && len(rule.Conds) == 0 {
				t.Fatalf("%s/%s 是无条件放行", k, rule.Name)
			}
		}
	}
}

func TestParseCNTable(t *testing.T) {
	got := ParseCNTable("# 注释\n1.0.1.0/24\r\n\n1.0.2.0/23 \nbad\n1.0.1.0/24\n0.0.0.0/0\n")
	if len(got) != 2 || got[0].String() != "1.0.1.0/24" || got[1].String() != "1.0.2.0/23" {
		t.Fatalf("解析结果 %v", got)
	}
}

func TestPolicyEqual(t *testing.T) {
	a := Policy{Kind: Whitelist, TunLUID: 1, Allow: []netip.Addr{node}}
	b := a
	b.Allow = []netip.Addr{node}
	if !a.Equal(b) {
		t.Fatal("内容相同应相等")
	}
	b.AllowTun = true
	if a.Equal(b) {
		t.Fatal("AllowTun 不同应不等")
	}
}

// 回归：随包的真实大陆表（6000 多段）曾让单条规则的条件数组超过 wf 的 4 KiB 分配上限而 panic
func TestBundledCNTableStaysWithinConditionLimit(t *testing.T) {
	b, err := os.ReadFile("../../../Vendor/rules/cn4.txt")
	if err != nil {
		t.Skip("缺少 Vendor/rules/cn4.txt（先运行 scripts/fetch-core.sh）")
	}
	c := ctx
	c.CNRanges = ParseCNTable(string(b))
	if len(c.CNRanges) < 1000 {
		t.Fatalf("随包大陆表只有 %d 段", len(c.CNRanges))
	}
	var allow []netip.Addr
	for i := range maxAllow {
		allow = append(allow, netip.MustParseAddr(fmt.Sprintf("45.%d.%d.1", i/256, i%256)))
	}
	r := build(t, Policy{Kind: Whitelist, TunLUID: tun, Allow: allow})
	// FWPM_FILTER_CONDITION0 在 64 位下 40 字节；控制在 4 KiB 以内，就算分配器回退成原版也不会 panic
	const condSize, limit = 40, 4096
	for _, rule := range r {
		if len(rule.Conds)*condSize > limit {
			t.Fatalf("%s 有 %d 个条件（%d 字节）", rule.Name, len(rule.Conds), len(rule.Conds)*condSize)
		}
	}
}

func TestGameBlocksAIAndKeepsBrowsersOnTun(t *testing.T) {
	claude := `C:\Users\u\AppData\Local\AnthropicClaude\app-1.0\claude.exe`
	game := `D:\Steam\steamapps\common\Game\game.exe`
	uu := `C:\Program Files\Netease\UU\uu.exe`
	anthropic := netip.MustParseAddr("160.79.104.10")
	c := ctx
	c.AIRanges = []netip.Prefix{netip.MustParsePrefix("160.79.104.0/23"), netip.MustParsePrefix("0.0.0.0/0")}
	r, err := Build(Policy{Kind: Game, TunLUID: tun, Block: []string{claude, "", ctx.CoreExe, ctx.UIExe}, TunOnly: []string{browser, strings.ToUpper(browser)}}, c)
	if err != nil {
		t.Fatal(err)
	}
	const accel = 0x77
	cases := []struct {
		name string
		p    pkt
		want Action
	}{
		{"游戏直连外网", pkt{family: V4, app: game, remote: google, port: 27015, proto: ProtoUDP}, Permit},
		{"游戏经加速器网卡", pkt{family: V4, app: game, remote: google, port: 27015, luid: accel}, Permit},
		{"游戏经 TUN", pkt{family: V4, app: game, remote: google, port: 443, luid: tun}, Permit},
		{"加速器直连", pkt{family: V4, app: uu, remote: node, port: 443}, Permit},
		{"系统 DNS 照常", pkt{family: V4, app: `C:\Windows\System32\svchost.exe`, remote: router, port: 53}, Permit},
		{"浏览器经 TUN", pkt{family: V4, app: browser, remote: google, port: 443, luid: tun}, Permit},
		{"浏览器绕过 TUN 拒绝", pkt{family: V4, app: browser, remote: google, port: 443}, Block},
		{"AI 程序经 TUN 也拒绝", pkt{family: V4, app: claude, remote: anthropic, port: 443, luid: tun}, Block},
		{"AI 程序直连拒绝", pkt{family: V4, app: claude, remote: google, port: 443}, Block},
		{"AI 程序连局域网也拒绝", pkt{family: V4, app: claude, remote: router, port: 11434}, Block},
		{"AI 程序 IPv6 拒绝", pkt{family: V6, app: claude, remote: netip.MustParseAddr("2001:db8::1"), port: 443}, Block},
		{"任何程序直连 AI 服务地址都拒绝", pkt{family: V4, app: game, remote: anthropic, port: 443}, Block},
		{"内核可以连 AI 地址以外的节点", pkt{family: V4, app: ctx.CoreExe, remote: node, port: 443}, Permit},
		{"控制端口仍只给服务与界面", pkt{family: V4, app: game, remote: netip.MustParseAddr("127.0.0.1"), port: 19097, loopback: true}, Block},
		{"IPv6 仍整体封锁", pkt{family: V6, app: game, remote: netip.MustParseAddr("2001:db8::1"), port: 443}, Block},
	}
	for _, tc := range cases {
		if got := verdict(r, tc.p); got != tc.want {
			t.Errorf("%s：得到 %v，期望 %v", tc.name, got, tc.want)
		}
	}
	for _, rule := range r {
		for _, cond := range rule.Conds {
			if cond.Field == FieldApp && rule.Action == Block && (cond.App == "" || strings.EqualFold(cond.App, ctx.CoreExe) || strings.EqualFold(cond.App, ctx.UIExe)) {
				t.Fatalf("黑名单不能含空路径或自己的程序：%+v", rule)
			}
			if cond.Field == FieldRemotePrefix && cond.Prefix.Bits() < 4 {
				t.Fatalf("零长度前缀会拦掉全部地址：%+v", rule)
			}
		}
	}
	// TUN 还没起来时浏览器没有出路（宁可断网）
	r2 := build(t, Policy{Kind: Game, TunOnly: []string{browser}})
	if verdict(r2, pkt{family: V4, app: browser, remote: google, port: 443}) != Block {
		t.Fatal("没有 TUN 时浏览器不能直连")
	}
}

func TestGameBlacklistIsChunkedAndCapped(t *testing.T) {
	var block []string
	for i := range 1200 {
		block = append(block, fmt.Sprintf(`C:\Apps\a%d\x.exe`, i))
	}
	r := build(t, Policy{Kind: Game, Block: block})
	total := 0
	for _, rule := range r {
		if rule.Weight == wGameBlockAI && rule.Family == V4 {
			if len(rule.Conds) > appChunk {
				t.Fatalf("单条规则 %d 个程序条件，超过 %d", len(rule.Conds), appChunk)
			}
			total += len(rule.Conds)
		}
	}
	if total != maxBlock {
		t.Fatalf("黑名单应截到 %d 个，得到 %d", maxBlock, total)
	}
	if (Policy{Kind: Game, TunOnly: []string{"a"}}).Equal(Policy{Kind: Game, TunOnly: []string{"b"}}) {
		t.Fatal("名单变化必须触发重写")
	}
	if (Policy{Kind: Game}).Restrictive() {
		t.Fatal("游戏模式不是熔断类策略")
	}
}
