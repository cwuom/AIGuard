package core

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	GroupProxy               = "节点选择"
	GroupAuto                = "自动选择"
	GroupGateAI              = "AIGUARD-GATE-AI"
	GroupGateMain            = "AIGUARD-GATE-MAIN"
	GroupGateDirect          = "AIGUARD-GATE-DIRECT"
	GroupGateCN              = "AIGUARD-GATE-CN"
	GroupInternalPrefix      = "AIGUARD-"
	GroupProvider            = "sub"
	TunDevice                = "AIGuard"
	TunAddress               = "198.18.0.1"
	TestURL                  = "http://cp.cloudflare.com/generate_204"
	AutoCheckIntervalSeconds = 600

	infoNodeWords   = "剩余|流量|到期|过期|有效期|expire|官网|网址|重置|套餐|订阅|traffic|频道|群组|telegram|客服|公告"
	defaultTunStack = "mixed"
)

type CoreRuntime struct {
	Secret           string
	ListenerPassword string
	HasSubscription  bool
	ControllerPort   int
	ListenerUser     string
	ProbePort        int
	DirectProbePort  int
	DNSPort          int
	TunDevice        string
	TunStack         string
	// Game 是游戏模式：AI 服务一律拒绝、其余全部直连，DNS 返回真实 IP（加速器按 IP 加的路由才能生效），
	// 不开 strict-route（不和加速器抢 DNS）
	Game bool
}

func DefaultCoreRuntime() CoreRuntime {
	return CoreRuntime{
		ControllerPort: Ports.Controller, ListenerUser: "aiguard", ProbePort: Ports.Probe,
		DirectProbePort: Ports.DirectProbe, DNSPort: Ports.DNS, TunDevice: TunDevice, TunStack: defaultTunStack,
	}
}

var PrivateCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
	"100.64.0.0/10", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32",
}

// configure bootstrap DNS with IPs so resolution does not depend on system DNS
var BootstrapDNS = []string{"223.5.5.5", "119.29.29.29"}
var DomesticDoH = []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"}
var ForeignDoH = []string{"https://1.1.1.1/dns-query#" + GroupProxy, "https://8.8.8.8/dns-query#" + GroupProxy}

func ExcludeFilter(regions, extra []string) string {
	parts := make([]string, 0, len(regions)+len(extra)+1)
	for _, r := range regions {
		parts = append(parts, RegionNodePattern(r))
	}
	parts = append(parts, extra...)
	parts = append(parts, infoNodeWords)
	return "(?i)(" + strings.Join(parts, "|") + ")"
}

func NodeExcludeFilter(s GuardSettings) string {
	return ExcludeFilter(s.Sanitized().ForbiddenRegions, []string{"回国|直连|俄罗斯|russia"})
}

func ForceProxyDomains(s GuardSettings) []string {
	direct := CleanDomains(s.CustomDirectDomains)
	combined := append(append([]string{}, ForceProxyCatalog...), s.CustomProxyDomains...)
	out := []string{}
domains:
	for _, domain := range CleanDomains(combined) {
		for _, d := range direct {
			if domain == d || strings.HasSuffix(domain, "."+d) {
				continue domains
			}
		}
		out = append(out, domain)
	}
	return out
}

func EffectiveMode(s GuardSettings, rt CoreRuntime) ProxyMode {
	if rt.HasSubscription {
		return s.Mode
	}
	return ModeDirect
}

var captiveAdapter = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func BuildMihomoConfig(raw GuardSettings, rt CoreRuntime, captive bool, captiveInterface string) string {
	if rt.TunStack == "" {
		rt.TunStack = defaultTunStack
	}
	s := raw.Sanitized()
	mode := EffectiveMode(s, rt)
	if captive {
		mode = ModeDirect
	}
	var y YamlWriter
	y.Line("allow-lan: false")
	y.Line("mode: rule")
	y.Line("log-level: warning")
	y.Line("ipv6: false")
	y.Line("unified-delay: true")
	y.Line("tcp-concurrent: true")
	y.Line("find-process-mode: off")
	y.Line("geo-auto-update: false")
	y.Line("external-controller: " + q(fmt.Sprintf("127.0.0.1:%d", rt.ControllerPort)))
	y.Line("secret: " + q(rt.Secret))
	y.Line("skip-auth-prefixes: []")
	y.Line("profile:")
	y.Line("  store-selected: true")
	y.Line("  store-fake-ip: true")

	y.Line("tun:")
	y.Line("  enable: true")
	y.Line("  stack: " + rt.TunStack)
	y.Line("  device: " + q(rt.TunDevice))
	y.Line("  auto-route: true")
	y.Line("  auto-detect-interface: true")
	y.Line(fmt.Sprintf("  strict-route: %t", !rt.Game))
	y.Line("  dns-hijack: [" + q("any:53") + ", " + q("tcp://any:53") + "]")

	y.Line("sniffer:")
	y.Line("  enable: true")
	y.Line("  force-dns-mapping: true")
	y.Line("  parse-pure-ip: true")
	y.Line("  override-destination: true")
	y.Line("  sniff:")
	y.Line("    HTTP: {ports: [80, 8080-8880]}")
	y.Line("    TLS: {ports: [443, 8443]}")
	y.Line("    QUIC: {ports: [443, 8443]}")
	y.Line("  skip-domain: [" + q("Mijia Cloud") + ", " + q("+.push.apple.com") + "]")

	y.Line("dns:")
	y.Line("  enable: true")
	y.Line("  listen: " + q(fmt.Sprintf("127.0.0.1:%d", rt.DNSPort)))
	y.Line("  ipv6: false")
	y.Line("  cache-algorithm: arc")
	if rt.Game {
		y.Line("  enhanced-mode: redir-host")
	} else {
		y.Line("  enhanced-mode: fake-ip")
	}
	y.Line("  fake-ip-range: 198.18.0.1/16")
	y.Line("  fake-ip-filter-mode: blacklist")
	// NTP needs fake IPs so mihomo can still match its domain rules
	y.List("  fake-ip-filter", []string{
		"rule-set:cn-site", "*.lan", "*.local", "*.localdomain", "*.home.arpa", "+.msftconnecttest.com",
		"+.msftncsi.com", "localhost.ptlogin2.qq.com", "+.stun.*.*", "+.stun.*.*.*",
	})
	y.List("  default-nameserver", BootstrapDNS)
	y.List("  proxy-server-nameserver", DomesticDoH)
	y.List("  direct-nameserver", DomesticDoH)
	if mode == ModeProxy && rt.HasSubscription {
		y.List("  nameserver", ForeignDoH)
		y.Line("  nameserver-policy:")
		// preserve first-match precedence for direct, forced proxy and mainland overrides
		domestic, foreign := quotedList(DomesticDoH), quotedList(ForeignDoH)
		for _, d := range s.CustomDirectDomains {
			y.Line("    " + q("+."+d) + ": [" + domestic + "]")
		}
		for _, d := range ForceProxyDomains(s) {
			y.Line("    " + q("+."+d) + ": [" + foreign + "]")
		}
		y.Line("    " + q("rule-set:cn-site") + ": [" + domestic + "]")
	} else if captive && captiveAdapter.MatchString(captiveInterface) {
		y.List("  nameserver", append([]string{"dhcp://" + captiveInterface}, DomesticDoH...))
	} else {
		y.List("  nameserver", DomesticDoH)
	}

	if rt.HasSubscription {
		y.Line("proxy-providers:")
		y.Line("  " + GroupProvider + ":")
		y.Line("    type: file")
		y.Line("    path: " + q("./providers/sub.yaml"))
		y.Line("    health-check: {enable: false}")
	}

	y.Line("rule-providers:")
	for _, r := range BundledRuleSets {
		y.Line(fmt.Sprintf("  %s: {type: file, behavior: %s, format: mrs, path: %s}", r.Provider, r.Behavior, q("./rules/"+r.File)))
	}

	y.Line("proxy-groups:")
	if rt.HasSubscription {
		exclude := NodeExcludeFilter(s)
		y.group(GroupProxy, "select", []string{GroupAuto}, exclude)
		// fallback avoids routine exit changes and checks immediately when a node fails
		y.group(GroupAuto, "fallback", nil, exclude,
			"url: "+q(TestURL), fmt.Sprintf("interval: %d", AutoCheckIntervalSeconds), "timeout: 3000",
			"max-failed-times: 2", "lazy: false", "expected-status: 204")
		y.group(GroupGateAI, "select", []string{GroupProxy, "REJECT"}, "")
		y.group(GroupGateMain, "select", []string{GroupProxy, "REJECT"}, "")
		y.group(GroupGateCN, "select", []string{"DIRECT", GroupProxy, "REJECT"}, "")
	} else {
		y.group(GroupGateAI, "select", []string{"REJECT"}, "")
		y.group(GroupGateMain, "select", []string{"REJECT"}, "")
		y.group(GroupGateCN, "select", []string{"DIRECT", "REJECT"}, "")
	}
	y.group(GroupGateDirect, "select", []string{"DIRECT", "REJECT"}, "")

	// dedicated authenticated listeners bypass rules and gates for probes and subscription refresh
	y.Line("listeners:")
	listener := func(name string, port int, proxy string) {
		y.Line("  - name: " + q(name))
		y.Line("    type: http")
		y.Line("    listen: " + q("127.0.0.1"))
		y.Line(fmt.Sprintf("    port: %d", port))
		y.Line("    proxy: " + q(proxy))
		y.Line("    users: [{username: " + q(rt.ListenerUser) + ", password: " + q(rt.ListenerPassword) + "}]")
	}
	if rt.HasSubscription {
		listener("aiguard-probe", rt.ProbePort, GroupProxy)
	}
	listener("aiguard-direct", rt.DirectProbePort, "DIRECT")

	if rt.Game {
		y.List("rules", GameRules(s, mode))
	} else {
		y.List("rules", MihomoRules(s, mode, captive))
	}
	return y.String()
}

func MihomoRules(s GuardSettings, mode ProxyMode, captive bool) []string {
	var rules []string
	for _, cidr := range PrivateCIDRs {
		rules = append(rules, "IP-CIDR,"+cidr+",DIRECT,no-resolve")
	}
	rules = append(rules, "DOMAIN-SUFFIX,local,DIRECT", "DOMAIN-SUFFIX,lan,DIRECT")

	target := "REJECT"
	if mode == ModeProxy {
		target = GroupGateAI
		// reject foreign QUIC so browsers fall back to TCP
		rules = append(rules, "AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((RULE-SET,cn-site)))),REJECT")
	}
	for _, line := range AIRuleLines(s.DisabledAICategories, s.CustomAIDomains) {
		r := line + "," + target
		if strings.HasPrefix(line, "IP-CIDR") {
			r += ",no-resolve"
		}
		rules = append(rules, r)
	}
	for _, d := range s.CustomDirectDomains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+","+GroupGateDirect)
	}

	switch {
	case mode == ModeDirect && s.DirectOnlyMainland && !captive:
		for _, d := range ForceProxyDomains(s) {
			rules = append(rules, "DOMAIN-SUFFIX,"+d+",REJECT")
		}
		rules = append(rules, "RULE-SET,cn-site,"+GroupGateDirect, "RULE-SET,cn-ip,"+GroupGateDirect, "MATCH,REJECT")
	case mode == ModeDirect:
		rules = append(rules, "MATCH,"+GroupGateDirect)
	default:
		for _, d := range ForceProxyDomains(s) {
			rules = append(rules, "DOMAIN-SUFFIX,"+d+","+GroupGateMain)
		}
		// the mainland gate changes routing without reloading the config
		rules = append(rules, "RULE-SET,cn-site,"+GroupGateCN, "RULE-SET,cn-ip,"+GroupGateCN, "MATCH,"+GroupGateMain)
	}
	return rules
}

// GameRules 是游戏模式的规则：AI 名单一律拒绝（不走代理），用户指定的强制代理域名照旧，其余全部直连
func GameRules(s GuardSettings, mode ProxyMode) []string {
	var rules []string
	for _, cidr := range PrivateCIDRs {
		rules = append(rules, "IP-CIDR,"+cidr+",DIRECT,no-resolve")
	}
	rules = append(rules, "DOMAIN-SUFFIX,local,DIRECT", "DOMAIN-SUFFIX,lan,DIRECT")
	for _, line := range AIRuleLines(s.DisabledAICategories, s.CustomAIDomains) {
		r := line + ",REJECT"
		if strings.HasPrefix(line, "IP-CIDR") {
			r += ",no-resolve"
		}
		rules = append(rules, r)
	}
	for _, d := range s.CustomDirectDomains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+",DIRECT")
	}
	target := "REJECT"
	if mode == ModeProxy {
		target = GroupGateMain
	}
	for _, d := range ForceProxyDomains(s) {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+","+target)
	}
	return append(rules, "MATCH,DIRECT")
}

func q(s string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, ch := range s {
		switch ch {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if ch < 0x20 {
				fmt.Fprintf(&out, `\u%04X`, ch)
			} else {
				out.WriteRune(ch)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

type YamlWriter struct{ text strings.Builder }

func (y *YamlWriter) String() string { return y.text.String() }

func (y *YamlWriter) Line(line string) {
	y.text.WriteString(line)
	y.text.WriteByte('\n')
}

func (y *YamlWriter) List(key string, items []string) {
	if len(items) == 0 {
		y.Line(key + ": []")
		return
	}
	indent := key[:len(key)-len(strings.TrimLeft(key, " "))]
	y.Line(key + ":")
	for _, item := range items {
		y.Line(indent + "  - " + q(item))
	}
}

func quotedList(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = q(item)
	}
	return strings.Join(quoted, ", ")
}

func (y *YamlWriter) group(name, kind string, proxies []string, exclude string, extra ...string) {
	y.Line("  - name: " + q(name))
	y.Line("    type: " + kind)
	if len(proxies) != 0 {
		y.Line("    proxies: [" + quotedList(proxies) + "]")
	}
	if exclude != "" {
		y.Line("    use: [" + q(GroupProvider) + "]")
		y.Line("    exclude-filter: " + q(exclude))
	}
	for _, e := range extra {
		y.Line("    " + e)
	}
}
