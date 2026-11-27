package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func builderRuntime() CoreRuntime {
	rt := DefaultCoreRuntime()
	rt.Secret, rt.ListenerPassword, rt.HasSubscription = "s3cret", `pw"x`, true
	return rt
}

func has(t *testing.T, text, needle string) {
	t.Helper()
	if !strings.Contains(text, needle) {
		t.Fatalf("missing %q", needle)
	}
}

func lacks(t *testing.T, text, needle string) {
	t.Helper()
	if strings.Contains(text, needle) {
		t.Fatalf("unexpected %q", needle)
	}
}

func TestAIRulesComeBeforeMainlandDirectRules(t *testing.T) {
	rules := MihomoRules(DefaultSettings(), ModeProxy, false)
	ai, cn := slices.Index(rules, "DOMAIN-SUFFIX,claude.ai,"+GroupGateAI), slices.Index(rules, "RULE-SET,cn-site,"+GroupGateCN)
	check(t, ai >= 0 && ai < cn, "AI rules must precede mainland rules")
	want(t, rules[len(rules)-1], "MATCH,"+GroupGateMain)
	for _, rule := range rules {
		check(t, !strings.Contains(rule, "claude") || !strings.HasSuffix(rule, ",DIRECT"), rule)
	}
}

func TestDirectModeRejectsAIAndOnlyAllowsMainland(t *testing.T) {
	s := DefaultSettings()
	rules := MihomoRules(s, ModeDirect, false)
	check(t, slices.Contains(rules, "DOMAIN-SUFFIX,claude.ai,REJECT"), "direct mode must reject AI")
	lacks(t, strings.Join(rules, "\n"), GroupProxy)
	want(t, rules[len(rules)-1], "MATCH,REJECT")
	s.DirectOnlyMainland = false
	loose := MihomoRules(s, ModeDirect, false)
	want(t, loose[len(loose)-1], "MATCH,"+GroupGateDirect)
}

func TestForceProxySitesBeatMainlandList(t *testing.T) {
	s := DefaultSettings()
	s.CustomProxyDomains = []string{"HTTPS://Leak.Example.org/x", "both.example.com"}
	s.CustomDirectDomains = []string{"both.example.com"}
	s = s.Sanitized()
	rules := MihomoRules(s, ModeProxy, false)
	cn := slices.Index(rules, "RULE-SET,cn-site,"+GroupGateCN)
	for _, domain := range []string{"browserleaks.com", "whatismyip.com", "leak.example.org"} {
		i := slices.Index(rules, "DOMAIN-SUFFIX,"+domain+","+GroupGateMain)
		check(t, i >= 0 && i < cn, domain+" must precede mainland rules")
	}
	want(t, slices.Contains(rules, "DOMAIN-SUFFIX,both.example.com,"+GroupGateDirect), true)
	want(t, slices.Contains(rules, "DOMAIN-SUFFIX,both.example.com,"+GroupGateMain), false)

	yaml := BuildMihomoConfig(s, builderRuntime(), false, "")
	leak := strings.Index(yaml, `"+.browserleaks.com": ["https://1.1.1.1/dns-query#`+GroupProxy+`"`)
	cnPolicy := strings.Index(yaml, `"rule-set:cn-site": ["https://223.5.5.5`)
	check(t, leak >= 0 && leak < cnPolicy, "forced proxy DNS must precede mainland DNS")
	lacks(t, yaml, `"+.both.example.com": ["https://1.1.1.1`)

	s.CustomDirectDomains = []string{"example.net"}
	s.CustomProxyDomains = []string{"a.example.net", "example.network"}
	forced := ForceProxyDomains(s.Sanitized())
	want(t, slices.Contains(forced, "a.example.net"), false)
	want(t, slices.Contains(forced, "example.network"), true)
}

func TestNoSubscriptionFallsBackToDirect(t *testing.T) {
	rt := builderRuntime()
	rt.HasSubscription = false
	yaml := BuildMihomoConfig(DefaultSettings(), rt, false, "")
	lacks(t, yaml, GroupProxy)
	lacks(t, yaml, "proxy-providers")
	has(t, yaml, "MATCH,REJECT")
}

func TestQuotingEscapesSpecialCharacters(t *testing.T) {
	want(t, q("a\"b\\c\nd"), `"a\"b\\c\nd"`)
	yaml := BuildMihomoConfig(DefaultSettings(), builderRuntime(), false, "")
	has(t, yaml, `password: "pw\"x"`)
	want(t, q("\t\r\x1f"), `"\t\r\u001F"`)
}

func TestCatalogHasNoDuplicateOrMalformedEntries(t *testing.T) {
	for _, category := range AIRuleCatalog {
		for _, domain := range slices.Concat(category.Suffixes, category.Domains) {
			if domain != "google" {
				want(t, CleanDomains([]string{domain}), []string{strings.ToLower(domain)})
			}
		}
	}
	rules := AIRuleLines(nil, nil)
	unique := make(map[string]bool)
	for _, rule := range rules {
		unique[rule] = true
	}
	want(t, len(rules), len(unique))
	check(t, len(rules) > 300, "incomplete AI catalog")
	for _, domain := range []string{"anthropic.com", "claude.ai", "clau.de", "claudeusercontent.com", "sentry.io", "statsigapi.net", "intercom.io"} {
		check(t, unique["DOMAIN-SUFFIX,"+domain], "missing rule for "+domain)
	}
	for _, rule := range []string{"DOMAIN-KEYWORD,datadog", "DOMAIN-KEYWORD,sift", "RULE-SET,ai-anthropic",
		"RULE-SET,ai-ntp", "AND,((NETWORK,UDP),(DST-PORT,123))"} {
		check(t, unique[rule], "missing "+rule)
	}
	want(t, CleanDomains(ForceProxyCatalog), ForceProxyCatalog)
}

func TestClaudeStrictSurvivesThirdPartyToggle(t *testing.T) {
	rules := AIRuleLines([]string{"third-party"}, nil)
	for _, keyword := range []string{"sentry", "datadog", "sift"} {
		want(t, slices.Contains(rules, "DOMAIN-KEYWORD,"+keyword), true)
	}
	want(t, slices.Contains(rules, "RULE-SET,ai-anthropic"), true)
	lacks(t, BuildMihomoConfig(DefaultSettings(), builderRuntime(), false, ""), `ntp.org"`)
}

func TestNodeFilterFollowsForbiddenRegions(t *testing.T) {
	matcher := func(pattern string) func(string) bool {
		// consume the neighboring character for these lookarounds when checking for any match
		pattern = strings.NewReplacer(
			`(?<![a-z])`, `(?:^|[^a-z])`,
			`(?![a-z])`, `(?:$|[^a-z])`,
			`(?![a-z0-9])`, `(?:$|[^a-z0-9])`,
		).Replace(pattern)
		return regexp.MustCompile(pattern).MatchString
	}
	settings := DefaultSettings()
	excluded := matcher(NodeExcludeFilter(settings))
	for _, node := range []string{"🇭🇰 香港 01", "HK01 IEPL", "Hong Kong 02", "广港专线", "澳门 01", "MO-01", "中国 回国",
		"CN 直连", "剩余流量：100G", "套餐到期：2027-01-01", "HKG-BGP", "俄罗斯 01"} {
		check(t, excluded(node), "should exclude "+node)
	}
	for _, node := range []string{"日本 东京 01", "🇸🇬 Singapore", "Mongolia", "台湾 01", "韩国 首尔", "Germany Frankfurt",
		"🇺🇸 美国 CN2 GIA", "US-LAX-Hysteria", "USA 02"} {
		check(t, !excluded(node), "should retain "+node)
	}
	settings.ForbiddenRegions = []string{"CN", "HK", "MO", "US"}
	strict := matcher(NodeExcludeFilter(settings))
	check(t, strict("🇺🇸 美国 CN2 GIA") && strict("US-LAX-Hysteria") && strict("洛杉矶 01"), "should exclude US nodes")
	want(t, RegionFlag("US"), "🇺🇸")
}

func TestAndroidTunAndDnsListener(t *testing.T) {
	rt := builderRuntime()
	yaml := BuildMihomoConfig(DefaultSettings(), rt, false, "")
	has(t, yaml, "  stack: mixed\n  device: \"AIGuard\"")
	has(t, yaml, "  auto-route: true\n  auto-detect-interface: true\n  strict-route: true\n  dns-hijack:")
	has(t, yaml, `  listen: "127.0.0.1:1053"`)
	lacks(t, yaml, "mixed-port")
	lacks(t, yaml, "respect-rules")
	lacks(t, yaml, "dns.alidns.com")
	has(t, yaml, `name: "aiguard-probe"`)
	has(t, yaml, `path: "./providers/sub.yaml"`)
	for _, file := range BundledRuleFiles() {
		has(t, yaml, `path: "./rules/`+file+`"`)
	}
	rt.TunStack = "system"
	has(t, BuildMihomoConfig(DefaultSettings(), rt, false, ""), "  stack: system\n")
}

func TestAutoGroupHealthCheckIsSparseButReactive(t *testing.T) {
	s := DefaultSettings()
	yaml := BuildMihomoConfig(s, builderRuntime(), false, "")
	_, rest, _ := strings.Cut(yaml, `  - name: "`+GroupAuto+`"`)
	auto, _, _ := strings.Cut(rest, "  - name:")
	has(t, auto, "interval: 600")
	check(t, AutoCheckIntervalSeconds >= 300, "fallback health checks must be sparse")
	has(t, auto, "max-failed-times: 2")
	lacks(t, yaml, "health-check: {enable: true")
	want(t, s.Routing, RoutingSmart)
	want(t, slices.Contains(MihomoRules(s, ModeProxy, false), "RULE-SET,cn-ip,"+GroupGateCN), true)
}

func TestCaptiveUsesDhcpDnsOnlyForPhysicalInterface(t *testing.T) {
	for _, adapter := range []string{"wlan0", "Wi-Fi", "rmnet_data0", strings.Repeat("a", 64)} {
		yaml := BuildMihomoConfig(DefaultSettings(), builderRuntime(), true, adapter)
		has(t, yaml, "dhcp://"+adapter)
		has(t, yaml, "DOMAIN-SUFFIX,claude.ai,REJECT")
	}
	for _, adapter := range []string{`wlan0"; x`, "以太网", "Wi Fi", strings.Repeat("a", 65), ""} {
		yaml := BuildMihomoConfig(DefaultSettings(), builderRuntime(), true, adapter)
		lacks(t, yaml, "dhcp://")
		has(t, yaml, "  nameserver:\n    - \"https://223.5.5.5/dns-query\"")
	}
}

func TestGameModeRejectsAIAndGoesDirect(t *testing.T) {
	rt := builderRuntime()
	normal := BuildMihomoConfig(DefaultSettings(), rt, false, "")
	has(t, normal, "  strict-route: true\n")
	has(t, normal, "enhanced-mode: fake-ip")
	has(t, normal, "DOMAIN-SUFFIX,claude.ai,"+GroupGateAI)
	rt.Game = true
	game := BuildMihomoConfig(DefaultSettings(), rt, false, "")
	// TUN 照开：AI 网站在 TUN 里按名单拒绝
	has(t, game, "tun:\n  enable: true\n")
	has(t, game, "  strict-route: false\n")
	has(t, game, "enhanced-mode: redir-host")
	has(t, game, "DOMAIN-SUFFIX,claude.ai,REJECT")
	has(t, game, "  - \"MATCH,DIRECT\"\n")
	lacks(t, game, "DOMAIN-SUFFIX,claude.ai,"+GroupGateAI)
	lacks(t, game, "MATCH,"+GroupGateMain)
	// AI 规则必须排在直连之前
	if strings.Index(game, "claude.ai,REJECT") > strings.Index(game, "MATCH,DIRECT") {
		t.Fatal("AI 拒绝规则必须在 MATCH 之前")
	}
}

func TestAIIPv4Ranges(t *testing.T) {
	for _, cidr := range AIIPv4Ranges(nil) {
		if strings.Contains(cidr, ":") || strings.Contains(cidr, ",") || !strings.Contains(cidr, "/") {
			t.Fatalf("非法 IPv4 段 %q", cidr)
		}
	}
}

func TestMihomoYAMLMatchesKotlin(t *testing.T) {
	// generated by the Kotlin builder with the Windows device name and strict-route line
	for _, tc := range []struct {
		name    string
		mode    ProxyMode
		route   RoutingMode
		sub     bool
		captive bool
		adapter string
		sha256  string
	}{
		{"proxy-smart", ModeProxy, RoutingSmart, true, false, "", "6c4ff433136798450d12b9b26385dafddcab04696acfe285cbc8e972cc4e49d1"},
		{"proxy-global", ModeProxy, RoutingGlobal, true, false, "", "6c4ff433136798450d12b9b26385dafddcab04696acfe285cbc8e972cc4e49d1"},
		{"direct-sub", ModeDirect, RoutingSmart, true, false, "", "56f6a9e15430a164a716f573d1339ac2358f45b4dacff912440bab4f10c4cadc"},
		{"direct-no-sub", ModeDirect, RoutingSmart, false, false, "", "9ad22d29bd871c2a915060acb287b1d526f873821d5fe67be00318a4d75af7e2"},
		{"captive-dhcp", ModeProxy, RoutingSmart, true, true, "wlan0", "6b96a5b473c5170ba19418cde892aec0476971bdd8e162d6e840cb12d847ca50"},
		{"captive-domestic", ModeProxy, RoutingSmart, true, true, "以太网", "a30c6869cdd680dd99d2459338d70ebddfe67ee45681a038eb388c8e319d1ec1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, rt := DefaultSettings(), builderRuntime()
			s.Mode, s.Routing, rt.HasSubscription = tc.mode, tc.route, tc.sub
			s.CustomProxyDomains = []string{"leak.example.org", "both.example.com"}
			s.CustomDirectDomains = []string{"both.example.com"}
			s.CustomAIDomains = []string{"example.ai"}
			yaml := BuildMihomoConfig(s, rt, tc.captive, tc.adapter)
			want(t, fmt.Sprintf("%x", sha256.Sum256([]byte(yaml))), tc.sha256)
		})
	}
}

func TestGeneratedConfigsPassMihomoValidation(t *testing.T) {
	if os.Getenv("AIGUARD_INTEGRATION") != "1" {
		t.Skip("set AIGUARD_INTEGRATION=1 to validate with the bundled mihomo")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("the Kotlin validation fixture uses the macOS mihomo")
	}
	vendor, err := filepath.Abs("../../../Vendor")
	if err != nil {
		t.Fatal(err)
	}
	mihomo := filepath.Join(vendor, "mihomo")
	if stat, err := os.Stat(mihomo); err != nil || stat.Mode().Perm()&0111 == 0 {
		t.Skip("Vendor/mihomo is unavailable or not executable")
	}
	dir := t.TempDir()
	for _, folder := range []string{"providers", "rules"} {
		if err := os.Mkdir(filepath.Join(dir, folder), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range BundledRuleFiles() {
		data, err := os.ReadFile(filepath.Join(vendor, "rules", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "rules", f), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	provider := "proxies:\n  - {name: \"US 01\", type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}\n"
	if err := os.WriteFile(filepath.Join(dir, "providers", "sub.yaml"), []byte(provider), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		mode  ProxyMode
		route RoutingMode
		sub   bool
		game  bool
	}{
		{"proxy-smart", ModeProxy, RoutingSmart, true, false},
		{"proxy-global", ModeProxy, RoutingGlobal, true, false},
		{"direct-sub", ModeDirect, RoutingSmart, true, false},
		{"direct-no-sub", ModeDirect, RoutingSmart, false, false},
		{"game", ModeProxy, RoutingSmart, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, rt := DefaultSettings(), builderRuntime()
			s.Mode, s.Routing, rt.HasSubscription, rt.Game = tc.mode, tc.route, tc.sub, tc.game
			s.CustomProxyDomains = []string{"leak.example.org"}
			config := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(config, []byte(BuildMihomoConfig(s, rt, false, "")), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, mihomo, "-t", "-d", dir, "-f", config).CombinedOutput()
			if err != nil || !bytes.Contains(out, []byte("test is successful")) {
				t.Fatalf("mihomo -t: %v\n%s", err, out[max(0, len(out)-600):])
			}
		})
	}
}
