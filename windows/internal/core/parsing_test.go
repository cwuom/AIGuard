package core

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestClashYAMLKeepsOnlyProxies(t *testing.T) {
	yaml := `port: 7890
proxies:
  - {name: "🇺🇸 US 01", type: ss, server: a.example.com, port: 443, cipher: aes-128-gcm, password: x}
  - name: "JP 02"
    type: trojan
    server: b.example.com
    port: 443
    password: y
proxy-groups:
  - {name: G, type: select, proxies: ["JP 02"]}
rules:
  - MATCH,DIRECT`
	p, err := ParseSubscription([]byte(yaml))
	want(t, err, nil)
	want(t, p.NodeCount, 2)
	lacks(t, p.ProviderContent, "rules:")
	lacks(t, p.ProviderContent, "proxy-groups")
}

func TestBase64URIList(t *testing.T) {
	list := "ss://YWVzLTEyOC1nY206eA@1.2.3.4:8388#US\ntrojan://pw@host.example:443?sni=x#JP\n"
	p, err := ParseSubscription([]byte(base64.StdEncoding.EncodeToString([]byte(list))))
	want(t, err, nil)
	want(t, p.NodeCount, 2)
	want(t, p.ProviderContent, list)
}

func TestRejectsHTMLAndEmpty(t *testing.T) {
	_, err := ParseSubscription([]byte("<html><body>login</body></html>"))
	want(t, err, ErrUnrecognizedSubscription)
	_, err = ParseSubscription([]byte("  \n"))
	want(t, err, ErrEmptySubscription)
}

func TestServerHostsFromAllFormats(t *testing.T) {
	yaml := `proxies:
  - {name: "JP 01", type: ss, server: jp1.example.com, port: 443, cipher: aes-128-gcm, password: x}
  - name: "SG 02"
    type: trojan
    server: 203.0.113.7
    port: 443
    password: y`
	want(t, ServerHosts(yaml), []string{"203.0.113.7", "jp1.example.com"})
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"US","add":"us.example.net","port":"443","id":"x"}`))
	uris := `trojan://pw@tr.example.org:443?sni=x#JP
vless://uuid@198.51.100.9:8443?type=ws#SG
hysteria2://auth@hy.example.com:5000/?insecure=1#HY
vmess://` + vmess
	want(t, ServerHosts(uris), []string{"198.51.100.9", "hy.example.com", "tr.example.org", "us.example.net"})
	want(t, len(ServerHosts(`  - {server: "evil;-j ACCEPT", port: 1}`)), 0)
}

func TestUsageHeader(t *testing.T) {
	u := ParseSubscriptionUsage("upload=1024; download=2048; total=10737418240; expire=1767225600")
	check(t, u != nil, "usage header rejected")
	want(t, u.Used(), int64(3072))
	want(t, u.Expire, ptr(int64(1767225600)))
	want(t, ParseSubscriptionUsage("foo=bar"), nil)
	want(t, (SubscriptionUsage{Upload: math.MaxInt64, Download: 10}).Used(), int64(math.MaxInt64))
	u = ParseSubscriptionUsage("upload=1.2; download=1e400; total=5")
	check(t, u != nil, "valid total should keep the usage header")
	want(t, u.Upload, int64(1))
	want(t, u.Download, int64(0))
}

func TestProfileNameFromHeaders(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("我的机场"))
	want(t, ProfileName(map[string]string{"Profile-Title": "base64:" + b64}), ptr("我的机场"))
	want(t, ProfileName(map[string]string{"content-disposition": "attachment; filename*=UTF-8''%E6%9C%BA%E5%9C%BA"}), ptr("机场"))
	want(t, ProfileName(map[string]string{"Content-Disposition": `attachment; filename="sub.yaml"`}), ptr("sub.yaml"))
}

func TestURLValidationAndMasking(t *testing.T) {
	for _, raw := range []string{"ftp://x.com/a", "https:///nohost", "https://bad_host/a", "https://sub.example.com/a b",
		"https://example.com../", "https://host:9999999999/x", "https://[::1]/x[y]"} {
		check(t, ValidateSubscriptionURL(raw) == nil, "invalid URL accepted")
	}
	check(t, ValidateSubscriptionURL(" https://sub.example.com/api/v1/client/abcd1234?token=x ") != nil, "valid URL rejected")
	s := SubscriptionInfo{URL: "https://sub.example.com/api/v1/client/abcd1234"}
	want(t, s.MaskedURL(), "https://sub.example.com/••••1234")
	want(t, s.Host(), "sub.example.com")
	s.URL = "https://u:p@SUB.example.com:443/api/abc%2F?token=x#hidden"
	want(t, s.MaskedURL(), "https://SUB.example.com/••••c%2F")
	want(t, s.Host(), "sub.example.com")
	s.URL = "https://[2001:db8::1]/short"
	want(t, s.MaskedURL(), "https://[2001:db8::1]/••••hort")
	s.URL = "HTTPS://[fe80::1%en0]/short"
	want(t, s.MaskedURL(), "HTTPS://[fe80::1%en0]/••••hort")
	s.URL = "https://127.000.0.01/short"
	want(t, s.Host(), "127.000.0.01")
	want(t, (SubscriptionInfo{URL: "/no/host"}).MaskedURL(), "••••")
}

func TestExitTraceParsers(t *testing.T) {
	want(t, ParseCloudflareTrace("fl=1\nip=1.2.3.4\nloc=jp\n"), ptr(ExitTrace{"1.2.3.4", "JP"}))
	want(t, ParseCloudflareTrace("ip=1.2.3.4\nloc=XYZ\n"), nil)
	want(t, ParseJSONTrace(`{"ip":"5.6.7.8","country":"US"}`), ptr(ExitTrace{"5.6.7.8", "US"}))
	want(t, ParseJSONTrace(`{"query":"5.6.7.8","countryCode":"sg"}`), ptr(ExitTrace{"5.6.7.8", "SG"}))
	want(t, ParseJSONTrace(`{"ip":"5.6.7.8","country":"1A"}`), nil)
}

func TestOldSettingsFileDecodesWithDefaultsAndUnknownKeys(t *testing.T) {
	var s GuardSettings
	err := json.Unmarshal([]byte(`{"enabled":false,"futureField":1,"mode":"bogus","routing":null,"forbiddenRegions":null,"lockPrivateDns":false,"networkHoldSeconds":4,"extraAIPackages":["ignored"],"LockSystemDns":false}`), &s)
	want(t, err, nil)
	d := DefaultSettings()
	d.Enabled = false
	want(t, s, d)
	want(t, s.Mode, ModeProxy)
	want(t, s.ProbeIntervalSeconds, 2)
	want(t, s.WakeHoldSeconds, 8)
	want(t, s.LockSystemDNS, true)
}

func TestMainlandAlwaysForbiddenAndValuesClamped(t *testing.T) {
	s := DefaultSettings()
	s.ForbiddenRegions = []string{"hk", "US", "x", "HK"}
	s.Schema, s.ProbeIntervalSeconds, s.LatencyThresholdMs = 99, 0, 99999
	s.FailureThreshold, s.RecoverSuccesses, s.WakeHoldSeconds, s.SubscriptionUpdateHours = 99, -1, 70, 999
	s = s.Sanitized()
	want(t, s.ForbiddenRegions, []string{"CN", "HK", "US"})
	want(t, s.Schema, CurrentSchema)
	want(t, s.ProbeIntervalSeconds, 1)
	want(t, s.LatencyThresholdMs, 10000)
	want(t, s.FailureThreshold, 20)
	want(t, s.RecoverSuccesses, 1)
	want(t, s.WakeHoldSeconds, 60)
	want(t, s.SubscriptionUpdateHours, 168)
	want(t, DefaultSettings().Sanitized().ForbiddenRegions, []string{"CN", "HK", "MO"})
	want(t, NewFuseConfig(s, ModeProxy).NetworkHoldMs, int64(60000))
}

func TestDomainAndPackageSanitizers(t *testing.T) {
	want(t, CleanDomains([]string{"HTTPS://Example.com/path", "*.a-b.example.org", "bad domain.com", "nodot", "x..y.com", "example.com"}),
		[]string{"example.com", "a-b.example.org"})
	want(t, CleanProcessNames([]string{" Cherry Studio ", "cherry studio.EXE", "com.x; rm -rf /", "nodot", "1abc.def", "C:\\apps\\codex.exe",
		"bad&name", ".exe", strings.Repeat("a", 65), strings.Repeat("a", 64)}),
		[]string{"cherry studio.exe", "nodot.exe", "1abc.def.exe", strings.Repeat("a", 64) + ".exe"})
}

func TestIPCRoundTrip(t *testing.T) {
	s := DefaultSettings()
	s.CustomAIDomains = []string{"x.ai"}
	req := IpcEnvelope{"tok", Request{Type: RequestUpdateSettings, Settings: &s}}
	text, err := json.Marshal(req)
	want(t, err, nil)
	var back IpcEnvelope
	want(t, json.Unmarshal(text, &back), nil)
	want(t, back, req)

	status := DefaultGuardStatus()
	status.Phase = PhaseTripped
	status.Fuse = FuseSnapshot{Tripped: true, Reason: &FuseReason{Type: ReasonUnsafeExit, Country: "HK"}}
	status.Latency = []LatencySample{{At: 1}, {At: 2, MS: ptr(120)}}
	resp := DefaultIpcResponse()
	resp.Status = &status
	data, err := json.Marshal(resp)
	want(t, err, nil)
	has(t, string(data), `"reason":{"type":"unsafeExit","country":"HK"}`)
	has(t, string(data), `"latency":[{"at":1},{"at":2,"ms":120}]`)
	has(t, string(data), `"systemDnsLocked":false`)
	lacks(t, string(data), `"privateDnsLocked"`)
	var responseBack IpcResponse
	want(t, json.Unmarshal(data, &responseBack), nil)
	want(t, responseBack, resp)
	want(t, json.Unmarshal([]byte(`{"token":"t","request":{"type":"status"}}`), &back), nil)
	want(t, back.Request, Request{Type: RequestStatus})
}

func TestKotlinJSONDefaultsAndDiscriminators(t *testing.T) {
	for _, tc := range []struct {
		request Request
		wire    string
	}{
		{Request{Type: RequestImportSubscription, URL: ""}, `{"type":"importSubscription","url":""}`},
		{Request{Type: RequestRestoreNetwork}, `{"type":"restoreNetwork","force":false}`},
		{Request{Type: RequestEvents}, `{"type":"events","after":0}`},
		{Request{Type: RequestCaptiveLogin}, `{"type":"captiveLogin","minutes":0}`},
	} {
		t.Run(tc.request.Type, func(t *testing.T) {
			data, err := json.Marshal(tc.request)
			want(t, err, nil)
			want(t, string(data), tc.wire)
			var got Request
			want(t, json.Unmarshal(data, &got), nil)
			want(t, got, tc.request)
		})
	}
	for _, tc := range []struct {
		reason FuseReason
		wire   string
	}{
		{FuseReason{Type: ReasonProxyUnstable, Failures: 2}, `{"type":"proxyUnstable","failures":2}`},
		{FuseReason{Type: ReasonUnsafeExit, Country: "HK"}, `{"type":"unsafeExit","country":"HK"}`},
		{FuseReason{Type: ReasonCoreDown}, `{"type":"coreDown"}`},
	} {
		var got FuseReason
		want(t, json.Unmarshal([]byte(tc.wire), &got), nil)
		want(t, got, tc.reason)
		b, err := json.Marshal(got)
		want(t, err, nil)
		want(t, string(b), tc.wire)
	}
	var status GuardStatus
	want(t, json.Unmarshal([]byte(`{"phase":"newPhase","ipv6Blocked":null,"unrelated":0}`), &status), nil)
	want(t, status, DefaultGuardStatus())
	var response IpcResponse
	want(t, json.Unmarshal([]byte(`{}`), &response), nil)
	want(t, response, DefaultIpcResponse())
	want(t, json.Unmarshal([]byte(`{"events":[]}`), &response), nil)
	data, err := json.Marshal(response)
	want(t, err, nil)
	want(t, string(data), `{"ok":true,"events":[]}`)
	want(t, MaxMessageBytes, 4*1024*1024)
	want(t, PipeName, `\\.\pipe\aiguard-control`)
	want(t, ServiceName, "AIGuard")
	want(t, Ports.Controller, 19097)
	want(t, Ports.Probe, 17892)
	want(t, Ports.DirectProbe, 17893)
	want(t, Ports.DNS, 1053)
	var envelope IpcEnvelope
	want(t, json.Unmarshal([]byte(`{"token":"t","request":{"type":"status","settings":12,"forCe":true}}`), &envelope), nil)
	want(t, envelope.Request, Request{Type: RequestStatus})
	want(t, json.Unmarshal([]byte(`{"token":"t","request":{"type":"clearEvents","after":{"ignored":true}}}`), &envelope), nil)
	var reason FuseReason
	want(t, json.Unmarshal([]byte(`{"type":"starting","country":true}`), &reason), nil)
	want(t, reason, FuseReason{Type: ReasonStarting})
	for _, invalid := range []string{
		`{}`, `{"token":"t","request":{"type":"events","After":0}}`,
		`{"token":"t","request":{"type":"events","after":2147483648}}`,
		`{"token":"t","request":{"type":"updateSettings","settings":{"customAIDomains":[null]}}}`,
	} {
		check(t, json.Unmarshal([]byte(invalid), &envelope) != nil, "accepted invalid envelope "+invalid)
	}
}

func TestVersionOrdering(t *testing.T) {
	want(t, CompareVersions("1.10.0", "1.9.2"), 1)
	want(t, CompareVersions("1.0", "1.0.0"), 0)
	want(t, CompareVersions("1.0.0", "1.0.1"), -1)
	want(t, CompareVersions("1.2147483648", "1.0"), 0)
}

func TestProviderNodesMergedIntoProxies(t *testing.T) {
	top := `{"proxies":{"自动选择":{"type":"Fallback","now":"JP 01","all":["JP 01","US 01"],"history":[{"delay":51}]},"DIRECT":{"type":"Direct","history":[]}}}`
	providers := `{"providers":{"sub":{"proxies":[{"name":"JP 01","type":"Shadowsocks","history":[{"delay":0},{"delay":88}]},{"name":"US 01","type":"Shadowsocks","history":[{"delay":0}]},{"name":"HK 01","type":"Shadowsocks","history":[]}]},"default":{"proxies":[{"name":"DIRECT","type":"Direct","history":[{"delay":9}]}]}}}`
	nodes, ok := ParseProxies(top, &providers)
	want(t, ok, true)
	want(t, nodes["JP 01"].LastDelay, ptr(88))
	check(t, nodes["US 01"].Tested && nodes["US 01"].LastDelay == nil, "zero delay is a tested timeout")
	want(t, nodes["HK 01"].Tested, false)
	want(t, nodes["自动选择"].All, []string{"JP 01", "US 01"})
	want(t, nodes["DIRECT"].Tested, false)
	nodes, ok = ParseProxies(top, nil)
	want(t, ok, true)
	want(t, len(nodes), 2)
	for _, invalid := range []string{`{"error":"x"}`, "not json"} {
		nodes, ok := ParseProxies(top, &invalid)
		want(t, ok, false)
		want(t, len(nodes), 0)
	}
}

func TestConnectionsParseAndRouteKind(t *testing.T) {
	data := `{"downloadTotal":10,"uploadTotal":5,"connections":[
    {"id":"a","metadata":{"network":"tcp","host":"claude.ai","destinationIP":"198.18.0.9","destinationPort":"443"},
     "upload":1,"download":2,"start":"2026-11-27T10:00:00.123Z","chains":["🇸🇬 SG 01","节点选择","AIGUARD-GATE-AI"],"rule":"DomainSuffix","rulePayload":"claude.ai"},
    {"id":"b","metadata":{"network":"udp","sniffHost":"x.cn","destinationIP":"1.1.1.1","destinationPort":"53"},"chains":["DIRECT"],"rule":"Match","rulePayload":""}]}`
	snap, ok := ParseConnections(data)
	want(t, ok, true)
	want(t, len(snap.Connections), 2)
	a, b := snap.Connections[0], snap.Connections[1]
	want(t, a.Chain, "节点选择 → 🇸🇬 SG 01")
	want(t, a.Rule, "DomainSuffix · claude.ai")
	want(t, a.Route(), RouteProxy)
	want(t, a.Start, ptr(int64(1795773600123)))
	want(t, a.Destination, "198.18.0.9:443")
	want(t, a.Network, "TCP")
	want(t, b.Host, "x.cn")
	want(t, b.Route(), RouteDirect)
	a.Leaf = "REJECT-DROP"
	want(t, a.Route(), RouteReject)
	a.Leaf = "DIRECT-HK 备用"
	want(t, a.Route(), RouteProxy)
}
