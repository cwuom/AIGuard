package guard

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aiguard/internal/core"
	"aiguard/internal/wfpolicy"
	"aiguard/internal/winsys"
)

type callLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *callLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, s)
}

func (l *callLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.lines)
}

type fakeFirewall struct {
	calls           *callLog
	mu              sync.Mutex
	policy, pending wfpolicy.Policy
	forced          bool
	forceCalled     chan struct{}
	context         wfpolicy.Context
	applyErr        error
	issue           string
}

func (f *fakeFirewall) Apply(p wfpolicy.Policy, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.add(fmt.Sprintf("apply:%s:%t:%t", p.Kind, p.AllowTun, force))
	if f.applyErr != nil {
		return f.applyErr
	}
	if f.forced {
		f.pending = p
	} else {
		f.policy = p
	}
	return nil
}
func (f *fakeFirewall) Current() wfpolicy.Policy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.policy
}
func (f *fakeFirewall) LastError() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applyErr
}
func (f *fakeFirewall) Verify() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.add("verify")
	return f.issue
}
func (f *fakeFirewall) SetContext(c wfpolicy.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.context = c
	f.calls.add("context")
}
func (f *fakeFirewall) ForceLockdown() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.add("force")
	if !f.forced {
		f.forced, f.pending = true, f.policy
		f.policy = wfpolicy.Policy{Kind: wfpolicy.Lockdown}
	}
	if f.forceCalled != nil {
		close(f.forceCalled)
		f.forceCalled = nil
	}
	return nil
}
func (f *fakeFirewall) ReleaseForcedLockdown() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.add("release")
	if f.forced {
		f.forced, f.policy = false, f.pending
	}
	return nil
}
func (f *fakeFirewall) Teardown() error { return f.Apply(wfpolicy.Policy{Kind: wfpolicy.None}, true) }

type fakeCore struct {
	calls    *callLog
	mu       sync.Mutex
	running  bool
	restarts int
	callback func(int)
	yaml     string
	writeErr error
}

func (c *fakeCore) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = true
	c.calls.add("start")
	return nil
}
func (c *fakeCore) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	c.calls.add("stop")
}
func (c *fakeCore) Running() bool   { c.mu.Lock(); defer c.mu.Unlock(); return c.running }
func (c *fakeCore) Restarts() int   { c.mu.Lock(); defer c.mu.Unlock(); return c.restarts }
func (c *fakeCore) NoteRestart()    { c.mu.Lock(); defer c.mu.Unlock(); c.restarts++ }
func (c *fakeCore) Version() string { return "test-mihomo" }
func (c *fakeCore) WriteConfig(yaml string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls.add("write-config")
	if c.writeErr != nil {
		return c.writeErr
	}
	c.yaml = yaml
	return nil
}
func (c *fakeCore) KillStale()         { c.calls.add("kill-stale") }
func (c *fakeCore) PIDs() []uint32     { return nil }
func (c *fakeCore) OnExit(f func(int)) { c.mu.Lock(); defer c.mu.Unlock(); c.callback = f }
func (c *fakeCore) exit(code int) {
	c.mu.Lock()
	c.running = false
	f := c.callback
	c.mu.Unlock()
	f(code)
}

type fakeSystem struct {
	calls          *callLog
	dns            atomic.Bool
	ipv6           atomic.Int32
	leak           atomic.Bool
	route          atomic.Uint64
	network        atomic.Int64
	v6Probe        func() bool
	dnsHook        func()
	restoreDNSHook func()
	closeHook      func(AppKind, []string, func() bool) []string
	scanMu         sync.Mutex
	scan           AppScan
	scans          int
	aiCloses       int
	tunnels        []bool
}

func (s *fakeSystem) setScan(scan AppScan) { s.scanMu.Lock(); defer s.scanMu.Unlock(); s.scan = scan }
func (s *fakeSystem) closes() int {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	return s.aiCloses
}

func (s *fakeSystem) Interfaces() ([]winsys.Iface, error) {
	return []winsys.Iface{
		{LUID: 1, Alias: "WiFi", GUID: "wifi", Up: true, Physical: true, IPv4: []string{fmt.Sprint("192.0.2.", s.network.Load()+1)}, Gateways: []string{"192.0.2.254"}},
		{LUID: 2, Alias: winsys.TunAlias, Up: true, Tunnel: true},
	}, nil
}
func (s *fakeSystem) DefaultRouteLUID() uint64 { return s.route.Load() }
func (s *fakeSystem) IPv6Reachable(time.Duration) bool {
	s.calls.add("probe-v6")
	if s.v6Probe != nil {
		return s.v6Probe()
	}
	return s.leak.Load()
}
func (s *fakeSystem) LockDNS([]winsys.Iface) (bool, []string) {
	s.calls.add("lock-dns")
	if s.dnsHook != nil {
		s.dnsHook()
	}
	return !s.dns.Swap(true), nil
}
func (s *fakeSystem) RestoreDNS() []string {
	s.calls.add("restore-dns")
	if s.restoreDNSHook != nil {
		s.restoreDNSHook()
	}
	s.dns.Store(false)
	return nil
}
func (s *fakeSystem) DNSLocked() bool { return s.dns.Load() }
func (s *fakeSystem) DisableIPv6([]winsys.Iface) []string {
	s.calls.add("disable-v6")
	s.ipv6.Store(1)
	return nil
}
func (s *fakeSystem) RestoreIPv6() []string  { s.calls.add("restore-v6"); s.ipv6.Store(0); return nil }
func (s *fakeSystem) IPv6DisabledCount() int { return int(s.ipv6.Load()) }
func (s *fakeSystem) CloseApps(kinds AppKind, extras []string, want func() bool) []string {
	if kinds == KindAI {
		s.scanMu.Lock()
		s.aiCloses++
		s.scanMu.Unlock()
	}
	if s.closeHook != nil {
		return s.closeHook(kinds, extras, want)
	}
	return nil
}
func (s *fakeSystem) ScanConflicts(withTunnels bool) []string {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	s.tunnels = append(s.tunnels, withTunnels)
	return nil
}
func (s *fakeSystem) ScanApps([]string, []string) AppScan {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	s.scans++
	return s.scan
}

type fakeClock struct {
	mono, unbiased atomic.Int64
}

func (c *fakeClock) Mono() int64      { return c.mono.Load() }
func (c *fakeClock) Unbiased() int64  { return c.unbiased.Load() }
func (c *fakeClock) Wall() int64      { return 1700000000000 + c.Mono() }
func (c *fakeClock) advance(ms int64) { c.mono.Add(ms); c.unbiased.Add(ms) }

type fakeController struct {
	versionHook   func(context.Context)
	calls         *callLog
	mu            sync.Mutex
	groups        map[string]string
	nodes         []string
	providerCount atomic.Int32
	up            atomic.Bool
	flushOK       atomic.Bool
	reloadStatus  atomic.Int32
	nodeAlive     atomic.Bool
	beforeSelect  func(group, target string)
}

func (c *fakeController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	send := func(obj any) { _ = json.NewEncoder(w).Encode(obj) }
	switch {
	case r.URL.Path == "/version" && r.Method == http.MethodGet:
		if c.versionHook != nil {
			c.versionHook(r.Context())
		}
		if !c.up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		send(map[string]string{"version": "test-mihomo"})
	case r.URL.Path == "/proxies" && r.Method == http.MethodGet:
		send(map[string]any{"proxies": map[string]any{}})
	case len(path) == 3 && path[0] == "group" && path[2] == "delay":
		c.calls.add("group-delay:" + path[1])
		send(map[string]int{"US": 20})
	case len(path) == 3 && path[0] == "proxies" && path[2] == "delay":
		send(map[string]int{"delay": 20})
	case len(path) == 2 && path[0] == "proxies":
		group := path[1]
		if r.Method == http.MethodPut {
			var v struct{ Name string }
			if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
				w.WriteHeader(400)
				return
			}
			if c.beforeSelect != nil {
				c.beforeSelect(group, v.Name)
			}
			c.mu.Lock()
			c.groups[group] = v.Name
			c.mu.Unlock()
			c.calls.add("select:" + group + ":" + v.Name)
			w.WriteHeader(204)
		} else {
			c.mu.Lock()
			now := c.groups[group]
			c.mu.Unlock()
			send(map[string]any{"now": now, "all": c.nodes, "alive": c.nodeAlive.Load()})
		}
	case r.URL.Path == "/connections" && r.Method == http.MethodDelete:
		c.calls.add("flush")
		if !c.flushOK.Load() {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	case r.URL.Path == "/configs" && r.Method == http.MethodPut:
		var config map[string]string
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			w.WriteHeader(400)
			return
		}
		c.calls.add("reload:" + config["path"])
		if status := int(c.reloadStatus.Load()); status != 0 {
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/providers/proxies/"+core.GroupProvider:
		if r.Method == http.MethodPut {
			c.calls.add("reload-provider")
			w.WriteHeader(204)
		} else {
			send(map[string]any{"proxies": make([]any, c.providerCount.Load())})
		}
	case r.URL.Path == "/providers/proxies" && r.Method == http.MethodGet:
		send(map[string]any{"providers": map[string]any{}})
	default:
		http.NotFound(w, r)
	}
}

type fakeFetcher struct {
	*core.ProxiedFetcher
	calls               *callLog
	beat                func(context.Context) *core.ExitTrace
	fallback, candidate *core.ExitTrace
}

func (f *fakeFetcher) ResetAll(ctx context.Context) {
	f.calls.add("reset-all")
	f.ProxiedFetcher.ResetAll(ctx)
}

func (f *fakeFetcher) Reset(ctx context.Context, port *int) {
	f.calls.add("reset-probe")
	f.ProxiedFetcher.Reset(ctx, port)
}

func (f *fakeFetcher) Fetch(ctx context.Context, target string, port *int, timeout int64, maxBytes int, headers map[string]string) (*core.FetchResult, bool) {
	if port != nil {
		f.calls.add(fmt.Sprintf("fetch-proxy:%d", *port))
		return nil, false
	}
	return f.ProxiedFetcher.Fetch(ctx, target, nil, timeout, maxBytes, headers)
}

func (f *fakeFetcher) Heartbeat(ctx context.Context, _ int, _ int64) (*core.ExitTrace, bool) {
	f.calls.add("heartbeat")
	if f.beat != nil {
		trace := f.beat(ctx)
		return trace, trace != nil
	}
	return nil, false
}

func (f *fakeFetcher) IPInfo(context.Context, int, int64) (*core.ExitTrace, bool) {
	f.calls.add("ipinfo")
	return f.fallback, f.fallback != nil
}

func (f *fakeFetcher) ExitTrace(context.Context, int) (*core.ExitTrace, bool) {
	return f.candidate, f.candidate != nil
}

func (f *fakeFetcher) ResolveDirect(_ context.Context, host string, _ int) ([]string, bool) {
	f.calls.add("resolve:" + host)
	return []string{"198.18.0.1", "198.19.255.255", "203.0.113.2", "2001:db8::1"}, true
}

type fixture struct {
	fetcher    *fakeFetcher
	g          *Guardian
	firewall   *fakeFirewall
	process    *fakeCore
	system     *fakeSystem
	clock      *fakeClock
	controller *fakeController
	paths      Paths
	calls      *callLog
}

func newFixture(t *testing.T, settings core.GuardSettings) *fixture {
	t.Helper()
	dir := t.TempDir()
	b := &fixture{calls: &callLog{}, paths: Paths{
		DataDir: dir, CoreHome: dir, Settings: filepath.Join(dir, "settings.json"), Events: filepath.Join(dir, "events.json"),
		Runtime: filepath.Join(dir, "runtime.json"), ProviderFile: filepath.Join(dir, "providers", "sub.yaml"),
		CoreConfig: filepath.Join(dir, "config.yaml"), CNTable: filepath.Join(dir, "cn4.txt"),
	}}
	b.firewall = &fakeFirewall{calls: b.calls, policy: wfpolicy.Policy{Kind: wfpolicy.None}}
	b.process = &fakeCore{calls: b.calls}
	b.system = &fakeSystem{calls: b.calls}
	b.system.route.Store(2)
	b.clock = &fakeClock{}
	b.controller = &fakeController{calls: b.calls, groups: map[string]string{core.GroupProxy: "US"}, nodes: []string{core.GroupAuto, "US", "JP"}}
	b.controller.up.Store(true)
	b.controller.flushOK.Store(true)
	b.controller.nodeAlive.Store(true)
	b.controller.providerCount.Store(1)
	server := httptest.NewServer(b.controller)
	t.Cleanup(server.Close)
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(b.paths.Settings, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(b.paths.CNTable, []byte("1.0.1.0/24\ninvalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if settings.Subscription != nil {
		if err = os.MkdirAll(filepath.Dir(b.paths.ProviderFile), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(b.paths.ProviderFile, []byte("proxies: [{name: US, server: 192.0.2.1}]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b.g, err = New(Options{Version: "test", Paths: b.paths, Firewall: b.firewall, Core: b.process, System: b.system, Clock: b.clock, ControllerURL: server.URL,
		WFContext: wfpolicy.Context{CoreExe: "core", ServiceExe: "daemon", UIExe: "ui", ControllerPort: 19097, ProbePorts: []uint16{17892, 17893}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b.fetcher = &fakeFetcher{ProxiedFetcher: b.g.fetcher.(*core.ProxiedFetcher), calls: b.calls}
	b.g.fetcher = b.fetcher
	t.Cleanup(b.g.Shutdown)
	return b
}

func (b *fixture) boot() {
	b.g.mu.Lock()
	defer b.g.mu.Unlock()
	b.g.boot(context.Background())
}

func (b *fixture) beat() time.Duration {
	b.g.mu.Lock()
	defer b.g.mu.Unlock()
	return b.g.heartbeat(context.Background())
}

func (b *fixture) tick() {
	b.g.mu.Lock()
	defer b.g.mu.Unlock()
	b.g.tick(context.Background())
}

func (b *fixture) request(t *testing.T, r core.Request) core.IpcResponse {
	t.Helper()
	raw, err := json.Marshal(core.IpcEnvelope{Token: "unused", Request: r})
	if err != nil {
		t.Fatal(err)
	}
	return b.handle(t, raw)
}

func (b *fixture) handle(t *testing.T, raw []byte) core.IpcResponse {
	t.Helper()
	var out core.IpcResponse
	if err := json.Unmarshal(b.g.Handle(context.Background(), raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func eventually(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !ok() {
		select {
		case <-deadline.C:
			t.Fatal("condition did not become true")
		case <-tick.C:
		}
	}
}

func ordered(t *testing.T, got []string, want ...string) {
	t.Helper()
	i := 0
	for _, call := range got {
		if call == want[i] {
			i++
			if i == len(want) {
				return
			}
		}
	}
	t.Fatalf("want ordered %q in %q", want, got)
}

func TestBootInstallsWhitelistBeforeCore(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.boot()
	calls := b.calls.list()
	ordered(t, calls, "context", "apply:whitelist:false:true", "start")
	for _, call := range calls {
		if strings.HasPrefix(call, "apply:") {
			if call != "apply:whitelist:false:true" {
				t.Fatalf("first policy: %s", call)
			}
			break
		}
	}
	if c := b.firewall.context; len(c.BootstrapDNS) != 2 || len(c.CNRanges) != 1 || c.UIExe != "ui" {
		t.Fatalf("firewall context: %+v", c)
	}
}

func TestBootDisabledRestoresSystemNetwork(t *testing.T) {
	s := core.DefaultSettings()
	s.Enabled = false
	b := newFixture(t, s)
	b.boot()
	calls := b.calls.list()
	ordered(t, calls, "apply:none:false:true", "restore-v6", "restore-dns")
	if slices.Contains(calls, "start") || b.firewall.Current().Kind != wfpolicy.None {
		t.Fatal(calls)
	}
}

func TestGateConfirmationRequiresFlushAndRestoresProxy(t *testing.T) {
	s := core.DefaultSettings()
	s.Subscription = &core.SubscriptionInfo{URL: "http://192.0.2.2/profile"}
	b := newFixture(t, s)
	b.controller.flushOK.Store(false)
	b.boot()
	ordered(t, b.calls.list(), "select:"+core.GroupGateAI+":REJECT", "select:"+core.GroupGateMain+":REJECT", "flush")
	if b.firewall.Current().AllowTun {
		t.Fatal("allowed TUN after failed flush")
	}
	b.controller.flushOK.Store(true)
	b.tick()
	if p := b.firewall.Current(); !p.AllowTun || p.TunLUID != 2 {
		t.Fatalf("TUN not allowed: %+v", p)
	}
	r := b.request(t, core.Request{Type: core.RequestRestoreNetwork, Force: true})
	if !r.OK || r.Status.Fuse.Tripped {
		t.Fatalf("restore: %+v", r)
	}
	eventually(t, func() bool {
		b.controller.mu.Lock()
		defer b.controller.mu.Unlock()
		return b.controller.groups[core.GroupGateAI] == core.GroupProxy && b.controller.groups[core.GroupGateMain] == core.GroupProxy
	})
}

func TestCoreExitTripsAndBacksOff(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.boot()
	b.tick()
	b.process.exit(9)
	eventually(t, func() bool {
		b.g.mu.Lock()
		defer b.g.mu.Unlock()
		return b.process.Restarts() == 1
	})
	r := b.request(t, core.Request{Type: core.RequestStatus})
	if reason := r.Status.Fuse.Reason; reason == nil || reason.Type != core.ReasonCoreDown {
		t.Fatalf("reason: %+v", reason)
	}
	b.clock.advance(999)
	b.tick()
	if b.process.Running() {
		t.Fatal("restarted before backoff")
	}
	b.clock.advance(1)
	b.tick()
	if !b.process.Running() {
		t.Fatal("did not restart after backoff")
	}
	b.process.exit(9)
	eventually(t, func() bool {
		b.g.mu.Lock()
		defer b.g.mu.Unlock()
		return b.process.Restarts() == 2
	})
	b.clock.advance(1999)
	b.tick()
	if b.process.Running() {
		t.Fatal("second exit did not double backoff")
	}
	b.clock.advance(1)
	b.tick()
	if !b.process.Running() {
		t.Fatal("second restart did not occur")
	}
}

func TestManualFuseIPC(t *testing.T) {
	s := core.DefaultSettings()
	s.Subscription = &core.SubscriptionInfo{URL: "http://192.0.2.2/profile"}
	b := newFixture(t, s)
	b.boot()
	r := b.request(t, core.Request{Type: core.RequestTripFuse})
	if !r.OK || !r.Status.FuseLatched || r.Status.Fuse.Reason.Type != core.ReasonManual {
		t.Fatalf("trip: %+v", r)
	}
	r = b.request(t, core.Request{Type: core.RequestRestoreNetwork})
	if !r.OK || r.Status.FuseLatched || !r.Status.Fuse.Tripped {
		t.Fatalf("verified restore: %+v", r)
	}
	r = b.request(t, core.Request{Type: core.RequestRestoreNetwork, Force: true})
	if !r.OK || r.Status.Fuse.Tripped {
		t.Fatalf("forced restore: %+v", r)
	}
	for _, raw := range []string{"{", `{"token":"ignored","request":{"type":"unknown"}}`, `{"token":"ignored","request":{"type":"updateSettings","settings":null}}`} {
		if b.handle(t, []byte(raw)).OK {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestResumeStagesWhitelistBeforeRelease(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.boot()
	b.tick()
	ready := make(chan struct{})
	b.firewall.forceCalled = ready
	done := make(chan struct{})
	b.g.mu.Lock()
	go func() { b.g.Suspend(); close(done) }()
	select {
	case <-ready:
		b.g.mu.Unlock()
	case <-time.After(time.Second):
		b.g.mu.Unlock()
		t.Fatal("ForceLockdown waited for guardian mutex")
	}
	<-done
	if b.firewall.Current().Kind != wfpolicy.Lockdown {
		t.Fatal("suspend did not lock down")
	}
	b.g.Resume()
	calls := b.calls.list()
	i := slices.Index(calls, "release")
	if i < 1 || !strings.HasPrefix(calls[i-1], "apply:whitelist:") {
		t.Fatal(calls)
	}
	if r := b.request(t, core.Request{Type: core.RequestStatus}); r.Status.FuseHoldRemainingMs == nil || *r.Status.FuseHoldRemainingMs != 8000 {
		t.Fatalf("wake hold: %+v", r.Status)
	}
}

func TestPowerEventsWhileDisabledLeaveFirewallAlone(t *testing.T) {
	s := core.DefaultSettings()
	s.Enabled = false
	b := newFixture(t, s)
	b.boot()
	before := b.calls.list()
	b.g.Suspend()
	b.g.Resume()
	if after := b.calls.list(); !slices.Equal(before, after) {
		t.Fatal(after)
	}
}

func TestShutdownStopsLoopsAndCoreWithoutRestoringNetwork(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.g.Start(context.Background())
	eventually(t, func() bool { return slices.Contains(b.calls.list(), "verify") })
	b.g.Shutdown()
	if b.process.Running() || b.firewall.Current().Kind != wfpolicy.Lockdown {
		t.Fatal(b.calls.list())
	}
	calls := b.calls.list()
	ordered(t, calls, "apply:lockdown:false:true", "stop")
	if slices.Contains(calls, "restore-dns") || slices.Contains(calls, "restore-v6") {
		t.Fatal(calls)
	}
	if b.g.ctx.Err() == nil {
		t.Fatal("context not cancelled")
	}
	b.g.work.Wait()
	if after := b.calls.list(); !slices.Equal(calls, after) {
		t.Fatal(after)
	}
}

func TestUpdateSettingsSyncsReloadsSanitizesAndDisables(t *testing.T) {
	s := core.DefaultSettings()
	b := newFixture(t, s)
	b.boot()
	s.LockSystemDNS = false
	s.DisableSystemIPv6 = false
	s.ProbeIntervalSeconds = 1000
	s.CustomAIDomains = []string{"https://EXAMPLE.NET/path"}
	s.Subscription = &core.SubscriptionInfo{URL: "http://192.0.2.2/ignored"}
	r := b.request(t, core.Request{Type: core.RequestUpdateSettings, Settings: &s})
	if !r.OK || r.Settings.ProbeIntervalSeconds != 10 || !slices.Equal(r.Settings.CustomAIDomains, []string{"example.net"}) || r.Settings.Subscription != nil || r.Status.SystemDNSLocked || r.Status.IPv6DisabledInterfaces != 0 {
		t.Fatalf("update: %+v", r)
	}
	ordered(t, b.calls.list(), "restore-v6", "restore-dns", "reload:"+b.paths.CoreConfig)
	if !strings.Contains(b.process.yaml, "example.net") {
		t.Fatal("custom rule not written")
	}
	s.Enabled = false
	r = b.request(t, core.Request{Type: core.RequestUpdateSettings, Settings: &s})
	if !r.OK || r.Status.Phase != core.PhaseDisabled || r.Status.FirewallPolicy != "none" || b.process.Running() {
		t.Fatalf("disable: %+v", r)
	}
	ordered(t, b.calls.list(), "restore-dns", "stop", "apply:none:false:false")
}

func TestImportSubscriptionReloadAndRollback(t *testing.T) {
	s := core.DefaultSettings()
	b := newFixture(t, s)
	b.boot()
	var requestCount atomic.Int32
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "clash.meta mihomo/1.19 AIGuard-Windows" {
			t.Errorf("unexpected UA: %s", r.UserAgent())
		}
		w.Header().Set("profile-title", "Test profile")
		fmt.Fprintf(w, "proxies:\n  - {name: US-%d, type: ss, server: 192.0.2.1, port: 4444, cipher: aes-128-gcm, password: test}\n", requestCount.Add(1))
	}))
	defer sub.Close()
	r := b.request(t, core.Request{Type: core.RequestImportSubscription, URL: sub.URL})
	if !r.OK || r.Status.Subscription == nil || r.Status.Subscription.NodeCount != 1 {
		t.Fatalf("import: %+v", r)
	}
	old, err := os.ReadFile(b.paths.ProviderFile)
	if err != nil || !strings.Contains(string(old), "US-1") {
		t.Fatalf("provider: %s %v", old, err)
	}
	b.controller.providerCount.Store(0)
	r = b.request(t, core.Request{Type: core.RequestImportSubscription, URL: sub.URL})
	if r.OK {
		t.Fatal("zero-node provider accepted")
	}
	contents, err := os.ReadFile(b.paths.ProviderFile)
	if err != nil || string(contents) != string(old) {
		t.Fatalf("rollback: %s %v", contents, err)
	}
	ordered(t, b.calls.list(), "reload:"+b.paths.CoreConfig, "reload-provider", "reload-provider")
}

func TestEventsCapCursorAndClearPersistence(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.g.mu.Lock()
	for i := range 305 {
		b.g.log(core.EventInfo, fmt.Sprint(i))
	}
	b.g.persistEvents()
	b.g.mu.Unlock()
	r := b.request(t, core.Request{Type: core.RequestEvents, After: 999})
	if !r.OK || len(*r.Events) != 300 || (*r.Events)[0].ID != 6 || (*r.Events)[299].ID != 305 {
		t.Fatalf("events: %+v", r)
	}
	clear := b.request(t, core.Request{Type: core.RequestClearEvents})
	if !clear.OK || *clear.EventsGeneration == *r.EventsGeneration {
		t.Fatalf("clear: %+v", clear)
	}
	raw, err := os.ReadFile(b.paths.Events)
	if err != nil || string(raw) != "[]" {
		t.Fatalf("events on disk: %s %v", raw, err)
	}
	r = b.request(t, core.Request{Type: core.RequestEvents, After: 999})
	if !r.OK || len(*r.Events) != 0 || *r.EventsGeneration != *clear.EventsGeneration {
		t.Fatalf("events after clear: %+v", r)
	}
	b.g.mu.Lock()
	b.g.log(core.EventInfo, "new")
	b.g.mu.Unlock()
	r = b.request(t, core.Request{Type: core.RequestEvents, After: 305})
	if len(*r.Events) != 1 || (*r.Events)[0].ID != 306 {
		t.Fatalf("IDs went back: %+v", r)
	}
}

func proxySettings() core.GuardSettings {
	s := core.DefaultSettings()
	s.Subscription = &core.SubscriptionInfo{URL: "http://example.test/profile"}
	return s
}

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for test signal")
		var zero T
		return zero
	}
}

func occurrences(calls []string, name string) int {
	n := 0
	for _, call := range calls {
		if call == name {
			n++
		}
	}
	return n
}

func TestDetectSuspendResetsFetcherAndEpoch(t *testing.T) {
	s := core.DefaultSettings()
	s.Enabled = false
	b := newFixture(t, s)
	b.g.mu.Lock()
	defer b.g.mu.Unlock()
	b.g.lastIPv6Check = new(int64(0))
	b.g.detectSuspend(0)
	epoch := b.g.epoch
	b.clock.advance(30000)
	b.g.detectSuspend(b.clock.Mono())
	b.clock.mono.Add(10000)
	b.g.detectSuspend(b.clock.Mono())
	if b.g.epoch != epoch || b.g.lastIPv6Check == nil {
		t.Fatal("awake clock or boundary invalidated state")
	}
	b.clock.mono.Add(10001)
	b.g.detectSuspend(b.clock.Mono())
	if b.g.epoch != epoch+1 || b.g.lastIPv6Check != nil || occurrences(b.calls.list(), "reset-all") != 1 {
		t.Fatalf("epoch %d, IPv6 check %v, calls %v", b.g.epoch, b.g.lastIPv6Check, b.calls.list())
	}
}

func TestSleepDiscardsInflightHeartbeat(t *testing.T) {
	b := newFixture(t, proxySettings())
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }) })
	b.fetcher.beat = func(context.Context) *core.ExitTrace {
		close(entered)
		<-release
		return &core.ExitTrace{IP: "203.0.113.1", Country: "US"}
	}
	b.boot()
	b.tick()
	done := make(chan time.Duration, 1)
	go func() { done <- b.beat() }()
	await(t, entered)
	b.g.Suspend()
	b.g.Resume()
	unblock.Do(func() { close(release) })
	if delay := await(t, done); delay != 200*time.Millisecond {
		t.Fatalf("stale heartbeat retry: %v", delay)
	}
	r := b.request(t, core.Request{Type: core.RequestStatus})
	if r.Status.HeartbeatAlive || r.Status.Exit.Trace != nil || len(r.Status.Latency) != 0 || !r.Status.Fuse.Tripped {
		t.Fatalf("stale heartbeat updated status: %+v", r.Status)
	}
}

func TestDelayedGateWriteCannotConfirmWhitelist(t *testing.T) {
	b := newFixture(t, proxySettings())
	blocked, release := make(chan struct{}), make(chan struct{})
	var once, unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }) })
	b.controller.beforeSelect = func(group, target string) {
		if group == core.GroupGateAI && target == core.GroupProxy {
			once.Do(func() { close(blocked); <-release })
		}
	}
	b.boot()
	b.request(t, core.Request{Type: core.RequestRestoreNetwork, Force: true})
	await(t, blocked)
	r := b.request(t, core.Request{Type: core.RequestTripFuse})
	if !r.Status.Fuse.Tripped || b.firewall.Current().AllowTun {
		t.Fatalf("TUN reopened before delayed write settled: %+v", b.firewall.Current())
	}
	unblock.Do(func() { close(release) })
	eventually(t, func() bool { return b.firewall.Current().AllowTun })
	b.controller.mu.Lock()
	defer b.controller.mu.Unlock()
	if b.controller.groups[core.GroupGateAI] != "REJECT" || b.controller.groups[core.GroupGateMain] != "REJECT" {
		t.Fatalf("TUN reopened with gates %+v", b.controller.groups)
	}
}

func TestShutdownCancelsInFlightBootAndJoins(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	entered, canceled := make(chan struct{}), make(chan struct{})
	b.controller.versionHook = func(ctx context.Context) {
		close(entered)
		<-ctx.Done()
		close(canceled)
	}
	b.g.Start(context.Background())
	await(t, entered)
	finished := make(chan struct{})
	go func() { b.g.Shutdown(); close(finished) }()
	await(t, finished)
	await(t, canceled)
	if b.process.Running() || b.firewall.Current().Kind != wfpolicy.Lockdown || slices.Contains(b.calls.list(), "verify") {
		t.Fatal(b.calls.list())
	}
}

func TestDNSWorkDoesNotHoldGuardianLock(t *testing.T) {
	s := core.DefaultSettings()
	s.LockSystemDNS = false
	b := newFixture(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }) })
	b.system.dnsHook = func() { close(entered); <-release }
	b.boot()

	raw := func(lock bool) []byte {
		next := s
		next.LockSystemDNS = lock
		data, err := json.Marshal(core.IpcEnvelope{Token: "unused", Request: core.Request{Type: core.RequestUpdateSettings, Settings: &next}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	enable, disable := raw(true), raw(false)
	enabled, disabled := make(chan []byte, 1), make(chan []byte, 1)
	go func() { enabled <- b.g.Handle(context.Background(), enable) }()
	await(t, entered)
	go func() { disabled <- b.g.Handle(context.Background(), disable) }()
	eventually(t, func() bool {
		return !b.request(t, core.Request{Type: core.RequestGetSettings}).Settings.LockSystemDNS
	})
	unblock.Do(func() { close(release) })
	await(t, enabled)
	await(t, disabled)
	r := b.request(t, core.Request{Type: core.RequestStatus})
	if r.Status.SystemDNSLocked || b.system.dns.Load() {
		t.Fatal("stale DNS lock overwrote newer restore")
	}
	ordered(t, b.calls.list(), "lock-dns", "restore-dns")
}

func TestPrecautionaryTripsSkipAppsAndManualTripClosesOnce(t *testing.T) {
	s := core.DefaultSettings()
	s.ExtraAIProcesses = []string{"Extra"}
	b := newFixture(t, s)
	type scan struct {
		kinds AppKind
		extra []string
	}
	calls := make(chan scan, 3)
	b.system.closeHook = func(k AppKind, extra []string, wanted func() bool) []string {
		if !wanted() {
			return nil
		}
		calls <- scan{k, extra}
		return []string{"extra.exe"}
	}
	b.boot()
	b.tick()
	b.g.Suspend()
	b.g.Resume()
	b.g.work.Wait()
	select {
	case call := <-calls:
		t.Fatalf("precautionary trip closed apps: %+v", call)
	default:
	}
	b.request(t, core.Request{Type: core.RequestTripFuse})
	first := await(t, calls)
	if first.kinds != KindAI|KindBrowser || !slices.Equal(first.extra, []string{"extra.exe"}) {
		t.Fatalf("first scan: %+v", first)
	}
	b.clock.advance(3000)
	b.tick()
	if next := await(t, calls); next.kinds != KindAI {
		t.Fatalf("repeat scan: %+v", next)
	}
	b.request(t, core.Request{Type: core.RequestRestoreNetwork, Force: true})
	b.g.work.Wait()
	r := b.request(t, core.Request{Type: core.RequestEvents})
	if !slices.ContainsFunc(*r.Events, func(e core.GuardEvent) bool {
		return e.Level == core.EventWarning && e.Message == "熔断：已关闭 extra.exe"
	}) {
		t.Fatal("closed process missing from events")
	}
}

func TestUnsafeHeartbeatSelectsSafeNodeAndRefusesEarlyRecovery(t *testing.T) {
	b := newFixture(t, proxySettings())
	b.fetcher.beat = func(context.Context) *core.ExitTrace { return &core.ExitTrace{Country: "HK", IP: "203.0.113.1"} }
	b.fetcher.candidate = &core.ExitTrace{Country: "JP", IP: "203.0.113.2"}
	b.boot()
	b.tick()
	b.request(t, core.Request{Type: core.RequestRestoreNetwork, Force: true})
	b.g.work.Wait()
	b.beat()
	ordered(t, b.calls.list(), "heartbeat", "flush", "select:"+core.GroupProxy+":JP", "reset-probe")
	r := b.request(t, core.Request{Type: core.RequestStatus})
	if !r.Status.Fuse.Tripped || r.Status.Fuse.Reason.Type != core.ReasonUnsafeExit || r.Status.Exit.Trace.Country != "JP" {
		t.Fatalf("unsafe exit: %+v", r.Status)
	}
	b.fetcher.beat = func(context.Context) *core.ExitTrace { return b.fetcher.candidate }
	for range 4 {
		b.beat()
	}
	r = b.request(t, core.Request{Type: core.RequestStatus})
	if r.Status.Fuse.Tripped || !r.Status.HeartbeatAlive || r.Status.FirewallPolicy != "leakGuard" {
		t.Fatalf("verified recovery: %+v", r.Status)
	}
}

func TestHeartbeatFallbackAndAutoHealthCheckThrottle(t *testing.T) {
	b := newFixture(t, proxySettings())
	b.controller.groups[core.GroupProxy] = core.GroupAuto
	b.controller.groups[core.GroupAuto] = "US"
	b.fetcher.fallback = &core.ExitTrace{Country: "US", IP: "203.0.113.1"}
	b.boot()
	b.tick()
	b.beat()
	if r := b.request(t, core.Request{Type: core.RequestStatus}); !r.Status.HeartbeatAlive {
		t.Fatalf("fallback did not populate status: %+v", r.Status)
	}
	ordered(t, b.calls.list(), "heartbeat", "ipinfo")
	b.fetcher.fallback = nil
	for range 3 {
		b.beat()
		b.g.work.Wait()
	}
	if n := occurrences(b.calls.list(), "group-delay:"+core.GroupAuto); n != 1 {
		t.Fatalf("health check count %d", n)
	}
	b.clock.advance(20000)
	b.beat()
	b.g.work.Wait()
	if n := occurrences(b.calls.list(), "group-delay:"+core.GroupAuto); n != 2 {
		t.Fatalf("health check count %d", n)
	}
}

func TestCaptiveLoginUsesPrimaryAndExpires(t *testing.T) {
	b := newFixture(t, proxySettings())
	b.boot()
	r := b.request(t, core.Request{Type: core.RequestCaptiveLogin, Minutes: 20})
	if !r.OK || r.Status.EffectiveMode != core.ModeDirect || r.Status.CaptiveUntil == nil || *r.Status.CaptiveUntil-b.clock.Wall() != 600000 || r.Status.PrimaryInterface == nil || *r.Status.PrimaryInterface != "WiFi" {
		t.Fatalf("captive: %+v", r.Status)
	}
	if !strings.Contains(b.process.yaml, "dhcp://WiFi") {
		t.Fatal("missing captive interface in config")
	}
	b.clock.advance(600000)
	b.tick()
	r = b.request(t, core.Request{Type: core.RequestStatus})
	if r.Status.CaptiveUntil != nil || r.Status.EffectiveMode != core.ModeProxy || strings.Contains(b.process.yaml, "dhcp://WiFi") {
		t.Fatalf("captive did not expire: %+v", r.Status)
	}
	r = b.request(t, core.Request{Type: core.RequestCaptiveLogin, Minutes: 0})
	if r.Status.CaptiveUntil == nil || *r.Status.CaptiveUntil-b.clock.Wall() != 60000 {
		t.Fatal("captive minimum not applied")
	}
	r = b.request(t, core.Request{Type: core.RequestEndCaptiveLogin})
	if r.Status.CaptiveUntil != nil {
		t.Fatal("captive did not end by request")
	}
}

func TestConfigWriteFailureReturnsSavedSettingsAndRetries(t *testing.T) {
	s := core.DefaultSettings()
	b := newFixture(t, s)
	b.boot()
	s.CustomAIDomains = []string{"example.org"}
	b.process.writeErr = errors.New("test write failure")
	r := b.request(t, core.Request{Type: core.RequestUpdateSettings, Settings: &s})
	if r.OK || r.Error == nil || !strings.Contains(*r.Error, "test write failure") || r.Settings == nil || len(r.Settings.CustomAIDomains) != 1 {
		t.Fatalf("write failure: %+v", r)
	}
	saved, err := readJSON[core.GuardSettings](b.paths.Settings)
	if err != nil || !slices.Equal(saved.CustomAIDomains, s.CustomAIDomains) {
		t.Fatalf("saved settings: %+v %v", saved, err)
	}
	b.process.writeErr = nil
	r = b.request(t, core.Request{Type: core.RequestUpdateSettings, Settings: &s})
	if !r.OK || !strings.Contains(b.process.yaml, "example.org") {
		t.Fatalf("retry: %+v", r)
	}
	ordered(t, b.calls.list(), "reload:"+b.paths.CoreConfig)
}

func TestFirewallFailureAndVerifyCadence(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.firewall.applyErr = errors.New("test filter failure")
	b.firewall.issue = "test verification issue"
	b.boot()
	b.tick()
	b.clock.advance(999)
	b.tick()
	if n := occurrences(b.calls.list(), "verify"); n != 1 {
		t.Fatalf("before 1s: %d verifies", n)
	}
	b.clock.advance(1)
	b.tick()
	if n := occurrences(b.calls.list(), "verify"); n != 2 {
		t.Fatalf("at 1s: %d verifies", n)
	}
	r := b.request(t, core.Request{Type: core.RequestStatus})
	if r.Status.Phase != core.PhaseError || r.Status.LastError == nil {
		t.Fatalf("failure status: %+v", r.Status)
	}
	r = b.request(t, core.Request{Type: core.RequestEvents})
	for _, want := range []string{"防火墙规则加载失败：test filter failure，仅剩内核闸门一层防护", "test verification issue"} {
		n := 0
		for _, e := range *r.Events {
			if e.Message == want && e.Level == core.EventCritical {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("expected one %q event, got %d", want, n)
		}
	}
	b.firewall.mu.Lock()
	b.firewall.applyErr = nil
	b.firewall.issue = ""
	b.firewall.mu.Unlock()
	b.clock.advance(119000)
	b.tick()
	b.clock.advance(4999)
	b.tick()
	if n := occurrences(b.calls.list(), "verify"); n != 3 {
		t.Fatalf("before 5s: %d verifies", n)
	}
	b.clock.advance(1)
	b.tick()
	if n := occurrences(b.calls.list(), "verify"); n != 4 {
		t.Fatalf("at 5s: %d verifies", n)
	}
	r = b.request(t, core.Request{Type: core.RequestStatus})
	if r.Status.Phase != core.PhaseProtected {
		t.Fatalf("recovery status: %+v", r.Status)
	}
}

func TestNetworkChangeTripsBeforeDNSAndExcludesFakeIPs(t *testing.T) {
	b := newFixture(t, proxySettings())
	b.boot()
	b.tick()
	b.request(t, core.Request{Type: core.RequestRestoreNetwork, Force: true})
	before := len(b.calls.list())
	b.system.network.Add(1)
	b.tick()
	ordered(t, b.calls.list()[before:], "apply:whitelist:false:false", "reset-all", "lock-dns", "flush")
	r := b.request(t, core.Request{Type: core.RequestStatus})
	if r.Status.Fuse.Reason == nil || r.Status.Fuse.Reason.Type != core.ReasonNetworkChanged || !r.Status.TunUp {
		t.Fatalf("network change: %+v", r.Status)
	}
	p := b.firewall.Current()
	got := make([]string, 0, len(p.Allow))
	for _, ip := range p.Allow {
		got = append(got, ip.String())
	}
	if !slices.Equal(got, []string{"192.0.2.1", "203.0.113.2"}) {
		t.Fatalf("whitelist exceptions: %+v", p.Allow)
	}
}

func TestResumeHardPolicyKeepsLockdown(t *testing.T) {
	s := core.DefaultSettings()
	s.FuseAction = core.FuseCutAll
	b := newFixture(t, s)
	b.boot()
	b.tick()
	b.g.Suspend()
	b.g.Resume()
	calls := b.calls.list()
	i := slices.Index(calls, "release")
	if i < 1 || calls[i-1] != "apply:lockdown:false:false" || b.firewall.Current().Kind != wfpolicy.Lockdown {
		t.Fatal(calls)
	}
}

// 回归：关闭熔断时合盖唤醒曾经一直停在强制断网
func TestResumeWithoutFuseReleasesToLeakGuard(t *testing.T) {
	s := core.DefaultSettings()
	s.FuseEnabled = false
	b := newFixture(t, s)
	b.boot()
	b.tick()
	b.g.Suspend()
	b.g.Resume()
	if !slices.Contains(b.calls.list(), "release") || b.firewall.Current().Kind != wfpolicy.LeakGuard {
		t.Fatal(b.firewall.Current().Kind, b.calls.list())
	}
}

func TestMissedResumeIsRecoveredByTick(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.boot()
	b.tick()
	b.g.Suspend()
	b.clock.advance(5000)
	b.tick()
	if slices.Contains(b.calls.list(), "release") {
		t.Fatal("5 秒内不应自行解除强制断网")
	}
	b.clock.advance(11000)
	b.tick()
	if !slices.Contains(b.calls.list(), "release") || b.firewall.Current().Kind != wfpolicy.Whitelist {
		t.Fatal(b.firewall.Current().Kind, b.calls.list())
	}
}

func TestRuntimeSecretsAndPersistedEventsReload(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	secrets, err := readJSON[runtimeSecrets](b.paths.Runtime)
	if err != nil {
		t.Fatal("runtime secrets were not written")
	}
	for _, value := range []string{secrets.Secret, secrets.ListenerPassword} {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != 24 {
			t.Fatal("runtime secret must be 24 hex-encoded bytes")
		}
	}
	if secrets.Secret == secrets.ListenerPassword {
		t.Fatal("the two runtime secrets must be generated independently")
	}
	b.g.mu.Lock()
	b.g.log(core.EventCritical, "persist immediately")
	b.g.mu.Unlock()
	stored, err := readJSON[[]core.GuardEvent](b.paths.Events)
	if err != nil || len(stored) != 1 {
		t.Fatal("critical event was not persisted")
	}
	first := b.request(t, core.Request{Type: core.RequestControllerInfo})
	if first.Controller == nil || first.Controller.BaseURL != b.g.options.ControllerURL || first.Controller.Secret != secrets.Secret {
		t.Fatal("controller info did not use runtime settings")
	}
	b.g.Shutdown()
	reopened, err := New(b.g.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Shutdown)
	if reopened.runtime.Secret != secrets.Secret || reopened.runtime.ListenerPassword != secrets.ListenerPassword {
		t.Fatal("runtime secrets changed on reload")
	}
	if len(reopened.events) < 1 || reopened.events[0] != stored[0] || reopened.nextEventID <= stored[0].ID {
		t.Fatal("persisted event or cursor was lost")
	}
}

func TestDisabledShutdownOnlyStopsCore(t *testing.T) {
	s := core.DefaultSettings()
	s.Enabled = false
	b := newFixture(t, s)
	b.boot()
	before := len(b.calls.list())
	b.g.Shutdown()
	if got := b.calls.list()[before:]; !slices.Equal(got, []string{"stop", "reset-all"}) {
		t.Fatalf("disabled shutdown touched platform protection: %v", got)
	}
}

func TestTUNRouteLossRestartsAfterGrace(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.boot()
	b.tick()
	b.system.route.Store(1)
	b.clock.advance(20001)
	b.tick()
	r := b.request(t, core.Request{Type: core.RequestStatus})
	if r.Status.TunUp || r.Status.Fuse.Reason == nil || r.Status.Fuse.Reason.Type != core.ReasonTunLost {
		t.Fatalf("route loss did not trip: %+v", r.Status)
	}
	b.clock.advance(7999)
	b.tick()
	if b.process.Restarts() != 0 {
		t.Fatal("restarted before route loss persisted for 8s")
	}
	b.clock.advance(1)
	b.tick()
	if b.process.Restarts() != 1 {
		t.Fatal("TUN recovery did not restart the core")
	}
	ordered(t, b.calls.list(), "start", "stop", "start")
}

func TestIPv6LeakTripsAndIsRecheckedSooner(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.boot()
	b.tick()
	b.system.leak.Store(true)
	b.clock.advance(29999)
	b.tick()
	if got := occurrences(b.calls.list(), "probe-v6"); got != 1 {
		t.Fatalf("regular probe count: %d", got)
	}
	b.clock.advance(1)
	b.tick()
	r := b.request(t, core.Request{Type: core.RequestStatus})
	if r.Status.IPv6Blocked == nil || *r.Status.IPv6Blocked || r.Status.Fuse.Reason == nil || r.Status.Fuse.Reason.Type != core.ReasonIPv6Leak {
		t.Fatalf("IPv6 failure did not trip: %+v", r.Status)
	}
	b.system.leak.Store(false)
	b.clock.advance(5000)
	b.tick()
	r = b.request(t, core.Request{Type: core.RequestStatus})
	if r.Status.Fuse.Tripped || r.Status.IPv6Blocked == nil || !*r.Status.IPv6Blocked {
		t.Fatalf("IPv6 protection did not recover: %+v", r.Status)
	}
}

func TestPeriodicDNSCheckRepairsExternalChange(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.boot()
	b.tick()
	b.system.dns.Store(false)
	b.clock.advance(30000)
	b.tick()
	if b.system.dns.Load() {
		t.Fatal("DNS rechecked before 60 seconds")
	}
	b.clock.advance(30000)
	b.tick()
	if !b.system.dns.Load() {
		t.Fatal("DNS not relocked after 60 seconds")
	}
	r := b.request(t, core.Request{Type: core.RequestEvents})
	if !slices.ContainsFunc(*r.Events, func(e core.GuardEvent) bool {
		return e.Level == core.EventWarning && e.Message == "网卡 DNS 被改动，已重新锁定（否则 DNS 会绕过内核）"
	}) {
		t.Fatal("DNS repair not logged")
	}
}

func TestReloadFailureFallsBackToRestart(t *testing.T) {
	s := core.DefaultSettings()
	b := newFixture(t, s)
	b.boot()
	b.controller.reloadStatus.Store(http.StatusInternalServerError)
	s.CustomProxyDomains = []string{"example.org"}
	r := b.request(t, core.Request{Type: core.RequestUpdateSettings, Settings: &s})
	if !r.OK || !r.Status.CoreRunning {
		t.Fatalf("reload fallback: %+v", r)
	}
	ordered(t, b.calls.list(), "start", "reload:"+b.paths.CoreConfig, "stop", "start", "flush")
}

func TestShutdownFinishesConcurrentDisable(t *testing.T) {
	s := core.DefaultSettings()
	b := newFixture(t, s)
	restoring, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }) })
	b.system.restoreDNSHook = func() {
		close(restoring)
		<-release
	}
	b.boot()
	s.Enabled = false
	raw, err := json.Marshal(core.IpcEnvelope{Token: "unused", Request: core.Request{Type: core.RequestUpdateSettings, Settings: &s}})
	if err != nil {
		t.Fatal(err)
	}
	update := make(chan []byte, 1)
	go func() { update <- b.g.Handle(context.Background(), raw) }()
	await(t, restoring)
	stopped := make(chan struct{})
	go func() {
		b.g.Shutdown()
		close(stopped)
	}()
	await(t, b.g.ctx.Done())
	unblock.Do(func() { close(release) })
	await(t, stopped)
	await(t, update)
	if b.firewall.Current().Kind != wfpolicy.None || b.system.dns.Load() || b.process.Running() {
		t.Fatal(b.calls.list())
	}
}

func TestSmallCNTableIsReportedAtBoot(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.boot()
	r := b.request(t, core.Request{Type: core.RequestEvents})
	for _, e := range *r.Events {
		if e.Level == core.EventCritical && strings.Contains(e.Message, "大陆 IP 表只有 1 条") {
			return
		}
	}
	t.Fatal("缺失的大陆 IP 表没有报严重事件")
}

// 回归：漏收睡眠通知时，唤醒后曾经只重置探测而不熔断
func TestDetectedSleepTripsAsNetworkChange(t *testing.T) {
	b := newFixture(t, core.DefaultSettings())
	b.boot()
	b.g.mu.Lock()
	b.g.engine = core.NewFuseEngine(b.g.fuseConfig(), b.clock.Mono(), false)
	b.g.applyProtection()
	b.g.detectSuspend(b.clock.Mono())
	b.clock.mono.Add(60000)
	b.g.detectSuspend(b.clock.Mono())
	snap := b.g.engine.Snapshot()
	b.g.mu.Unlock()
	if !snap.Tripped || snap.Reason == nil || snap.Reason.Type != core.ReasonNetworkChanged {
		t.Fatalf("唤醒后应按换网熔断：%+v", snap)
	}
	if b.firewall.Current().Kind != wfpolicy.Whitelist {
		t.Fatalf("唤醒后防火墙应收紧为白名单：%v", b.firewall.Current().Kind)
	}
}

const (
	chromeExe  = `C:\Program Files\Google\Chrome\Application\chrome.exe`
	claudeExe  = `C:\Users\u\AppData\Local\AnthropicClaude\app-1.0\claude.exe`
	firefoxExe = `C:\Program Files\Mozilla Firefox\firefox.exe`
)

func gameFixture(t *testing.T, mutate func(*core.GuardSettings)) *fixture {
	t.Helper()
	s := core.DefaultSettings()
	s.Subscription = &core.SubscriptionInfo{URL: "http://192.0.2.2/profile"}
	if mutate != nil {
		mutate(&s)
	}
	b := newFixture(t, s)
	b.paths.AppHistory = filepath.Join(b.paths.DataDir, "app-history.json")
	b.g.options.Paths.AppHistory = b.paths.AppHistory
	b.boot()
	b.tick()
	return b
}

func (b *fixture) yaml() string {
	b.process.mu.Lock()
	defer b.process.mu.Unlock()
	return b.process.yaml
}

func TestGameModeIsManualByDefault(t *testing.T) {
	b := gameFixture(t, nil)
	b.system.setScan(AppScan{Games: []string{"原神"}, Accelerators: []string{"UU 加速器"}})
	b.clock.advance(10000)
	b.tick()
	b.system.scanMu.Lock()
	scans := b.system.scans
	b.system.scanMu.Unlock()
	if b.firewall.Current().Kind == wfpolicy.Game || scans != 0 {
		t.Fatal("默认不自动检测，也不应扫描进程", b.firewall.Current().Kind, scans)
	}
}

func TestManualGameModeRejectsAllAIAndClosesAIApps(t *testing.T) {
	b := gameFixture(t, nil)
	b.system.setScan(AppScan{AI: []string{claudeExe}, AIRunning: true, Browsers: []string{chromeExe}, Known: []string{firefoxExe}})
	s := b.g.settings
	s.GameMode = true
	b.request(t, core.Request{Type: core.RequestUpdateSettings, Settings: &s})
	b.clock.advance(1000)
	b.tick()
	p := b.firewall.Current()
	if p.Kind != wfpolicy.Game || p.TunLUID == 0 || !slices.Contains(p.Block, claudeExe) || !slices.Contains(p.TunOnly, chromeExe) || !slices.Contains(p.TunOnly, firefoxExe) {
		t.Fatalf("应进入游戏模式：AI 程序禁止联网、浏览器只能经 TUN：%+v", p)
	}
	yaml := b.yaml()
	for _, want := range []string{"tun:\n  enable: true\n", "strict-route: false", "enhanced-mode: redir-host", "DOMAIN-SUFFIX,claude.ai,REJECT", "MATCH,DIRECT"} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("游戏模式配置缺少 %q", want)
		}
	}
	// 进入时立即强制关闭 AI 程序（不看「熔断时关闭」开关）
	eventually(t, func() bool { return b.system.closes() >= 1 })
	st := b.request(t, core.Request{Type: core.RequestStatus}).Status
	if !st.GameMode || st.GameReason == nil || *st.GameReason != core.GameReasonManual {
		t.Fatalf("状态没反映游戏模式：%+v", st)
	}
	if !b.system.dns.Load() {
		t.Fatal("游戏模式 TUN 照开，DNS 必须保持锁定")
	}
}

func TestGameModeKeepsClosingAIAppsThatReappear(t *testing.T) {
	b := gameFixture(t, func(s *core.GuardSettings) { s.GameMode = true; s.CloseAppsOnFuse = false })
	b.clock.advance(1000)
	b.tick()
	eventually(t, func() bool { return b.system.closes() >= 1 })
	before := b.system.closes()
	other := `C:\Users\u\AppData\Local\Programs\cursor\Cursor.exe`
	b.system.setScan(AppScan{AI: []string{other}, AIRunning: true})
	b.clock.advance(2000)
	b.tick()
	if !slices.Contains(b.firewall.Current().Block, other) {
		t.Fatal("新出现的 AI 程序必须禁止联网", b.firewall.Current().Block)
	}
	eventually(t, func() bool { return b.system.closes() > before })
	if h, err := readJSON[[]string](b.paths.AppHistory); err != nil || !slices.Contains(h, other) {
		t.Fatal("AI 程序记录没有保存", h, err)
	}
	// WebView2 宿主的 AI 应用不拉黑运行库路径，但照样关闭
	n := b.system.closes()
	b.system.setScan(AppScan{AIRunning: true})
	b.clock.advance(2000)
	b.tick()
	eventually(t, func() bool { return b.system.closes() > n })
}

func TestAutoDetectedGameModeLingersThenRestores(t *testing.T) {
	b := gameFixture(t, func(s *core.GuardSettings) { s.GameAutoDetect = true })
	b.system.setScan(AppScan{Games: []string{"cs2"}})
	b.clock.advance(6000)
	b.tick()
	if b.firewall.Current().Kind != wfpolicy.Game {
		t.Fatal("开启自动检测后检测到游戏应进入游戏模式")
	}
	// 加速器抢走默认路由（TUN 不再是默认路由）也不熔断、不重启内核
	b.system.route.Store(1)
	b.system.setScan(AppScan{})
	for range 30 {
		b.clock.advance(1000)
		b.tick()
	}
	if snap := b.g.engine.Snapshot(); snap.Tripped && snap.Reason != nil && snap.Reason.Type == core.ReasonTunLost {
		t.Fatal("游戏模式下不应因 TUN 不是默认路由而熔断")
	}
	if slices.Contains(b.calls.list(), "stop") {
		t.Fatal("游戏模式下不应重启内核", b.calls.list())
	}
	b.system.route.Store(2)
	b.clock.advance(40000)
	b.tick()
	if k := b.firewall.Current().Kind; k == wfpolicy.Game || k == wfpolicy.None {
		t.Fatalf("游戏退出一分钟后应恢复防泄漏，得到 %s", k)
	}
	if yaml := b.yaml(); !strings.Contains(yaml, "enhanced-mode: fake-ip") || !strings.Contains(yaml, "strict-route: true") {
		t.Fatal("退出游戏模式必须恢复正常配置")
	}
}

func TestManualTripOverridesGameMode(t *testing.T) {
	b := gameFixture(t, func(s *core.GuardSettings) { s.GameMode = true })
	b.clock.advance(1000)
	b.tick()
	b.request(t, core.Request{Type: core.RequestTripFuse})
	if k := b.firewall.Current().Kind; k == wfpolicy.Game {
		t.Fatal("手动熔断必须真的断网，不能停在游戏模式")
	}
}

func TestDisablingGuardLeavesGameMode(t *testing.T) {
	b := gameFixture(t, func(s *core.GuardSettings) { s.GameMode = true })
	b.clock.advance(1000)
	b.tick()
	s := b.g.settings
	s.Enabled = false
	b.request(t, core.Request{Type: core.RequestUpdateSettings, Settings: &s})
	st := b.request(t, core.Request{Type: core.RequestStatus}).Status
	if st.GameMode || b.firewall.Current().Kind != wfpolicy.None {
		t.Fatal("关闭守护后不应再显示游戏模式", st.GameMode, b.firewall.Current().Kind)
	}
}

func TestGameModeAbortsWhenFirewallCannotSwitch(t *testing.T) {
	b := gameFixture(t, nil)
	b.firewall.mu.Lock()
	b.firewall.applyErr = errors.New("BFE 不可用")
	b.firewall.mu.Unlock()
	s := b.g.settings
	s.GameMode = true
	b.request(t, core.Request{Type: core.RequestUpdateSettings, Settings: &s})
	b.clock.advance(1000)
	b.tick()
	if b.g.gameActive || strings.Contains(b.yaml(), "redir-host") {
		t.Fatal("防火墙没换成功时不能宣称进入游戏模式")
	}
}

func TestManualLatchBeatsGameModeEvenIfReasonChanges(t *testing.T) {
	b := gameFixture(t, func(s *core.GuardSettings) { s.GameMode = true })
	b.clock.advance(1000)
	b.tick()
	b.request(t, core.Request{Type: core.RequestTripFuse})
	b.g.mu.Lock()
	b.g.engine.Handle(core.Geo{Country: new("CN")}, b.g.mono())
	b.g.applyProtection()
	latched := b.g.engine.IsLatched()
	b.g.mu.Unlock()
	if !latched {
		t.Fatal("手动熔断应锁定")
	}
	if k := b.firewall.Current().Kind; k == wfpolicy.Game {
		t.Fatal("手动锁定期间即使熔断原因变了也不能回到游戏模式策略")
	}
}
