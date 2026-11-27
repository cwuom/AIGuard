package guard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aiguard/internal/core"
	"aiguard/internal/wfpolicy"
	"aiguard/internal/winsys"
)

type Options struct {
	Version  string
	Paths    Paths
	Firewall Firewall
	Core     Core
	System   System
	Clock    Clock
	// Log receives one line without a trailing newline
	Log func(line string)
	// WFContext provides app paths and ports for the firewall
	WFContext wfpolicy.Context
	// ControllerURL overrides the local mihomo controller endpoint
	ControllerURL string
}

// Guardian owns the daemon state. Its internal methods run with mu held unless noted
type Guardian struct {
	mu          sync.Mutex
	options     Options
	ctx         context.Context
	cancel      context.CancelFunc
	work        sync.WaitGroup
	done        chan struct{}
	started     bool
	bootReady   bool
	stopping    bool
	stopParent  func() bool
	suspended   bool
	suspendedAt int64
	enabled     atomic.Bool
	trippedFlag atomic.Bool

	settings core.GuardSettings
	runtime  core.CoreRuntime
	api      *core.MihomoApi
	fetcher  probeFetcher
	engine   *core.FuseEngine

	// these mutexes serialize side effects that must run with mu released
	gateIO, networkIO, configIO, appIO, subscriptionIO sync.Mutex

	events           []core.GuardEvent
	nextEventID      int
	eventsGeneration string
	eventsDirty      bool

	latency                        []core.LatencySample
	exitStatus                     core.ExitStatus
	heartbeatAlive                 bool
	coreVersion                    string
	apiUp, tunUp                   bool
	tunInterface, primaryInterface string
	tunLUID                        uint64
	lastFingerprint                *string
	conflicts                      []string
	lastError                      *string
	nodeCount                      *int

	captiveUntil                  *int64
	apiFailures                   int
	wantCore                      bool
	nextRestartAt                 *int64
	restartBackoffMs              int64
	coreStartedAt                 *int64
	coreRun                       uint64
	appliedGates                  map[string]string
	switchingNode                 bool
	lastTripped                   bool
	appsClosedThisTrip            bool
	armedOnce                     bool
	lastCoreTransition            *int64
	softGatesConfirmed            bool
	gateGeneration                uint64
	coreTransitions               int
	configApplyPending            bool
	firewallFailing               bool
	lastAIScan                    *int64
	tunLostSince, lastAutoRestart *int64
	autoRestartCount              int
	restarting                    bool
	nodeDownLogged                bool

	allowIPs         []netip.Addr
	lastAllowRefresh *int64
	lastResolvedNode string
	lastForcedCheck  *int64
	epoch            uint64
	hookWarningShown bool
	ipv6Blocked      *bool

	lastIPv6Check         *int64
	lastSlowWork          *int64
	lastSubscriptionCheck *int64
	lastFirewallVerify    *int64
	lastDNSCheck          *int64
	bootedAt              int64
	lastTickMono          *int64
	lastTickUnbiased      int64

	// 游戏模式：gameActive 是当前是否生效，blockApps 是禁止联网的 AI 程序，tunOnlyApps 是只能经 TUN 的浏览器
	gameActive   bool
	gameFlag     atomic.Bool
	tunOnlyApps  []string
	gameReason   string
	gameDetected string
	gameSeenAt   *int64
	gameExitAt   *int64
	lastAppScan  *int64
	blockApps    []string
	appHistory   []string
}

type runtimeSecrets struct {
	Secret           string `json:"secret"`
	ListenerPassword string `json:"listenerPassword"`
}

// New reads the daemon state and prepares startup protection
func New(o Options) (*Guardian, error) {
	if o.Firewall == nil || o.Core == nil || o.System == nil || o.Clock == nil {
		return nil, errors.New("缺少守护平台接口")
	}
	rt := core.DefaultCoreRuntime()
	if o.ControllerURL == "" {
		o.ControllerURL = fmt.Sprintf("http://127.0.0.1:%d", rt.ControllerPort)
	}

	settings := core.DefaultSettings()
	if stored, err := readJSON[core.GuardSettings](o.Paths.Settings); err == nil {
		settings = stored
	}
	settings = settings.Sanitized()

	secrets, err := readJSON[runtimeSecrets](o.Paths.Runtime)
	if err != nil || secrets.Secret == "" || secrets.ListenerPassword == "" {
		secrets = runtimeSecrets{Secret: randomSecret(), ListenerPassword: randomSecret()}
		if err := writeJSON(o.Paths.Runtime, secrets); err != nil {
			return nil, fmt.Errorf("运行密钥保存失败：%w", err)
		}
	}
	rt.Secret, rt.ListenerPassword = secrets.Secret, secrets.ListenerPassword
	rt.HasSubscription = settings.Subscription != nil && regularFile(o.Paths.ProviderFile)

	o.WFContext.BootstrapDNS = nil
	for _, ip := range core.BootstrapDNS {
		o.WFContext.BootstrapDNS = append(o.WFContext.BootstrapDNS, netip.MustParseAddr(ip))
	}
	cn, _ := os.ReadFile(o.Paths.CNTable)
	o.WFContext.CNRanges = wfpolicy.ParseCNTable(string(cn))
	o.WFContext.AIRanges = aiRanges(settings)

	events, err := readJSON[[]core.GuardEvent](o.Paths.Events)
	if err != nil {
		events = nil
	}
	events = events[max(0, len(events)-300):]
	nextID := 1
	for _, event := range events {
		nextID = max(nextID, event.ID+1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	g := &Guardian{
		options: o, ctx: ctx, cancel: cancel, done: make(chan struct{}),
		settings: settings, runtime: rt, api: core.NewMihomoApi(o.ControllerURL, rt.Secret),
		fetcher:      core.NewProxiedFetcher(rt.ListenerUser, rt.ListenerPassword),
		appliedGates: make(map[string]string), restartBackoffMs: 1000,
		events: events, nextEventID: nextID, eventsGeneration: eventGeneration(),
	}
	g.engine = core.NewFuseEngine(g.fuseConfig(), g.mono(), settings.Enabled)
	g.enabled.Store(settings.Enabled)
	if o.Paths.AppHistory != "" {
		if h, err := readJSON[[]string](o.Paths.AppHistory); err == nil {
			g.appHistory = h[max(0, len(h)-appHistoryLimit):]
		}
	}
	return g, nil
}

// Start schedules boot and the two daemon loops
func (g *Guardian) Start(ctx context.Context) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started || g.stopping {
		return
	}
	g.started = true
	g.stopParent = context.AfterFunc(ctx, g.cancel)
	if ctx.Err() != nil {
		g.cancel()
	}
	g.launch(func(ctx context.Context) {
		g.boot(ctx)
		if g.active(ctx) {
			g.work.Go(func() {
				g.loop(ctx, func(ctx context.Context) time.Duration {
					g.tick(ctx)
					return time.Second
				})
			})
			g.work.Go(func() { g.loop(ctx, g.heartbeat) })
		}
	})
}

func (g *Guardian) loop(ctx context.Context, run func(context.Context) time.Duration) {
	for ctx.Err() == nil {
		g.mu.Lock()
		if !g.active(ctx) {
			g.mu.Unlock()
			return
		}
		delay := run(ctx)
		g.mu.Unlock()
		if !wait(ctx, delay) {
			return
		}
	}
}

func (g *Guardian) launch(run func(context.Context)) {
	if !g.active(g.ctx) {
		return
	}
	g.work.Go(func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.active(g.ctx) {
			run(g.ctx)
		}
	})
}

func (g *Guardian) boot(ctx context.Context) {
	g.bootedAt = g.mono()
	g.options.Firewall.SetContext(g.options.WFContext)
	g.applyFirewall(g.desiredPolicy(), true)
	// 与 Android 一致：大陆段少于 1000 条说明规则文件缺失或损坏，熔断时会连大陆网站也打不开
	if n := len(g.options.WFContext.CNRanges); n < 1000 {
		g.log(core.EventCritical, fmt.Sprintf("大陆 IP 表只有 %d 条（缺失或损坏），熔断时防火墙只会放行局域网；请重新安装", n))
	}
	version := outside(g, func() string {
		g.options.Core.KillStale()
		return g.options.Core.Version()
	})
	if !g.active(ctx) {
		return
	}
	g.coreVersion = version
	if version == "" {
		version = "版本未知"
	}
	g.log(core.EventInfo, fmt.Sprintf("守护进程已启动（v%s，mihomo %s）", g.options.Version, version))
	g.saveSettings()
	g.applyProtection()
	g.syncSystemNetwork(false)
	if !g.active(ctx) {
		return
	}
	if ifaces, route, ok := g.readInterfaces(ctx); ok {
		g.lastFingerprint = new(winsys.Fingerprint(ifaces))
		g.primaryInterface = winsys.Primary(ifaces, route)
		g.updateTun(ifaces)
	}
	g.bootReady = true
	if g.settings.Enabled && !g.suspended && g.active(ctx) {
		g.startCore(ctx)
	}
}

// Suspend installs the forced policy before waiting for the guardian lock
func (g *Guardian) Suspend() {
	if !g.enabled.Load() {
		return
	}
	err := g.options.Firewall.ForceLockdown()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopping || !g.settings.Enabled {
		// a concurrent disable or shutdown may have applied its final policy before ForceLockdown
		p := wfpolicy.Policy{Kind: wfpolicy.None}
		if g.settings.Enabled {
			p.Kind = wfpolicy.Lockdown
		}
		if g.applyFirewall(p, true) == nil {
			g.noteFirewallResult(g.options.Firewall.ReleaseForcedLockdown())
		}
		return
	}
	g.suspended = true
	g.suspendedAt = g.mono()
	g.epoch++
	if err != nil {
		g.noteFirewallResult(err)
	} else {
		g.log(core.EventInfo, "系统即将睡眠：已全部断网")
	}
}

// Resume stages the new policy while the firewall is still forced to lock down
func (g *Guardian) Resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.resumeLocked()
}

// resumeLocked 先让熔断引擎进入换网保护并把新策略暂存进防火墙，再解除强制断网。
// 用户关闭了熔断时引擎不会进入保护，这时回到平时的防泄漏策略：不能因为合盖一次就永久断网
func (g *Guardian) resumeLocked() {
	if !g.suspended || !g.active(g.ctx) {
		return
	}
	g.engine.Handle(core.NetworkChanged{}, g.mono())
	g.epoch++
	g.fetcher.ResetAll(g.ctx)
	g.lastIPv6Check = nil
	g.suspended = false
	if g.applyProtection() != nil {
		g.suspended = true
		return
	}
	g.noteFirewallResult(g.options.Firewall.ReleaseForcedLockdown())
	g.log(core.EventInfo, "已唤醒：重新验证线路")
	g.work.Add(1)
	defer g.work.Done()
	g.flushConnections(g.ctx)
	if g.bootReady && g.settings.Enabled && !g.wantCore {
		g.startCore(g.ctx)
	}
}

// Shutdown cancels and joins daemon work before persisting the final state
func (g *Guardian) Shutdown() {
	g.mu.Lock()
	if g.stopping {
		g.mu.Unlock()
		<-g.done
		return
	}
	g.stopping = true
	g.enabled.Store(false)
	g.trippedFlag.Store(false)
	g.cancel()
	if g.stopParent != nil {
		g.stopParent()
	}
	if g.settings.Enabled {
		err := g.applyFirewall(wfpolicy.Policy{Kind: wfpolicy.Lockdown}, true)
		if err == nil && g.suspended {
			err = g.options.Firewall.ReleaseForcedLockdown()
			g.noteFirewallResult(err)
		}
		if err == nil {
			g.log(core.EventWarning, "防护服务停止：已全部断网，服务重新启动后自动恢复")
		}
	}
	g.wantCore = false
	g.stopCore()
	g.mu.Unlock()
	g.work.Wait()

	g.mu.Lock()
	defer g.mu.Unlock()
	g.fetcher.ResetAll(g.ctx)
	g.persistEvents()
	g.saveSettings()
	close(g.done)
}

func (g *Guardian) mono() int64 { return g.options.Clock.Mono() }
func (g *Guardian) wall() int64 { return g.options.Clock.Wall() }

func (g *Guardian) active(ctx context.Context) bool {
	return !g.stopping && g.ctx.Err() == nil && ctx.Err() == nil
}

func (g *Guardian) current(ctx context.Context, epoch uint64) bool {
	return g.active(ctx) && epoch == g.epoch
}

func (g *Guardian) effectiveMode() core.ProxyMode {
	if g.captiveUntil != nil {
		return core.ModeDirect
	}
	return core.EffectiveMode(g.settings, g.runtime)
}

func (g *Guardian) fuseConfig() core.FuseConfig {
	return core.NewFuseConfig(g.settings, g.effectiveMode())
}

func (g *Guardian) flushConnections(ctx context.Context) bool {
	if !g.active(ctx) {
		return false
	}
	return outside(g, func() bool { return g.api.FlushConnections(ctx) })
}

func outside[T any](g *Guardian, call func() T) T {
	g.mu.Unlock()
	defer g.mu.Lock()
	return call()
}

func outside2[A, B any](g *Guardian, call func() (A, B)) (A, B) {
	g.mu.Unlock()
	defer g.mu.Lock()
	return call()
}

func wait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func elapsed(now int64, last *int64, interval int64) bool {
	return last == nil || now-*last >= interval
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func readJSON[T any](path string) (T, error) {
	var out T
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &out)
	}
	return out, err
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeAtomic(path, data)
}

func writeAtomic(path string, data []byte) error {
	if path == "" {
		return errors.New("缺少文件路径")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func randomSecret() string {
	var data [24]byte
	rand.Read(data[:])
	return hex.EncodeToString(data[:])
}

func eventGeneration() string {
	var id [16]byte
	rand.Read(id[:])
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func present(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func (g *Guardian) writeLog(line string) {
	if g.options.Log != nil {
		g.options.Log(strings.NewReplacer("\r", " ", "\n", " ").Replace(line))
	}
}

func (g *Guardian) log(level core.EventLevel, message string) {
	g.writeLog("[" + string(level) + "] " + message)
	g.events = append(g.events, core.GuardEvent{ID: g.nextEventID, At: g.wall(), Level: level, Message: message})
	g.nextEventID++
	if len(g.events) > 300 {
		g.events = g.events[len(g.events)-300:]
	}
	g.eventsDirty = true
	if level == core.EventCritical {
		g.persistEvents()
	}
}

func (g *Guardian) persistEvents() {
	if g.eventsDirty && writeJSON(g.options.Paths.Events, g.events) == nil {
		g.eventsDirty = false
	}
}

func (g *Guardian) saveSettings() {
	if err := writeJSON(g.options.Paths.Settings, g.settings); err != nil {
		g.writeLog("[error] 设置保存失败：" + err.Error())
	}
}
