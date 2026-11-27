//go:build windows

// Package wfp 把 wfpolicy 生成的规则写进 Windows Filtering Platform。
//
// 做法参考 wireguard-windows（tunnel/firewall）与 mihomo 所用 sing-tun 的 strict-route：
// 自己的 provider + 最高权重子层，放行写高权重、兜底拦截写最低权重。不同之处是这里的对象全部持久化，
// 服务崩溃、被杀或重启电脑后规则依然有效（fail-closed，等同 macOS pf 锚点不随守护进程退出而撤销），
// 只有显式 Teardown（关闭守护、卸载、firewall-reset）才会删除。每次切换策略都在一个 WFP 事务里先删后加。
package wfp

import (
	"errors"
	"fmt"
	"sync"

	"aiguard/internal/wfpolicy"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

var (
	// 固定 GUID：升级、重装后仍能找到并替换旧规则
	providerID = wf.ProviderID(windows.GUID{Data1: 0x6a1e5d2b, Data2: 0x3c4f, Data3: 0x4b9a, Data4: [8]byte{0xa1, 0x7e, 0x41, 0x49, 0x47, 0x55, 0x41, 0x52}})
	sublayerID = wf.SublayerID(windows.GUID{Data1: 0x6a1e5d2b, Data2: 0x3c4f, Data3: 0x4b9a, Data4: [8]byte{0xa1, 0x7e, 0x41, 0x49, 0x47, 0x55, 0x41, 0x53}})
	layers     = []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6}
)

// Firewall 是 WFP 防火墙。方法可并发调用（睡眠事件来自服务控制线程）
type Firewall struct {
	mu      sync.Mutex
	session *wf.Session
	ctx     wfpolicy.Context
	appIDs  map[string]string
	current wfpolicy.Policy
	applied int
	// forced 为 true 时处于睡眠前的强制断网，Apply 只记录期望策略，等 Release 后再写入
	forced  bool
	pending wfpolicy.Policy
	lastErr error
}

// New 连接 WFP。ctx 里的程序路径会立即换算成 App ID，路径不存在时报错（宁可起不来也不能放行错的程序）
func New(ctx wfpolicy.Context) (*Firewall, error) {
	f := &Firewall{ctx: ctx, appIDs: map[string]string{}, current: wfpolicy.Policy{Kind: wfpolicy.None}}
	for _, p := range []string{ctx.CoreExe, ctx.ServiceExe, ctx.UIExe} {
		if p == "" {
			continue
		}
		id, err := wf.AppID(p)
		if err != nil {
			return nil, fmt.Errorf("无法取得 %s 的 App ID：%w", p, err)
		}
		f.appIDs[p] = id
	}
	if err := f.open(); err != nil {
		return nil, err
	}
	return f, nil
}

// open 建立新会话；新会话建好之前保留旧的，失败时不会留下空会话
func (f *Firewall) open() error {
	s, err := wf.New(&wf.Options{Name: "AIGuard", Description: "AIGuard 防泄漏防火墙", Dynamic: false})
	if err != nil {
		return fmt.Errorf("连接 WFP 失败：%w", err)
	}
	if f.session != nil {
		f.session.Close()
	}
	f.session = s
	return nil
}

func (f *Firewall) ensureSession() error {
	if f.session != nil {
		return nil
	}
	return f.open()
}

// SetContext 更新大陆 IP 段等参数，下一次 Apply 时生效
func (f *Firewall) SetContext(ctx wfpolicy.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ctx.CoreExe, ctx.ServiceExe, ctx.UIExe = f.ctx.CoreExe, f.ctx.ServiceExe, f.ctx.UIExe
	f.ctx = ctx
}

// Current 返回最近一次成功写入（或强制断网中被搁置）的策略
func (f *Firewall) Current() wfpolicy.Policy {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forced {
		return wfpolicy.Policy{Kind: wfpolicy.Lockdown}
	}
	return f.current
}

// LastError 返回最近一次写入失败的原因
func (f *Firewall) LastError() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastErr
}

// Apply 原子地切换到策略 p。force 为 true 时即使策略没变也重写（用于核对失败后重装）
func (f *Firewall) Apply(p wfpolicy.Policy, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forced {
		f.pending = p
		return nil
	}
	return f.applyLocked(p, force)
}

func (f *Firewall) applyLocked(p wfpolicy.Policy, force bool) error {
	if !force && f.lastErr == nil && p.Equal(f.current) {
		return nil
	}
	if p.Kind == wfpolicy.None {
		err := f.teardownLocked()
		f.lastErr = err
		return err
	}
	rules, err := wfpolicy.Build(f.resolveBlock(p), f.ctx)
	if err == nil {
		err = f.write(rules)
		// BFE 重启后旧会话句柄失效，重连再试一次
		if err != nil && f.open() == nil {
			err = f.write(rules)
		}
	}
	f.lastErr = err
	if err != nil {
		return err
	}
	f.current = p
	f.applied = len(rules)
	return nil
}

// resolveBlock 换算游戏模式名单里程序的 App ID；文件已不存在（卸载或升级换了目录）的直接跳过，
// 不能因为一个过期路径让整套规则写不进去
func (f *Firewall) resolveBlock(p wfpolicy.Policy) wfpolicy.Policy {
	p.Block = f.resolvable(p.Block)
	p.TunOnly = f.resolvable(p.TunOnly)
	return p
}

func (f *Firewall) resolvable(paths []string) []string {
	if len(paths) == 0 {
		return paths
	}
	ok := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, known := f.appIDs[path]; !known {
			id, err := wf.AppID(path)
			if err != nil {
				continue
			}
			f.appIDs[path] = id
		}
		ok = append(ok, path)
	}
	return ok
}

func (f *Firewall) write(rules []wfpolicy.Rule) (err error) {
	if err := f.ensureSession(); err != nil {
		return err
	}
	s := f.session
	if err := s.BeginTransaction(); err != nil {
		return fmt.Errorf("开始 WFP 事务失败：%w", err)
	}
	committed := false
	defer func() {
		if !committed {
			s.AbortTransaction()
		}
	}()
	if err := f.ensureBase(s); err != nil {
		return err
	}
	if err := deleteOurs(s); err != nil {
		return err
	}
	for i, r := range rules {
		wr, err := f.toRule(r)
		if err != nil {
			return err
		}
		if err := s.AddRule(wr); err != nil {
			return fmt.Errorf("写入第 %d 条规则「%s」失败：%w", i+1, r.Name, err)
		}
	}
	if err := s.CommitTransaction(); err != nil {
		return fmt.Errorf("提交 WFP 事务失败：%w", err)
	}
	committed = true
	return nil
}

func baseExists(s *wf.Session) (provider, sublayer bool, err error) {
	providers, err := s.Providers()
	if err != nil {
		return false, false, fmt.Errorf("读取 WFP provider 失败：%w", err)
	}
	for _, p := range providers {
		if p.ID == providerID {
			provider = true
			break
		}
	}
	if !provider {
		return false, false, nil
	}
	sublayers, err := s.Sublayers(providerID)
	if err != nil {
		return true, false, fmt.Errorf("读取 WFP 子层失败：%w", err)
	}
	for _, sl := range sublayers {
		if sl.ID == sublayerID {
			return true, true, nil
		}
	}
	return true, false, nil
}

func (f *Firewall) ensureBase(s *wf.Session) error {
	hasProvider, hasSublayer, err := baseExists(s)
	if err != nil {
		return err
	}
	// 不设置 ServiceName：设置后服务停止时规则会被系统停用，与 fail-closed 相反
	if !hasProvider {
		if err := s.AddProvider(&wf.Provider{ID: providerID, Name: "AIGuard", Description: "AIGuard 防泄漏防火墙", Persistent: true}); err != nil {
			return fmt.Errorf("创建 WFP provider 失败：%w", err)
		}
	}
	if hasSublayer {
		return nil
	}
	err = s.AddSublayer(&wf.Sublayer{ID: sublayerID, Name: "AIGuard", Description: "AIGuard 防泄漏规则", Persistent: true, Provider: providerID, Weight: 0xFFFF})
	if err != nil {
		return fmt.Errorf("创建 WFP 子层失败：%w", err)
	}
	return nil
}

func deleteOurs(s *wf.Session) error {
	for _, layer := range layers {
		rules, err := s.RulesForProvider(layer, providerID)
		if err != nil {
			return fmt.Errorf("读取现有规则失败：%w", err)
		}
		for _, r := range rules {
			if err := s.DeleteRule(r.ID); err != nil {
				return fmt.Errorf("删除旧规则「%s」失败：%w", r.Name, err)
			}
		}
	}
	return nil
}

func (f *Firewall) toRule(r wfpolicy.Rule) (*wf.Rule, error) {
	guid, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	out := &wf.Rule{
		ID:         wf.RuleID(guid),
		Name:       "AIGuard：" + r.Name,
		Layer:      wf.LayerALEAuthConnectV4,
		Sublayer:   sublayerID,
		Weight:     uint64(r.Weight),
		Action:     wf.ActionPermit,
		Persistent: true,
		Provider:   providerID,
	}
	if r.Family == wfpolicy.V6 {
		out.Layer = wf.LayerALEAuthConnectV6
	}
	if r.Action == wfpolicy.Block {
		out.Action = wf.ActionBlock
	}
	for _, c := range r.Conds {
		m, err := f.toMatch(c)
		if err != nil {
			return nil, fmt.Errorf("规则「%s」：%w", r.Name, err)
		}
		out.Conditions = append(out.Conditions, m)
	}
	return out, nil
}

func (f *Firewall) toMatch(c wfpolicy.Cond) (*wf.Match, error) {
	switch c.Field {
	case wfpolicy.FieldApp:
		id, ok := f.appIDs[c.App]
		if !ok {
			return nil, fmt.Errorf("未登记的程序 %s", c.App)
		}
		return &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: id}, nil
	case wfpolicy.FieldRemotePrefix:
		if !c.Prefix.IsValid() {
			return nil, errors.New("非法地址段")
		}
		if c.Prefix.IsSingleIP() {
			return &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: c.Prefix.Addr()}, nil
		}
		return &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: c.Prefix}, nil
	case wfpolicy.FieldRemotePort:
		return &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: c.Port}, nil
	case wfpolicy.FieldLocalPort:
		return &wf.Match{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: c.Port}, nil
	case wfpolicy.FieldProtocol:
		return &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProto(c.Proto)}, nil
	case wfpolicy.FieldLocalInterface:
		return &wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: c.LUID}, nil
	case wfpolicy.FieldLoopback:
		return &wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: wf.ConditionFlagIsLoopback}, nil
	}
	return nil, fmt.Errorf("未知条件 %d", c.Field)
}

// Verify 核对规则仍在（其他软件或管理员可能删掉）。返回问题描述；缺失时按当前策略强制重装
func (f *Firewall) Verify() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forced || f.current.Kind == wfpolicy.None {
		return ""
	}
	if err := f.ensureSession(); err != nil {
		return "无法读取防火墙规则：" + err.Error()
	}
	n := 0
	for _, layer := range layers {
		rules, err := f.session.RulesForProvider(layer, providerID)
		if err != nil {
			if f.open() == nil {
				rules, err = f.session.RulesForProvider(layer, providerID)
			}
			if err != nil {
				return "无法读取防火墙规则：" + err.Error()
			}
		}
		n += len(rules)
	}
	if n == f.applied {
		return ""
	}
	if err := f.applyLocked(f.current, true); err != nil {
		return fmt.Sprintf("防火墙规则被改动（剩 %d/%d 条），重装失败：%v", n, f.applied, err)
	}
	return fmt.Sprintf("防火墙规则被改动（剩 %d/%d 条），已重新写入", n, f.applied)
}

// ForceLockdown 睡眠前立即全部断网，不经过守护服务的事件队列
func (f *Firewall) ForceLockdown() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forced {
		return nil
	}
	f.pending = f.current
	err := f.applyLocked(wfpolicy.Policy{Kind: wfpolicy.Lockdown}, true)
	f.forced = err == nil
	return err
}

// ReleaseForcedLockdown 唤醒后恢复到强制断网期间最后一次期望的策略
func (f *Firewall) ReleaseForcedLockdown() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.forced {
		return nil
	}
	f.forced = false
	return f.applyLocked(f.pending, true)
}

// Teardown 删除全部规则、子层与 provider
func (f *Firewall) Teardown() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forced = false
	err := f.teardownLocked()
	f.lastErr = err
	return err
}

func (f *Firewall) teardownLocked() error {
	if err := f.ensureSession(); err != nil {
		return err
	}
	s := f.session
	if err := s.BeginTransaction(); err != nil {
		return fmt.Errorf("开始 WFP 事务失败：%w", err)
	}
	fail := func(err error) error {
		s.AbortTransaction()
		return err
	}
	hasProvider, hasSublayer, err := baseExists(s)
	if err != nil {
		return fail(err)
	}
	// 事务里的调用失败需要自己回滚，所以先查清对象是否存在，只删存在的
	if hasProvider {
		if err := deleteOurs(s); err != nil {
			return fail(err)
		}
	}
	if hasSublayer {
		if err := s.DeleteSublayer(sublayerID); err != nil {
			return fail(fmt.Errorf("删除 WFP 子层失败：%w", err))
		}
	}
	if hasProvider {
		if err := s.DeleteProvider(providerID); err != nil {
			return fail(fmt.Errorf("删除 WFP provider 失败：%w", err))
		}
	}
	if err := s.CommitTransaction(); err != nil {
		return fmt.Errorf("提交 WFP 事务失败：%w", err)
	}
	f.current = wfpolicy.Policy{Kind: wfpolicy.None}
	f.applied = 0
	return nil
}

// Close 只断开会话，不删除持久规则
func (f *Firewall) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.session != nil {
		f.session.Close()
		f.session = nil
	}
}

// Reset 不依赖任何状态地清掉 AIGuard 的全部 WFP 对象，供卸载和断网自救使用
func Reset() error {
	s, err := wf.New(&wf.Options{Name: "AIGuard reset"})
	if err != nil {
		return err
	}
	defer s.Close()
	f := &Firewall{session: s}
	return f.teardownLocked()
}
