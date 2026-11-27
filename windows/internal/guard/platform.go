// Package guard 是守护服务的主循环（对应 Android 的 daemon/Guardian.kt、macOS 的 aiguardd/Guardian.swift）。
// 它只依赖这里定义的平台接口，所以能在任意系统上用假实现测试；Windows 实现见 platform_windows.go。
package guard

import (
	"time"

	"aiguard/internal/wfpolicy"
	"aiguard/internal/winsys"
)

// Firewall 是 WFP 防火墙（*wfp.Firewall 实现）
type Firewall interface {
	// Apply 原子切换策略；失败时旧规则保持不变
	Apply(p wfpolicy.Policy, force bool) error
	Current() wfpolicy.Policy
	LastError() error
	// Verify 核对规则仍在，缺失就重装；返回给用户看的问题描述，正常时为空
	Verify() string
	// SetContext 更新大陆 IP 段等参数（程序路径不可改）
	SetContext(ctx wfpolicy.Context)
	// ForceLockdown 睡眠前立即全部断网；之后的 Apply 只记录不写入，直到 ReleaseForcedLockdown
	ForceLockdown() error
	ReleaseForcedLockdown() error
	Teardown() error
}

// Core 是 mihomo 内核进程（*winsys.CoreProcess 实现）
type Core interface {
	Start() error
	Stop()
	Running() bool
	Restarts() int
	NoteRestart()
	Version() string
	WriteConfig(yaml string) error
	KillStale()
	PIDs() []uint32
	// OnExit 只对仍是当前进程的意外退出回调；回调在任意 goroutine 上执行
	OnExit(func(code int))
}

// AppKind 是熔断时要关闭的应用类别
type AppKind int

const (
	KindAI AppKind = 1 << iota
	KindBrowser
)

// System 是其余系统操作
type System interface {
	Interfaces() ([]winsys.Iface, error)
	// DefaultRouteLUID 返回去往公网的最佳路由所在网卡，用来判断 TUN 是否真的接管了路由
	DefaultRouteLUID() uint64
	IPv6Reachable(timeout time.Duration) bool

	LockDNS(ifaces []winsys.Iface) (changed bool, failed []string)
	RestoreDNS() (failed []string)
	DNSLocked() bool

	DisableIPv6(ifaces []winsys.Iface) (failed []string)
	RestoreIPv6() (failed []string)
	IPv6DisabledCount() int

	// CloseApps 关闭交互会话里的 AI 进程和/或浏览器，返回被关闭的进程名；stillWanted 返回 false 时停手
	CloseApps(kinds AppKind, extraProcesses []string, stillWanted func() bool) []string
	// ScanConflicts 返回正在运行的其他代理/VPN 软件名；withTunnels 为 false 时不报其他隧道网卡（游戏模式下加速器的网卡是正常的）
	ScanConflicts(withTunnels bool) []string
	// ScanApps 扫描正在运行的游戏、加速器，以及游戏模式下要处理的 AI 程序与浏览器
	ScanApps(extraAI, extraGame []string) AppScan
}

// AppScan 是一次进程扫描的结果（路径已去重）
type AppScan struct {
	// AI 是正在运行的 AI 程序路径，Browsers 是正在运行的浏览器路径
	AI, Browsers []string
	// AIRunning 表示有 AI 进程在运行（含不拉黑路径的 WebView2 宿主），游戏模式下要关闭
	AIRunning bool
	// Known 是本机装着、但不一定在运行的常见浏览器
	Known []string
	// Games、Accelerators 是检测到的游戏与加速器名字（去重）
	Games, Accelerators []string
}

// Paths 是服务的运行文件布局（数据目录只有 SYSTEM 与管理员可读写）
type Paths struct {
	// DataDir 形如 C:\ProgramData\AIGuard
	DataDir string
	// Settings、Runtime（控制密钥）、Events、ProviderFile 等都在 DataDir 下
	Settings, Runtime, Events, State            string
	CoreHome, CoreConfig, ProviderFile, CNTable string
	DaemonLog                                   string
	// AppHistory 记录见过的 AI 程序与浏览器路径（游戏模式的黑名单来源之一）
	AppHistory string
}

// Clock 便于测试时控制时间：Mono 是单调毫秒（含睡眠时间），Unbiased 是不含睡眠时间的单调毫秒，Wall 是 epoch 毫秒。
// Mono 与 Unbiased 的差值突然变大说明系统睡过一觉（对应 Android 的 elapsedRealtime 与 uptimeMillis）
type Clock interface {
	Mono() int64
	Unbiased() int64
	Wall() int64
}
