//go:build windows

package guard

import (
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"aiguard/internal/core"
	"aiguard/internal/winsys"

	"golang.org/x/sys/windows"
)

// WindowsSystem 把 winsys 的各个部件拼成 System 接口
type WindowsSystem struct {
	DNS        *winsys.DNSLock
	IPv6       *winsys.IPv6Switch
	InstallDir string
	profiles   []string
	systemRoot string
	// unity 缓存「这个程序目录下有没有 UnityPlayer.dll」，避免每次扫描都查磁盘
	unity map[string]bool
}

func NewWindowsSystem(p Paths, installDir string) *WindowsSystem {
	root, _ := windows.GetSystemWindowsDirectory()
	if root == "" {
		root = os.Getenv("SystemRoot")
	}
	return &WindowsSystem{
		DNS:        winsys.NewDNSLock(filepath.Join(p.State, "dns.json")),
		IPv6:       winsys.NewIPv6Switch(filepath.Join(p.State, "ipv6.json")),
		InstallDir: installDir,
		systemRoot: root,
	}
}

func (s *WindowsSystem) Interfaces() ([]winsys.Iface, error) { return winsys.Interfaces() }
func (s *WindowsSystem) DefaultRouteLUID() uint64            { return winsys.DefaultRouteLUID() }
func (s *WindowsSystem) IPv6Reachable(t time.Duration) bool  { return winsys.IPv6Reachable(t) }

func (s *WindowsSystem) LockDNS(ifaces []winsys.Iface) (bool, []string) { return s.DNS.Lock(ifaces) }
func (s *WindowsSystem) RestoreDNS() []string                           { return s.DNS.Restore() }
func (s *WindowsSystem) DNSLocked() bool                                { return s.DNS.Locked() }

func (s *WindowsSystem) DisableIPv6(ifaces []winsys.Iface) []string { return s.IPv6.DisableAll(ifaces) }
func (s *WindowsSystem) RestoreIPv6() []string                      { return s.IPv6.RestoreAll() }
func (s *WindowsSystem) IPv6DisabledCount() int                     { return s.IPv6.DisabledCount() }

func (s *WindowsSystem) CloseApps(kinds AppKind, extra []string, stillWanted func() bool) []string {
	// 用户目录随时可能新增（新用户首次登录），每次熔断时重新读取
	s.profiles = winsys.UserProfiles()
	extra = core.CleanProcessNames(extra)
	return winsys.CloseMatching(func(p winsys.Proc) bool {
		if kinds&KindAI != 0 && core.IsAIProcess(p.Exe, p.Cmdline, s.profiles, s.systemRoot, s.InstallDir, extra) {
			return true
		}
		if kinds&KindBrowser != 0 && !core.IsProtected(p.Exe, s.systemRoot, s.InstallDir) && core.IsBrowser(p.Exe) {
			return true
		}
		return false
	}, stillWanted)
}

func (s *WindowsSystem) ScanConflicts(withTunnels bool) []string {
	found := winsys.ScanConflicts(s.InstallDir)
	if !withTunnels {
		return found
	}
	if ifaces, err := winsys.Interfaces(); err == nil {
		for _, t := range winsys.ForeignTuns(ifaces) {
			name := "隧道网卡「" + t + "」"
			dup := false
			for _, f := range found {
				if strings.EqualFold(f, name) {
					dup = true
				}
			}
			if !dup {
				found = append(found, name)
			}
		}
	}
	return found
}

var procQueryUnbiasedInterruptTime = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryUnbiasedInterruptTime")
var procGetTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

// WindowsClock：GetTickCount64 含睡眠时间，QueryUnbiasedInterruptTime（100ns 单位）不含
type WindowsClock struct{}

func (WindowsClock) Mono() int64 {
	r, _, _ := procGetTickCount64.Call()
	return int64(r)
}

func (WindowsClock) Unbiased() int64 {
	var t uint64
	procQueryUnbiasedInterruptTime.Call(uintptr(unsafe.Pointer(&t)))
	return int64(t / 10000)
}

func (WindowsClock) Wall() int64 { return time.Now().UnixMilli() }
