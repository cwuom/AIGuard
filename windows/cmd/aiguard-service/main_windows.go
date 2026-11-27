//go:build windows

// aiguard-service.exe：以 LocalSystem 运行的防护服务，同时承担安装/卸载/断网自救命令。
//
//	aiguard-service.exe run                                服务入口（由服务管理器调用）
//	aiguard-service.exe debug                              在管理员控制台里前台运行，便于排查
//	aiguard-service.exe install --src DIR --user-sid SID   安装或升级（界面经 UAC 调用）
//	aiguard-service.exe uninstall [--purge]                卸载
//	aiguard-service.exe firewall-reset                     删除全部防火墙规则并恢复 DNS/IPv6（断网自救）
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"aiguard/internal/core"
	"aiguard/internal/guard"
	"aiguard/internal/install"
	"aiguard/internal/ipc"
	"aiguard/internal/version"
	"aiguard/internal/wfp"
	"aiguard/internal/wfpolicy"
	"aiguard/internal/winsys"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

// ---------- 日志 ----------

type logger struct {
	mu   sync.Mutex
	path string
}

func (l *logger) write(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, err := os.Stat(l.path); err == nil && st.Size() > 10<<20 {
		os.Remove(l.path + ".1")
		os.Rename(l.path, l.path+".1")
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), line)
}

func paths() guard.Paths {
	data := install.DataDir()
	return guard.Paths{
		DataDir:      data,
		Settings:     filepath.Join(data, "settings.json"),
		Runtime:      filepath.Join(data, "runtime.json"),
		Events:       filepath.Join(data, "events.json"),
		State:        filepath.Join(data, "state"),
		CoreHome:     filepath.Join(data, "core"),
		CoreConfig:   filepath.Join(data, "core", "config.yaml"),
		ProviderFile: filepath.Join(data, "core", "providers", "sub.yaml"),
		CNTable:      filepath.Join(install.ProgramDir(), "rules", core.CNTable),
		DaemonLog:    filepath.Join(data, "logs", "daemon.log"),
		AppHistory:   filepath.Join(data, "state", "app-history.json"),
	}
}

// prepareCoreHome 把规则库复制进内核工作目录（配置里用 ./rules/ 相对路径）
func prepareCoreHome(p guard.Paths) error {
	for _, d := range []string{p.State, filepath.Join(p.CoreHome, "rules"), filepath.Join(p.CoreHome, "providers"), filepath.Dir(p.DaemonLog)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	src := filepath.Join(install.ProgramDir(), "rules")
	for _, f := range core.BundledRuleFiles() {
		in, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			return fmt.Errorf("缺少规则文件 %s：%w", f, err)
		}
		dst := filepath.Join(p.CoreHome, "rules", f)
		if old, err := os.ReadFile(dst); err == nil && string(old) == string(in) {
			continue
		}
		if err := os.WriteFile(dst+".tmp", in, 0o600); err != nil {
			return err
		}
		if err := os.Rename(dst+".tmp", dst); err != nil {
			return err
		}
	}
	return nil
}

// ---------- 服务 ----------

type service struct{ log *logger }

// 睡眠回调：系统在挂起路径上同步调用，必须在返回前完成断网
var (
	powrprof                                     = windows.NewLazySystemDLL("powrprof.dll")
	procPowerRegisterSuspendResumeNotification   = powrprof.NewProc("PowerRegisterSuspendResumeNotification")
	procPowerUnregisterSuspendResumeNotification = powrprof.NewProc("PowerUnregisterSuspendResumeNotification")
	activeGuardian                               *guard.Guardian
	activeGuardianMu                             sync.Mutex
)

const (
	pbtAPMSuspend         = 0x4
	pbtAPMResumeSuspend   = 0x7
	pbtAPMResumeAutomatic = 0x12
	deviceNotifyCallback  = 2
)

type deviceNotifySubscribeParameters struct {
	callback uintptr
	context  uintptr
}

var powerCallback = syscall.NewCallback(func(ctx, typ, setting uintptr) uintptr {
	activeGuardianMu.Lock()
	g := activeGuardian
	activeGuardianMu.Unlock()
	if g == nil {
		return 0
	}
	switch typ {
	case pbtAPMSuspend:
		g.Suspend()
	case pbtAPMResumeSuspend, pbtAPMResumeAutomatic:
		go g.Resume()
	}
	return 0
})

// 参数结构体必须在注册期间一直有效，放在包级变量里
var powerParams = deviceNotifySubscribeParameters{callback: powerCallback}

func registerPower() (uintptr, error) {
	var h uintptr
	r, _, _ := procPowerRegisterSuspendResumeNotification.Call(deviceNotifyCallback, uintptr(unsafe.Pointer(&powerParams)), uintptr(unsafe.Pointer(&h)))
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return h, nil
}

func (s *service) build() (*guard.Guardian, *ipc.Server, error) {
	p := paths()
	if err := prepareCoreHome(p); err != nil {
		return nil, nil, err
	}
	cfg, err := install.LoadConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("读取安装参数失败（请重新安装）：%w", err)
	}
	dir := install.ProgramDir()
	wctx := wfpolicy.Context{
		CoreExe:        filepath.Join(dir, "core", "mihomo.exe"),
		ServiceExe:     filepath.Join(dir, "aiguard-service.exe"),
		UIExe:          filepath.Join(dir, "AIGuard.exe"),
		ControllerPort: uint16(core.Ports.Controller),
		ProbePorts:     []uint16{uint16(core.Ports.Probe), uint16(core.Ports.DirectProbe)},
	}
	fw, err := wfp.New(wctx)
	if err != nil {
		return nil, nil, err
	}
	coreProc := &winsys.CoreProcess{
		Binary:  wctx.CoreExe,
		Home:    p.CoreHome,
		Config:  p.CoreConfig,
		LogFile: filepath.Join(filepath.Dir(p.DaemonLog), "mihomo.log"),
	}
	g, err := guard.New(guard.Options{
		Version:   version.Version,
		Paths:     p,
		Firewall:  fw,
		Core:      coreProc,
		System:    guard.NewWindowsSystem(p, dir),
		Clock:     guard.WindowsClock{},
		Log:       s.log.write,
		WFContext: wctx,
	})
	if err != nil {
		return nil, nil, err
	}
	srv, err := ipc.Listen(core.PipeName, cfg.UserSID)
	if err != nil {
		return nil, nil, fmt.Errorf("创建控制管道失败：%w", err)
	}
	srv.AllowedExe = []string{wctx.UIExe}
	srv.Handler = g.Handle
	return g, srv, nil
}

func (s *service) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	g, srv, err := s.build()
	if err != nil {
		// 启动失败时持久化的防火墙规则仍在（fail-closed），服务管理器会按恢复策略重试
		s.log.write("[critical] 防护服务启动失败：" + err.Error())
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	go srv.Serve(ctx)

	activeGuardianMu.Lock()
	activeGuardian = g
	activeGuardianMu.Unlock()
	accepts := svc.AcceptStop | svc.AcceptShutdown
	powerHandle, err := registerPower()
	if err != nil {
		// 回调注册不了就退回服务管理器的电源事件（异步，断网可能晚于睡眠）
		s.log.write("[warning] 无法注册睡眠回调，改用服务电源事件：" + err.Error())
		accepts |= svc.AcceptPowerEvent
	}
	status <- svc.Status{State: svc.Running, Accepts: accepts}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.PowerEvent:
			switch c.EventType {
			case pbtAPMSuspend:
				g.Suspend()
			case pbtAPMResumeSuspend, pbtAPMResumeAutomatic:
				go g.Resume()
			}
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending, WaitHint: 20000}
			if powerHandle != 0 {
				procPowerUnregisterSuspendResumeNotification.Call(powerHandle)
			}
			activeGuardianMu.Lock()
			activeGuardian = nil
			activeGuardianMu.Unlock()
			srv.Close()
			g.Shutdown()
			return false, 0
		}
	}
	return false, 0
}

// ---------- 命令 ----------

// restoreSystem 用状态目录里的备份恢复 DNS 与 IPv6（不依赖服务在运行）；有失败时返回 false，备份保留
func restoreSystem(log func(string)) bool {
	state := paths().State
	ok := true
	if failed := winsys.NewDNSLock(filepath.Join(state, "dns.json")).Restore(); len(failed) > 0 {
		log("DNS 恢复失败：" + strings.Join(failed, "、"))
		ok = false
	}
	if failed := winsys.NewIPv6Switch(filepath.Join(state, "ipv6.json")).RestoreAll(); len(failed) > 0 {
		log("IPv6 恢复失败：" + strings.Join(failed, "、"))
		ok = false
	}
	return ok
}

func isAdmin() bool {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2, windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid); err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	ok, err := windows.Token(0).IsMember(sid)
	return err == nil && ok
}

func main() {
	inService, err := svc.IsWindowsService()
	if err == nil && inService {
		os.MkdirAll(filepath.Join(install.DataDir(), "logs"), 0o700)
		svc.Run(install.ServiceName, &service{log: &logger{path: paths().DaemonLog}})
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法：aiguard-service.exe install|uninstall|firewall-reset|debug")
		os.Exit(2)
	}
	if !isAdmin() {
		fmt.Fprintln(os.Stderr, "需要以管理员身份运行")
		os.Exit(5)
	}
	cmd, rest := os.Args[1], os.Args[2:]
	// 先确保数据目录属于管理员，再写任何日志
	if err := install.PrepareDataDir(); err != nil {
		fmt.Fprintln(os.Stderr, "数据目录不可用："+err.Error())
		os.Exit(1)
	}
	switch cmd {
	case "install":
		fs := flag.NewFlagSet("install", flag.ExitOnError)
		src := fs.String("src", "", "安装包目录")
		sid := fs.String("user-sid", "", "界面用户 SID")
		fs.Parse(rest)
		l := &logger{path: filepath.Join(install.DataDir(), "logs", "install.log")}
		if *src == "" {
			exe, _ := os.Executable()
			*src = filepath.Dir(exe)
		}
		l.write(fmt.Sprintf("安装 %s（来源 %s）", version.Version, *src))
		if err := install.Install(*src, *sid, version.Version); err != nil {
			l.write("安装失败：" + err.Error())
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		l.write("安装完成")
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
		purge := fs.Bool("purge", false, "同时删除设置、订阅与日志")
		fs.Parse(rest)
		l := &logger{path: filepath.Join(install.DataDir(), "logs", "install.log")}
		say := func(s string) { l.write(s); fmt.Println(s) }
		// 先停服务（服务退出时会写入全部断网），再删规则、恢复系统设置
		if err := install.RemoveService(); err != nil {
			say("删除服务失败：" + err.Error())
		}
		if err := wfp.Reset(); err != nil {
			say("删除防火墙规则失败：" + err.Error())
			os.Exit(1)
		}
		install.RemoveShortcut()
		if !restoreSystem(say) {
			// 备份和本工具都留着，修好网卡后可以再运行一次 uninstall 或 firewall-reset
			say("防火墙规则已删除，但 DNS/IPv6 没能全部恢复；已保留备份与程序，处理后请再运行一次卸载")
			os.Exit(1)
		}
		if *purge {
			install.RemoveData()
		}
		install.RemoveProgramDir()
		say("卸载完成")
	case "firewall-reset":
		say := func(s string) { fmt.Println(s) }
		// 服务还在的话它会立刻把规则写回去，所以先停服务并改为手动启动
		if err := install.StopService(); err != nil {
			say("无法停止防护服务：" + err.Error())
			os.Exit(1)
		}
		if err := wfp.Reset(); err != nil {
			say("删除防火墙规则失败：" + err.Error())
			os.Exit(1)
		}
		if !restoreSystem(say) {
			say("防火墙规则已删除，但 DNS/IPv6 没能全部恢复，详见上面的提示")
			os.Exit(1)
		}
		say("已删除 AIGuard 的全部防火墙规则并恢复 DNS/IPv6。防护服务已停止并改为手动启动，在界面里点「启动防护服务」可恢复防护。")
	case "debug":
		l := &logger{path: paths().DaemonLog}
		if err := debug.Run(install.ServiceName, &service{log: l}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "未知命令："+cmd)
		os.Exit(2)
	}
}
