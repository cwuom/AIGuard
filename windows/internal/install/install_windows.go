//go:build windows

// Package install 负责注册/升级/卸载 Windows 服务与文件布局。只由提权后的 aiguard-service.exe 调用。
//
// 布局：
//
//	%ProgramFiles%\AIGuard\        程序（AIGuard.exe、aiguard-service.exe、core\mihomo.exe、rules\）
//	%ProgramData%\AIGuard\         设置、订阅、内核工作目录、日志（只有 SYSTEM 与管理员可读写）
package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"aiguard/internal/ipc"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	ServiceName = "AIGuard"
	displayName = "AI 出差管家防护服务"
	description = "AIGuard：TUN 接管、WFP 防火墙熔断与 DNS/IPv6 防泄漏。停止本服务不会撤销防火墙规则。"
)

// Files 是需要从安装包复制到程序目录的文件（相对路径）
var Files = []string{
	"AIGuard.exe",
	"aiguard-service.exe",
	`core\mihomo.exe`,
	`rules\geosite-cn.mrs`,
	`rules\geoip-cn.mrs`,
	`rules\geosite-anthropic.mrs`,
	`rules\geosite-category-ntp.mrs`,
	`rules\cn4.txt`,
	"LICENSE.txt",
	"THIRD_PARTY_NOTICES.md",
}

// ProgramDir 返回程序目录
func ProgramDir() string {
	pf := os.Getenv("ProgramW6432")
	if pf == "" {
		pf = os.Getenv("ProgramFiles")
	}
	return filepath.Join(pf, "AIGuard")
}

// DataDir 返回数据目录
func DataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "AIGuard")
}

// Config 是安装时记录的参数（数据目录下 install.json）
type Config struct {
	// UserSID 是安装界面的用户，只有他（以及管理员）能连控制管道
	UserSID string `json:"userSid"`
	Version string `json:"version"`
}

func configPath() string { return filepath.Join(DataDir(), "install.json") }

// LoadConfig 读取安装参数
func LoadConfig() (Config, error) {
	var c Config
	b, err := os.ReadFile(configPath())
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

// 数据目录与内核目录：禁止继承，只给 SYSTEM 与管理员完全控制（订阅链接、控制密钥、以 SYSTEM 运行的内核都在这里）
const adminOnlyDirSDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// 单个文件：服务 exe 只允许 SYSTEM 与管理员执行，普通用户无法冒用它的防火墙例外
const adminOnlyFileSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"

func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}

// trustedOwner 判断目录属主是否为 SYSTEM 或管理员组
func trustedOwner(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

// secureDir 建立只有管理员能碰的目录。ProgramData 下普通用户可以建子目录，
// 如果有人抢先建了同名目录或链接，就把它挪开再新建，避免以 SYSTEM 身份往别人控制的位置写文件
func secureDir(path string) error {
	if st, err := os.Lstat(path); err == nil {
		link := st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0
		if link || !st.IsDir() || !trustedOwner(path) {
			aside := fmt.Sprintf("%s.untrusted-%d", path, time.Now().Unix())
			if err := os.Rename(path, aside); err != nil {
				return fmt.Errorf("%s 不可信且无法挪开：%w", path, err)
			}
		}
	}
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	return applySDDL(path, adminOnlyDirSDDL)
}

// PrepareDataDir 在写任何日志或设置之前调用
func PrepareDataDir() error {
	if err := secureDir(DataDir()); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Join(DataDir(), "logs"), 0o700)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// 正在运行的 exe 不能覆盖，但可以改名；旧文件留到下次安装时清理
	if _, err := os.Stat(dst); err == nil {
		old := dst + ".old"
		os.Remove(old)
		if err := os.Rename(dst, old); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return os.Rename(tmp, dst)
}

// Install 从 srcDir（解压出来的安装包）安装或升级。userSID 由未提权的界面传入
func Install(srcDir, userSID, version string) error {
	if !ipc.ValidUserSID(userSID) {
		return fmt.Errorf("非法用户 SID")
	}
	for _, f := range Files {
		if _, err := os.Stat(filepath.Join(srcDir, f)); err != nil {
			return fmt.Errorf("安装包缺少 %s，请重新解压完整的安装包", f)
		}
	}
	dst := ProgramDir()
	if err := PrepareDataDir(); err != nil {
		return fmt.Errorf("无法创建数据目录：%w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("无法连接服务管理器：%w", err)
	}
	defer m.Disconnect()

	// 升级：先停旧服务。停服务期间持久化防火墙规则仍在，网络会短暂断开而不是泄漏
	if s, err := m.OpenService(ServiceName); err == nil {
		stop(s)
		s.Close()
	}

	same := strings.EqualFold(filepath.Clean(srcDir), filepath.Clean(dst))
	if !same {
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
		// 内核目录先收紧再放文件，新文件直接继承管理员专属的权限
		if err := secureDir(filepath.Join(dst, "core")); err != nil {
			return fmt.Errorf("无法设置内核目录权限：%w", err)
		}
		for _, f := range Files {
			if err := copyFile(filepath.Join(srcDir, f), filepath.Join(dst, f)); err != nil {
				return fmt.Errorf("复制 %s 失败：%w", f, err)
			}
		}
	}
	if err := applySDDL(filepath.Join(dst, "aiguard-service.exe"), adminOnlyFileSDDL); err != nil {
		return fmt.Errorf("无法设置服务程序权限：%w", err)
	}

	// 版本号另写一份到程序目录：数据目录只有管理员可读，界面需要它判断是否要升级
	if err := os.WriteFile(filepath.Join(dst, "VERSION"), []byte(version), 0o644); err != nil {
		return err
	}
	cfg, _ := json.MarshalIndent(Config{UserSID: userSID, Version: version}, "", "  ")
	if err := os.WriteFile(configPath(), cfg, 0o600); err != nil {
		return err
	}

	exe := filepath.Join(dst, "aiguard-service.exe")
	s, err := m.OpenService(ServiceName)
	if err != nil {
		s, err = m.CreateService(ServiceName, exe, mgr.Config{
			DisplayName:  displayName,
			Description:  description,
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, "run")
		if err != nil {
			return fmt.Errorf("注册服务失败：%w", err)
		}
	} else {
		c, err := s.Config()
		if err == nil {
			c.BinaryPathName = `"` + exe + `" run`
			c.StartType = mgr.StartAutomatic
			c.DisplayName = displayName
			c.Description = description
			s.UpdateConfig(c)
		}
	}
	defer s.Close()
	// 崩溃后 1 秒、1 秒、5 秒自动重启，计数一天后清零
	s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}, 86400)
	s.SetRecoveryActionsOnNonCrashFailures(true)
	CreateShortcut()
	if err := s.Start(); err != nil {
		return fmt.Errorf("启动服务失败：%w", err)
	}
	return waitState(s, svc.Running, 30*time.Second)
}

func stop(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("停止服务失败：%w", err)
	}
	return waitState(s, svc.Stopped, 30*time.Second)
}

func waitState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return errors.New("等待服务状态超时")
}

// StopService 停止服务并改为手动启动（断网自救用）：否则重启电脑后服务会自动起来，把规则重新写回去
func StopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return nil
	}
	defer s.Close()
	if c, err := s.Config(); err == nil && c.StartType != mgr.StartManual {
		c.StartType = mgr.StartManual
		if err := s.UpdateConfig(c); err != nil {
			return fmt.Errorf("无法把服务改为手动启动：%w", err)
		}
	}
	return stop(s)
}

// RemoveService 停止并删除服务（防火墙、DNS、IPv6 的清理由调用方先做）
func RemoveService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return nil
	}
	defer s.Close()
	if err := stop(s); err != nil {
		return err
	}
	return s.Delete()
}

// InstalledVersion 读取程序目录里的版本号，普通用户可读；没装时返回空串
func InstalledVersion() string {
	b, err := os.ReadFile(filepath.Join(ProgramDir(), "VERSION"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ServicePID 返回正在运行的防护服务进程号，没在运行时返回 0（普通用户可调用）
func ServicePID() uint32 {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString(ServiceName)
	h, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS_PROCESS
	var need uint32
	if err := windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need); err != nil {
		return 0
	}
	if st.CurrentState != windows.SERVICE_RUNNING {
		return 0
	}
	return st.ProcessId
}

// ServiceInfo 返回服务是否已安装、是否在运行（界面用，不需要管理员权限）
func ServiceInfo() (installed, running bool) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString(ServiceName)
	h, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &st); err != nil {
		return true, false
	}
	return true, st.CurrentState == windows.SERVICE_RUNNING
}

// RemoveProgramDir 在当前进程退出后删除程序目录（运行中的 exe 不能直接删）
func RemoveProgramDir() {
	dir := ProgramDir()
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`), "/C",
		fmt.Sprintf(`ping -n 3 127.0.0.1 >NUL & rmdir /S /Q "%s"`, dir))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW | windows.DETACHED_PROCESS}
	cmd.Start()
}

func shortcutPath() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\AI 出差管家.lnk`)
}

// CreateShortcut 在「开始」菜单（所有用户）放一个界面快捷方式；失败不影响安装
func CreateShortcut() error {
	target := filepath.Join(ProgramDir(), "AIGuard.exe")
	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	// 路径只来自固定目录，不含用户输入；仍用单引号并转义，防止目录名里的引号
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	script := fmt.Sprintf(`$s=(New-Object -ComObject WScript.Shell).CreateShortcut(%s); $s.TargetPath=%s; $s.WorkingDirectory=%s; $s.Description='AI 出差管家'; $s.Save()`,
		q(shortcutPath()), q(target), q(ProgramDir()))
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// RemoveShortcut 删除「开始」菜单快捷方式
func RemoveShortcut() { os.Remove(shortcutPath()) }

// RemoveData 删除设置、订阅与日志
func RemoveData() error { return os.RemoveAll(DataDir()) }
