//go:build windows

package winsys

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Proc 是一个进程的快照。Cmdline 只在需要时读取（读命令行要多开一次句柄）
type Proc struct {
	PID     uint32
	Name    string
	Exe     string
	Cmdline string
	Session uint32
}

// Processes 枚举全部进程；withCmdline 为 true 时同时读取完整路径与命令行
func Processes(withCmdline bool) ([]Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return nil, err
	}
	self := uint32(os.Getpid())
	var out []Proc
	for {
		if e.ProcessID != 0 && e.ProcessID != 4 && e.ProcessID != self {
			p := Proc{PID: e.ProcessID, Name: windows.UTF16ToString(e.ExeFile[:])}
			windows.ProcessIdToSessionId(p.PID, &p.Session)
			if withCmdline {
				p.Exe, p.Cmdline = details(p.PID)
			}
			out = append(out, p)
		}
		if err := windows.Process32Next(snap, &e); err != nil {
			break
		}
	}
	return out, nil
}

func details(pid uint32) (exe, cmdline string) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(h)
	return imagePath(h), commandLine(h)
}

func imagePath(h windows.Handle) string {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// commandLine 用 ProcessCommandLineInformation 读取，不需要读目标进程内存（Windows 8.1 起可用）
func commandLine(h windows.Handle) string {
	size := uint32(4096)
	for range 3 {
		buf := make([]byte, size)
		var need uint32
		err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), size, &need)
		if err == nil {
			s := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
			if s.Buffer == nil || s.Length == 0 {
				return ""
			}
			return windows.UTF16ToString(unsafe.Slice(s.Buffer, s.Length/2))
		}
		if need <= size || need > 1<<20 {
			return ""
		}
		size = need
	}
	return ""
}

// Kill 打开句柄后先核对可执行文件路径没变（防止 PID 被复用），再结束进程
func Kill(p Proc) bool {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	if p.Exe != "" && !strings.EqualFold(imagePath(h), p.Exe) {
		return false
	}
	return windows.TerminateProcess(h, 1) == nil
}

// UserProfiles 读取所有用户目录，用来在关键词匹配前去掉用户名部分
func UserProfiles() []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	sids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	var out []string
	for _, sid := range sids {
		sk, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := sk.GetStringValue("ProfileImagePath")
		sk.Close()
		if err == nil && v != "" {
			if exp, err := registry.ExpandString(v); err == nil {
				v = exp
			}
			out = append(out, filepath.Clean(v))
		}
	}
	return out
}

// CloseMatching 结束所有交互会话里匹配的进程（会话 0 是系统服务，绝不碰），返回被关闭的进程名。
// stillWanted 在每次结束进程前检查，熔断已解除就停手
func CloseMatching(match func(Proc) bool, stillWanted func() bool) []string {
	procs, err := Processes(true)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var closed []string
	for _, p := range procs {
		if p.Session == 0 || p.Exe == "" || !match(p) {
			continue
		}
		if !stillWanted() {
			break
		}
		if Kill(p) && !seen[strings.ToLower(p.Name)] {
			seen[strings.ToLower(p.Name)] = true
			closed = append(closed, strings.TrimSuffix(p.Name, filepath.Ext(p.Name)))
		}
	}
	return closed
}

// ScanConflicts 找出正在运行的其他代理/VPN 软件；ownDir 下的进程（自己的内核）排除
func ScanConflicts(ownDir string) []string {
	procs, err := Processes(true)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	own := strings.ToLower(filepath.Clean(ownDir)) + `\`
	for _, p := range procs {
		name := ConflictName(p.Name)
		if name == "" || seen[name] {
			continue
		}
		if p.Exe != "" && strings.HasPrefix(strings.ToLower(p.Exe), own) {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}
