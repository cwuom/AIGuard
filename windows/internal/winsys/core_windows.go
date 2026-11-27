//go:build windows

package winsys

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CoreProcess 管理 mihomo 内核子进程。
// 内核放进「随句柄关闭而终止」的 Job：服务崩溃或被杀时内核跟着退出、TUN 随之消失，
// 持久化的 WFP 规则只放行已不存在的 TUN，于是全部流量被拦住，直到服务被系统重启（fail-closed）
type CoreProcess struct {
	Binary, Home, Config, LogFile string

	mu       sync.Mutex
	cmd      *exec.Cmd
	job      windows.Handle
	restarts int
	onExit   func(code int)
}

func (c *CoreProcess) OnExit(f func(code int)) {
	c.mu.Lock()
	c.onExit = f
	c.mu.Unlock()
}

func (c *CoreProcess) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmd != nil
}

func (c *CoreProcess) Restarts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.restarts
}

func (c *CoreProcess) NoteRestart() {
	c.mu.Lock()
	c.restarts++
	c.mu.Unlock()
}

var versionPattern = regexp.MustCompile(`v\d+\.\d+\.\d+`)

func (c *CoreProcess) Version() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Binary, "-v")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return versionPattern.FindString(string(out))
}

// WriteConfig 原子写入配置
func (c *CoreProcess) WriteConfig(yaml string) error {
	tmp := c.Config + ".tmp"
	if err := os.WriteFile(tmp, []byte(yaml), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.Config)
}

// PIDs 返回由本安装目录的内核可执行文件启动的全部进程
func (c *CoreProcess) PIDs() []uint32 {
	procs, err := Processes(true)
	if err != nil {
		return nil
	}
	var out []uint32
	for _, p := range procs {
		if strings.EqualFold(p.Exe, c.Binary) {
			out = append(out, p.PID)
		}
	}
	return out
}

// KillStale 结束上一个服务实例遗留的内核（正常情况下 Job 已经把它带走了）
func (c *CoreProcess) KillStale() {
	procs, err := Processes(true)
	if err != nil {
		return
	}
	for _, p := range procs {
		if strings.EqualFold(p.Exe, c.Binary) {
			Kill(p)
		}
	}
}

func (c *CoreProcess) ensureJob() error {
	if c.job != 0 {
		return nil
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return err
	}
	c.job = job
	return nil
}

func rotate(path string, max int64) {
	if st, err := os.Stat(path); err == nil && st.Size() > max {
		os.Remove(path + ".1")
		os.Rename(path, path+".1")
	}
}

// Start 启动内核；已在运行时什么也不做
func (c *CoreProcess) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != nil {
		return nil
	}
	if err := c.ensureJob(); err != nil {
		return err
	}
	rotate(c.LogFile, 10<<20)
	log, err := os.OpenFile(c.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(c.Binary, "-d", c.Home, "-f", c.Config)
	cmd.Dir = c.Home
	cmd.Stdout = log
	cmd.Stderr = log
	// 先挂起创建、放进 Job 再恢复，保证内核从第一条指令起就受 Job 约束
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED}
	if err := cmd.Start(); err != nil {
		log.Close()
		return err
	}
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(c.job, ph)
		windows.CloseHandle(ph)
	}
	if err == nil {
		err = resumeProcess(uint32(cmd.Process.Pid))
	}
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		return errors.New("内核无法放入受控 Job：" + err.Error())
	}
	c.cmd = cmd
	go func() {
		err := cmd.Wait()
		log.Close()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		c.mu.Lock()
		current := c.cmd == cmd
		if current {
			c.cmd = nil
		}
		cb := c.onExit
		c.mu.Unlock()
		if current && cb != nil {
			cb(code)
		}
	}()
	return nil
}

// Stop 结束内核：先给 3 秒让它收回 TUN 路由，再强制结束
func (c *CoreProcess) Stop() {
	c.mu.Lock()
	cmd := c.cmd
	c.cmd = nil
	c.mu.Unlock()
	if cmd == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()
	// Windows 没有 SIGTERM；mihomo 收到 CTRL_BREAK 需要同一控制台，这里直接结束，路由由 sing-tun 随进程清理
	cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

func resumeProcess(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snap)
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err := windows.Thread32First(snap, &te); err != nil {
		return err
	}
	resumed := false
	for {
		if te.OwnerProcessID == pid {
			th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
			if err == nil {
				_, err = windows.ResumeThread(th)
				windows.CloseHandle(th)
				if err == nil {
					resumed = true
				}
			}
		}
		if err := windows.Thread32Next(snap, &te); err != nil {
			break
		}
	}
	if !resumed {
		return errors.New("没有找到可恢复的主线程")
	}
	return nil
}

// InstallDir 返回服务可执行文件所在目录
func InstallDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}
