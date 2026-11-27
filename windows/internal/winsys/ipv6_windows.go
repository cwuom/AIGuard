//go:build windows

package winsys

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// IPv6Switch 关闭真实网卡的 IPv6 协议绑定（ms_tcpip6），关闭守护时恢复。
// WFP 已经拒绝全部 IPv6 出站，这里是第二层：网卡上根本没有 IPv6 地址，浏览器也不会尝试 IPv6
type IPv6Switch struct {
	mu       sync.Mutex
	backup   string
	disabled map[string]string // GUID -> 网卡名（展示用）
}

func NewIPv6Switch(backupFile string) *IPv6Switch {
	s := &IPv6Switch{backup: backupFile, disabled: map[string]string{}}
	readJSON(backupFile, &s.disabled)
	return s
}

func (s *IPv6Switch) DisabledCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.disabled)
}

func powershell(script string, timeout time.Duration) (string, error) {
	exe := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// bindingEnabled 返回 GUID -> 是否启用了 IPv6 绑定
func bindingEnabled(guids []string) (map[string]bool, error) {
	var list []string
	for _, g := range guids {
		if ValidGUID(g) {
			list = append(list, "'"+g+"'")
		}
	}
	if len(list) == 0 {
		return map[string]bool{}, nil
	}
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; $ids=@(%s); Get-NetAdapter -IncludeHidden | Where-Object { $ids -contains $_.InterfaceGuid } | ForEach-Object { $b = Get-NetAdapterBinding -InterfaceDescription $_.InterfaceDescription -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue; if ($b) { '{0} {1}' -f $_.InterfaceGuid, $b.Enabled } }`, strings.Join(list, ","))
	out, err := powershell(script, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%v：%s", err, out)
	}
	res := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 2 && ValidGUID(f[0]) {
			res[strings.ToUpper(f[0])] = strings.EqualFold(f[1], "True")
		}
	}
	return res, nil
}

func setBinding(guid string, enable bool) error {
	if !ValidGUID(guid) {
		return fmt.Errorf("非法网卡 GUID")
	}
	verb := "Disable-NetAdapterBinding"
	if enable {
		verb = "Enable-NetAdapterBinding"
	}
	// 网卡不在（拔掉的 USB 网卡）时必须报错：否则会被当成恢复成功，记录被删掉后再插上就没人恢复了
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; $a = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceGuid -eq '%s' }); if ($a.Count -eq 0) { throw 'adapter not found' }; $a | ForEach-Object { %s -InterfaceDescription $_.InterfaceDescription -ComponentID ms_tcpip6 }`, guid, verb)
	out, err := powershell(script, 60*time.Second)
	if err != nil {
		return fmt.Errorf("%v：%s", err, out)
	}
	return nil
}

// DisableAll 关闭所有真实网卡的 IPv6；返回关闭失败的网卡名
func (s *IPv6Switch) DisableAll(ifaces []Iface) (failed []string) {
	var guids []string
	names := map[string]string{}
	for _, i := range ifaces {
		if i.Physical && ValidGUID(i.GUID) {
			g := strings.ToUpper(i.GUID)
			guids = append(guids, g)
			names[g] = i.Alias
		}
	}
	if len(guids) == 0 {
		return nil
	}
	state, err := bindingEnabled(guids)
	if err != nil {
		return []string{"全部网卡（" + err.Error() + "）"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range guids {
		if !state[g] {
			continue
		}
		s.disabled[g] = names[g]
		if err := writeJSON(s.backup, s.disabled); err != nil {
			delete(s.disabled, g)
			failed = append(failed, names[g])
			continue
		}
		if err := setBinding(g, false); err != nil {
			delete(s.disabled, g)
			writeJSON(s.backup, s.disabled)
			failed = append(failed, names[g])
		}
	}
	return failed
}

// RestoreAll 恢复由我们关闭的网卡
func (s *IPv6Switch) RestoreAll() (failed []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for g, name := range s.disabled {
		if err := setBinding(g, true); err != nil {
			failed = append(failed, name)
			continue
		}
		delete(s.disabled, g)
	}
	if len(s.disabled) == 0 {
		os.Remove(s.backup)
	} else {
		writeJSON(s.backup, s.disabled)
	}
	return failed
}
