//go:build windows

package winsys

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const tcpipInterfaces = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`

// DNSLock 把真实网卡的 IPv4 DNS 锁到 TUN（mihomo dns-hijack 接管），关闭守护时恢复。
// 备份的是注册表里的静态 NameServer（空串表示 DHCP 下发），只改 NameServer，不碰搜索后缀
type DNSLock struct {
	mu     sync.Mutex
	backup string
	// saved: GUID -> 原静态 DNS
	saved map[string]string
}

func NewDNSLock(backupFile string) *DNSLock {
	l := &DNSLock{backup: backupFile, saved: map[string]string{}}
	readJSON(backupFile, &l.saved)
	return l
}

// Locked 表示至少有一块网卡处于锁定状态
func (l *DNSLock) Locked() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.saved) > 0
}

func readNameServer(guid string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipInterfaces+guid, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("NameServer")
	if err == registry.ErrNotExist {
		return "", nil
	}
	return v, err
}

func setNameServer(guid string, servers string) error {
	g, err := windows.GUIDFromString(guid)
	if err != nil {
		return err
	}
	ns, err := windows.UTF16PtrFromString(servers)
	if err != nil {
		return err
	}
	return winipcfg.SetInterfaceDnsSettings(g, &winipcfg.DnsInterfaceSettings{
		Version:    winipcfg.DnsInterfaceSettingsVersion1,
		Flags:      winipcfg.DnsInterfaceSettingsFlagNameserver,
		NameServer: ns,
	})
}

// Lock 锁定当前所有真实网卡；返回是否有网卡被改动（新接入的网卡、被用户改回去的网卡）
func (l *DNSLock) Lock(ifaces []Iface) (changed bool, failed []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, i := range ifaces {
		if !i.Physical || !ValidGUID(i.GUID) {
			continue
		}
		cur, err := readNameServer(i.GUID)
		if err != nil {
			failed = append(failed, i.Alias)
			continue
		}
		if strings.TrimSpace(cur) == TunDNS {
			continue
		}
		// 已有备份说明之前锁过、后来被改回去了：保留最早的原始值
		if _, ok := l.saved[i.GUID]; !ok {
			l.saved[i.GUID] = cur
			// 先落盘备份再改系统设置，崩溃后也能恢复
			if err := writeJSON(l.backup, l.saved); err != nil {
				delete(l.saved, i.GUID)
				failed = append(failed, i.Alias)
				continue
			}
		}
		if err := setNameServer(i.GUID, TunDNS); err != nil {
			failed = append(failed, fmt.Sprintf("%s（%v）", i.Alias, err))
			continue
		}
		changed = true
	}
	return changed, failed
}

// Restore 恢复全部备份，已拔掉的网卡也照样写回（下次接入时就是原设置）
func (l *DNSLock) Restore() (failed []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for guid, orig := range l.saved {
		cur, err := readNameServer(guid)
		// 用户在锁定期间自己改成了别的值，就尊重用户的新设置
		if err == nil && strings.TrimSpace(cur) != TunDNS {
			delete(l.saved, guid)
			continue
		}
		if err := setNameServer(guid, orig); err != nil {
			failed = append(failed, guid)
			continue
		}
		delete(l.saved, guid)
	}
	if len(l.saved) == 0 {
		os.Remove(l.backup)
	} else {
		writeJSON(l.backup, l.saved)
	}
	return failed
}
