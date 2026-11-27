package winsys

import "testing"

func TestFingerprintIgnoresTunAndOrder(t *testing.T) {
	a := []Iface{
		{GUID: "{A}", Alias: "Wi-Fi", IPv4: []string{"192.168.1.5"}, Gateways: []string{"192.168.1.1"}, Up: true, Physical: true},
		{GUID: "{T}", Alias: TunAlias, IPv4: []string{"198.18.0.1"}, Up: true, Tunnel: true},
	}
	b := []Iface{
		{GUID: "{T}", Alias: TunAlias, IPv4: []string{"198.18.0.1"}, Up: true, Tunnel: true},
		{GUID: "{A}", Alias: "Wi-Fi", IPv4: []string{"192.168.1.5"}, Gateways: []string{"192.168.1.1"}, Up: true, Physical: true},
	}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("顺序与 TUN 不应影响指纹")
	}
	b[1].IPv4 = []string{"192.168.1.6"}
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("IP 变化必须改变指纹")
	}
	b[1].IPv4 = []string{"192.168.1.5"}
	b[1].Gateways = []string{"192.168.1.254"}
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("网关变化必须改变指纹")
	}
}

func TestPrimaryPrefersDefaultRoute(t *testing.T) {
	list := []Iface{
		{LUID: 1, Alias: "以太网", Up: true, Physical: true, Gateways: []string{"10.0.0.1"}},
		{LUID: 2, Alias: "Wi-Fi", Up: true, Physical: true, Gateways: []string{"192.168.1.1"}},
	}
	if got := Primary(list, 2); got != "Wi-Fi" {
		t.Fatalf("得到 %q", got)
	}
	if got := Primary(list, 99); got != "以太网" {
		t.Fatalf("默认路由不在真实网卡上时退回第一块有网关的网卡，得到 %q", got)
	}
}

func TestTunDetection(t *testing.T) {
	list := []Iface{
		{Alias: "aiguard", Up: true, Tunnel: true, Description: "AIGuard Tunnel"},
		{Alias: "Clash", Up: true, Tunnel: true, Description: "Wintun Userspace Tunnel"},
		{Alias: "OpenVPN", Up: false, Tunnel: true},
	}
	if FindTun(list) == nil {
		t.Fatal("网卡名不区分大小写")
	}
	got := ForeignTuns(list)
	if len(got) != 1 || got[0] != "Clash" {
		t.Fatalf("其他隧道网卡：%v", got)
	}
	if !IsTunnelDriver("Wintun Userspace Tunnel") || !IsTunnelDriver("TAP-Windows Adapter V9") || IsTunnelDriver("Intel(R) Wi-Fi 6E AX211 160MHz") {
		t.Fatal("驱动识别有误")
	}
}

func TestConflictAndGUID(t *testing.T) {
	if ConflictName("clash-verge-service.exe") != "" {
		t.Fatal("Clash Verge 退出后常驻的服务进程不应算冲突")
	}
	if ConflictName("Clash-Verge.EXE") != "Clash Verge" || ConflictName("chrome.exe") != "" {
		t.Fatal("冲突软件识别有误")
	}
	if !ValidGUID("{4D36E972-E325-11CE-BFC1-08002BE10318}") || ValidGUID("{x}'; rm") || ValidGUID("4D36E972-E325-11CE-BFC1-08002BE10318") {
		t.Fatal("GUID 校验有误")
	}
}

func TestParseNameServers(t *testing.T) {
	got := ParseNameServers("8.8.8.8, 1.1.1.1 ;  ")
	if len(got) != 2 || got[0] != "8.8.8.8" || got[1] != "1.1.1.1" {
		t.Fatalf("得到 %v", got)
	}
	if len(ParseNameServers("")) != 0 {
		t.Fatal("空串表示 DHCP")
	}
}
