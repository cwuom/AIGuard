//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"aiguard/internal/core"
	"aiguard/internal/install"
	"aiguard/internal/ipc"
	"aiguard/internal/version"

	"github.com/wailsapp/wails/v3/pkg/application"
	"golang.org/x/sys/windows"
)

// UIService 绑定给前端调用。服务相关的请求走命名管道，节点与连接直接查 mihomo 控制接口（与 macOS 版相同）
type UIService struct {
	app *application.App

	mu         sync.Mutex
	api        *core.MihomoApi
	apiSecret  string
	lastStatus *core.GuardStatus
	onStatus   func(*core.GuardStatus)
}

// ServiceView 是服务安装与版本状态
type ServiceView struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Version   string `json:"version"`
	Outdated  bool   `json:"outdated"`
	Newer     bool   `json:"newer"`
	Error     string `json:"error,omitempty"`
}

// StateView 是前端每秒轮询的状态
type StateView struct {
	Version       string            `json:"version"`
	Service       ServiceView       `json:"service"`
	Status        *core.GuardStatus `json:"status"`
	ReasonTitle   string            `json:"reasonTitle,omitempty"`
	SubMaskedURL  string            `json:"subMaskedUrl,omitempty"`
	RunningFromPF bool              `json:"runningFromProgramFiles"`
}

func call(ctx context.Context, req core.Request, timeout time.Duration) (*core.IpcResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, err := json.Marshal(core.IpcEnvelope{Request: req})
	if err != nil {
		return nil, err
	}
	out, err := ipc.Call(ctx, core.PipeName, body, install.ServicePID)
	if errors.Is(err, ipc.ErrUntrustedServer) {
		return nil, errors.New("控制管道被其他程序占用，已拒绝连接；请重启电脑后再打开")
	}
	if err != nil {
		return nil, fmt.Errorf("连不上防护服务：%w", err)
	}
	var r core.IpcResponse
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("防护服务返回了无法解析的数据：%w", err)
	}
	return &r, nil
}

// must 把失败响应转成 error，前端收到的是 rejected promise
func must(r *core.IpcResponse, err error) (*core.IpcResponse, error) {
	if err != nil {
		return nil, err
	}
	if !r.OK {
		msg := "操作失败"
		if r.Error != nil {
			msg = *r.Error
		}
		return r, errors.New(msg)
	}
	return r, nil
}

func runningFromProgramFiles() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	return strings.EqualFold(filepath.Dir(exe), install.ProgramDir())
}

// State 汇总服务状态；服务没装或没运行时 Status 为空
func (u *UIService) State(ctx context.Context) StateView {
	v := StateView{Version: version.Version, RunningFromPF: runningFromProgramFiles()}
	v.Service.Installed, v.Service.Running = install.ServiceInfo()
	v.Service.Version = install.InstalledVersion()
	if v.Service.Running {
		r, err := call(ctx, core.Request{Type: core.RequestStatus}, 3*time.Second)
		if err != nil {
			v.Service.Error = err.Error()
		} else if r.Status != nil {
			v.Status = r.Status
			v.Service.Version = r.Status.Version
			if r.Status.Fuse.Reason != nil {
				v.ReasonTitle = r.Status.Fuse.Reason.Title()
			}
			if r.Status.Subscription != nil {
				v.SubMaskedURL = r.Status.Subscription.MaskedURL()
			}
		}
	}
	if v.Service.Installed && v.Service.Version != "" {
		c := core.CompareVersions(v.Service.Version, version.Version)
		v.Service.Outdated = c < 0
		v.Service.Newer = c > 0
	}
	u.mu.Lock()
	u.lastStatus = v.Status
	cb := u.onStatus
	u.mu.Unlock()
	if cb != nil {
		cb(v.Status)
	}
	return v
}

// SetGameMode 手动开关游戏模式（只改这一项设置）
func (u *UIService) SetGameMode(ctx context.Context, on bool) (*core.IpcResponse, error) {
	s, err := u.Settings(ctx)
	if err != nil {
		return nil, err
	}
	s.GameMode = on
	return u.SaveSettings(ctx, *s)
}

// MetaView 是不随时间变化的数据：地区表与 AI 名单分类
type MetaView struct {
	Version    string         `json:"version"`
	Regions    []RegionView   `json:"regions"`
	Categories []CategoryView `json:"categories"`
}

type RegionView struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type CategoryView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Note      string `json:"note"`
	Strict    bool   `json:"strict"`
	RuleCount int    `json:"ruleCount"`
}

var regionCodes = []string{"CN", "HK", "MO", "TW", "JP", "KR", "SG", "US", "GB", "DE", "FR", "NL", "RU", "IN", "AU", "CA", "MY", "TH", "VN", "PH", "ID", "TR", "AE", "IR", "KP", "BY", "CU", "SY"}

func (u *UIService) Meta() MetaView {
	m := MetaView{Version: version.Version}
	for _, c := range regionCodes {
		m.Regions = append(m.Regions, RegionView{Code: c, Name: core.RegionName(c)})
	}
	for _, c := range core.AIRuleCatalog {
		m.Categories = append(m.Categories, CategoryView{ID: c.ID, Name: c.Name, Note: c.Note, Strict: c.Strict, RuleCount: c.RuleCount()})
	}
	return m
}

func (u *UIService) Settings(ctx context.Context) (*core.GuardSettings, error) {
	r, err := must(call(ctx, core.Request{Type: core.RequestGetSettings}, 5*time.Second))
	if err != nil {
		return nil, err
	}
	return r.Settings, nil
}

// SaveSettings 返回完整响应：设置已保存但规则没生效时 ok=false 且带回新设置，前端据此回填
func (u *UIService) SaveSettings(ctx context.Context, s core.GuardSettings) (*core.IpcResponse, error) {
	return call(ctx, core.Request{Type: core.RequestUpdateSettings, Settings: &s}, 60*time.Second)
}

func (u *UIService) simple(ctx context.Context, req core.Request, timeout time.Duration) (*core.IpcResponse, error) {
	return must(call(ctx, req, timeout))
}

func (u *UIService) ImportSubscription(ctx context.Context, url string) (*core.IpcResponse, error) {
	return u.simple(ctx, core.Request{Type: core.RequestImportSubscription, URL: url}, 90*time.Second)
}
func (u *UIService) RefreshSubscription(ctx context.Context) (*core.IpcResponse, error) {
	return u.simple(ctx, core.Request{Type: core.RequestRefreshSubscription}, 90*time.Second)
}
func (u *UIService) RemoveSubscription(ctx context.Context) (*core.IpcResponse, error) {
	return u.simple(ctx, core.Request{Type: core.RequestRemoveSubscription}, 60*time.Second)
}
func (u *UIService) TripFuse(ctx context.Context) (*core.IpcResponse, error) {
	return u.simple(ctx, core.Request{Type: core.RequestTripFuse}, 10*time.Second)
}
func (u *UIService) RestoreNetwork(ctx context.Context, force bool) (*core.IpcResponse, error) {
	return u.simple(ctx, core.Request{Type: core.RequestRestoreNetwork, Force: force}, 10*time.Second)
}
func (u *UIService) CaptiveLogin(ctx context.Context, minutes int) (*core.IpcResponse, error) {
	return u.simple(ctx, core.Request{Type: core.RequestCaptiveLogin, Minutes: minutes}, 60*time.Second)
}
func (u *UIService) EndCaptiveLogin(ctx context.Context) (*core.IpcResponse, error) {
	return u.simple(ctx, core.Request{Type: core.RequestEndCaptiveLogin}, 60*time.Second)
}
func (u *UIService) RestartCore(ctx context.Context) (*core.IpcResponse, error) {
	return u.simple(ctx, core.Request{Type: core.RequestRestartCore}, 90*time.Second)
}
func (u *UIService) FlushConnections(ctx context.Context) (*core.IpcResponse, error) {
	return u.simple(ctx, core.Request{Type: core.RequestFlushConnections}, 10*time.Second)
}
func (u *UIService) ClearEvents(ctx context.Context) (*core.IpcResponse, error) {
	return u.simple(ctx, core.Request{Type: core.RequestClearEvents}, 10*time.Second)
}

// EventsView 对应 Kotlin 的 events 响应
type EventsView struct {
	Events     []core.GuardEvent `json:"events"`
	Generation string            `json:"eventsGeneration"`
}

func (u *UIService) Events(ctx context.Context, after int) (*EventsView, error) {
	r, err := must(call(ctx, core.Request{Type: core.RequestEvents, After: after}, 5*time.Second))
	if err != nil {
		return nil, err
	}
	v := &EventsView{}
	if r.Events != nil {
		v.Events = *r.Events
	}
	if r.EventsGeneration != nil {
		v.Generation = *r.EventsGeneration
	}
	return v, nil
}

// controller 取得 mihomo 控制接口；密钥变化（服务重装）时重建客户端
func (u *UIService) controller(ctx context.Context) (*core.MihomoApi, error) {
	r, err := must(call(ctx, core.Request{Type: core.RequestControllerInfo}, 3*time.Second))
	if err != nil {
		return nil, err
	}
	if r.Controller == nil {
		return nil, errors.New("防护服务没有返回内核控制信息")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.api == nil || u.apiSecret != r.Controller.Secret {
		u.api = core.NewMihomoApi(r.Controller.BaseURL, r.Controller.Secret)
		u.apiSecret = r.Controller.Secret
	}
	return u.api, nil
}

type NodeView struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Delay *int   `json:"delay"`
	Alive *bool  `json:"alive"`
}

type NodesView struct {
	Selected string     `json:"selected"`
	Resolved string     `json:"resolved"`
	Items    []NodeView `json:"items"`
}

const proxyGroup = "节点选择"
const autoGroup = "自动选择"
const probeURL = "http://cp.cloudflare.com/generate_204"

func (u *UIService) Nodes(ctx context.Context) (*NodesView, error) {
	api, err := u.controller(ctx)
	if err != nil {
		return nil, err
	}
	all, ok := api.Proxies(ctx)
	if !ok {
		return nil, errors.New("读取节点失败：内核没有响应")
	}
	g, ok := all[proxyGroup]
	if !ok {
		return &NodesView{}, nil
	}
	v := &NodesView{}
	if g.Now != nil {
		v.Selected = *g.Now
		if *g.Now == autoGroup {
			if a, ok := all[autoGroup]; ok && a.Now != nil {
				v.Resolved = *a.Now
			}
		}
	}
	for _, name := range g.All {
		p := all[name]
		n := NodeView{Name: name, Type: p.Type, Delay: p.LastDelay}
		if p.Tested {
			alive := p.Alive
			n.Alive = &alive
		}
		if name == autoGroup {
			n.Type = "自动（只在失效时换线）"
		}
		v.Items = append(v.Items, n)
	}
	return v, nil
}

func (u *UIService) SelectNode(ctx context.Context, name string) error {
	api, err := u.controller(ctx)
	if err != nil {
		return err
	}
	if !api.Select(ctx, proxyGroup, name) {
		return errors.New("切换节点失败")
	}
	// 换线后旧连接仍挂在旧节点上，断开让应用重连到新节点
	api.FlushConnections(ctx)
	return nil
}

func (u *UIService) TestDelays(ctx context.Context) error {
	api, err := u.controller(ctx)
	if err != nil {
		return err
	}
	if _, ok := api.GroupDelay(ctx, proxyGroup, probeURL, 3000); !ok {
		return errors.New("测速失败：内核没有响应")
	}
	return nil
}

type ConnView struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Destination string `json:"destination"`
	Network     string `json:"network"`
	Chain       string `json:"chain"`
	Rule        string `json:"rule"`
	Upload      int64  `json:"upload"`
	Download    int64  `json:"download"`
	Start       *int64 `json:"start"`
	Route       string `json:"route"`
}

type ConnsView struct {
	Connections   []ConnView `json:"connections"`
	UploadTotal   int64      `json:"uploadTotal"`
	DownloadTotal int64      `json:"downloadTotal"`
}

func (u *UIService) Connections(ctx context.Context) (*ConnsView, error) {
	api, err := u.controller(ctx)
	if err != nil {
		return nil, err
	}
	snap, ok := api.Connections(ctx)
	if !ok || snap == nil {
		return nil, errors.New("读取连接失败：内核没有响应")
	}
	v := &ConnsView{UploadTotal: snap.UploadTotal, DownloadTotal: snap.DownloadTotal}
	for _, c := range snap.Connections {
		v.Connections = append(v.Connections, ConnView{ID: c.ID, Host: c.Host, Destination: c.Destination, Network: c.Network,
			Chain: c.Chain, Rule: c.Rule, Upload: c.Upload, Download: c.Download, Start: c.Start, Route: string(c.Route())})
	}
	// 新连接在前
	sort.SliceStable(v.Connections, func(i, j int) bool {
		a, b := v.Connections[i].Start, v.Connections[j].Start
		return a != nil && (b == nil || *a > *b)
	})
	return v, nil
}

func (u *UIService) CloseConnection(ctx context.Context, id string) error {
	api, err := u.controller(ctx)
	if err != nil {
		return err
	}
	if !api.CloseConnection(ctx, id) {
		return errors.New("断开失败")
	}
	return nil
}

func (u *UIService) Autostart() (bool, error) {
	st, err := u.app.Autostart.Status()
	if err != nil {
		return false, err
	}
	return st.Enabled, nil
}

func (u *UIService) SetAutostart(on bool) error {
	if on {
		return u.app.Autostart.EnableWithOptions(autostartOptions)
	}
	return u.app.Autostart.Disable()
}

func (u *UIService) OpenLogs() error {
	dir := filepath.Join(install.DataDir(), "logs")
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"), dir)
	return cmd.Start()
}

// InstallService 用 UAC 提权运行安装包里的 aiguard-service.exe install，成功后从安装目录重新打开界面
func (u *UIService) InstallService(ctx context.Context) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	src := filepath.Dir(exe)
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	code, err := runElevated(filepath.Join(src, "aiguard-service.exe"),
		fmt.Sprintf(`install --src "%s" --user-sid %s`, src, sid), src)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("安装失败（退出码 %d），详情见 %s", code, filepath.Join(install.DataDir(), "logs", "install.log"))
	}
	target := filepath.Join(install.ProgramDir(), "AIGuard.exe")
	if !strings.EqualFold(filepath.Clean(exe), filepath.Clean(target)) {
		// 管道只认安装目录里的界面，从解压目录启动的这份界面必须换过去
		if err := exec.Command(target, "--after-install").Start(); err == nil {
			go func() {
				time.Sleep(500 * time.Millisecond)
				u.app.Quit()
			}()
		}
	}
	return nil
}

func (u *UIService) UninstallService(ctx context.Context, purge bool) error {
	args := "uninstall"
	if purge {
		args += " --purge"
	}
	code, err := runElevated(filepath.Join(install.ProgramDir(), "aiguard-service.exe"), args, install.ProgramDir())
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("卸载失败（退出码 %d）", code)
	}
	u.app.Autostart.Disable()
	go func() {
		time.Sleep(300 * time.Millisecond)
		u.app.Quit()
	}()
	return nil
}

func currentUserSID() (string, error) {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// shellExecuteInfo 对应 SHELLEXECUTEINFOW（x/sys 没有提供）；Go 的字段对齐与 C 在 64 位下一致
type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           windows.Handle
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       windows.Handle
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      windows.Handle
	dwHotKey       uint32
	hIconOrMonitor windows.Handle
	hProcess       windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
)

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// runElevated 通过 ShellExecuteEx("runas") 弹出 UAC 并等待结束，返回退出码
func runElevated(exe, args, dir string) (uint32, error) {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	wd, _ := windows.UTF16PtrFromString(dir)
	info := &shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		lpDirectory:  wd,
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(*info))
	ok, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(info)))
	if ok == 0 {
		if errors.Is(callErr, windows.ERROR_CANCELLED) {
			return 0, errors.New("已取消：需要在用户账户控制窗口里允许")
		}
		return 0, fmt.Errorf("无法提权运行：%w", callErr)
	}
	if info.hProcess == 0 {
		return 0, errors.New("无法等待安装进程")
	}
	defer windows.CloseHandle(info.hProcess)
	if _, err := windows.WaitForSingleObject(info.hProcess, 10*60*1000); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return 0, err
	}
	return code, nil
}
