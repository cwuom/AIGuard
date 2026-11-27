//go:build windows

// AIGuard.exe：托盘常驻的界面。防护本身在系统服务里，界面退出不影响防护
package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"aiguard/internal/core"
	"aiguard/internal/install"
	"aiguard/internal/version"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"golang.org/x/sys/windows/registry"
)

//go:embed frontend
var frontend embed.FS

//go:embed assets/tray.ico
var trayIcon []byte

// Windows 11 22H2（22621）起才有系统 Mica 背景；更早的系统用实色背景
func supportsMica() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	build, _, err := k.GetStringValue("CurrentBuildNumber")
	if err != nil {
		return false
	}
	n := 0
	for _, c := range build {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n >= 22621
}

// relaunchInstalled 两秒后启动安装目录里的界面（等当前实例退出、释放单实例锁）
func relaunchInstalled() {
	target := filepath.Join(install.ProgramDir(), "AIGuard.exe")
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`), "/C",
		`ping -n 3 127.0.0.1 >NUL & start "" "`+target+`" --after-install`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	cmd.Start()
}

// 登录时只放托盘，不弹窗口
var autostartOptions = application.AutostartOptions{Arguments: []string{"--hidden"}}

func main() {
	assets, err := fs.Sub(frontend, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	// 从解压目录打开、而安装目录里已有不旧于自己的界面时，直接换成已安装的那份（控制管道只认它）
	if !runningFromProgramFiles() {
		if iv := install.InstalledVersion(); iv != "" && core.CompareVersions(iv, version.Version) >= 0 {
			if err := exec.Command(filepath.Join(install.ProgramDir(), "AIGuard.exe")).Start(); err == nil {
				return
			}
		}
	}
	ui := &UIService{}
	var window *application.WebviewWindow

	app := application.New(application.Options{
		Name:        "AI 出差管家",
		Description: "AIGuard",
		Services:    []application.Service{application.NewService(ui)},
		Assets:      application.AssetOptions{Handler: http.FileServerFS(assets)},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "com.aiguard.windows.ui",
			OnSecondInstanceLaunch: func(d application.SecondInstanceData) {
				// 升级后新界面被单实例挡住：旧界面让位，稍后由 cmd 重新拉起安装目录里的新版
				if slices.Contains(d.Args, "--after-install") && core.CompareVersions(install.InstalledVersion(), version.Version) > 0 {
					relaunchInstalled()
					application.Get().Quit()
					return
				}
				if window != nil {
					window.Show()
					window.Restore()
					window.Focus()
				}
			},
		},
		Windows: application.WindowsOptions{DisableQuitOnLastWindowClosed: true},
	})
	ui.app = app

	mica := supportsMica()
	opts := application.WebviewWindowOptions{
		Name:      "main",
		Title:     "AI 出差管家",
		Width:     1120,
		Height:    760,
		MinWidth:  720,
		MinHeight: 520,
		URL:       "/",
		// 开机自启时只放托盘，不弹窗口
		Hidden: slices.Contains(os.Args[1:], "--hidden"),
		Windows: application.WindowsWindow{
			Theme: application.SystemDefault,
		},
	}
	if mica {
		opts.BackgroundType = application.BackgroundTypeTranslucent
		opts.Windows.BackdropType = application.Mica
	} else {
		opts.BackgroundColour = application.NewRGB(0xf3, 0xf3, 0xf3)
	}
	window = app.Window.NewWithOptions(opts)
	if !mica {
		window.OnWindowEvent(events.Common.WindowRuntimeReady, func(*application.WindowEvent) {
			app.Event.Emit("aiguard:no-mica")
		})
	}
	// 关闭窗口只是收进托盘，防护照常；退出界面走托盘菜单
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		window.Hide()
		e.Cancel()
	})

	tray := app.SystemTray.New()
	tray.SetIcon(trayIcon)
	tray.SetTooltip("AI 出差管家")
	show := func(page string) {
		window.Show()
		window.Restore()
		window.Focus()
		if page != "" {
			app.Event.Emit("aiguard:show", page)
		}
	}
	tray.OnClick(func() { show("") })

	menu := app.NewMenu()
	statusItem := menu.Add("正在连接防护服务…").SetEnabled(false)
	menu.AddSeparator()
	menu.Add("打开主窗口").OnClick(func(*application.Context) { show("") })
	tripItem := menu.Add("立即熔断").OnClick(func(*application.Context) {
		go ui.TripFuse(context.Background())
	})
	restoreItem := menu.Add("重新验证并恢复").OnClick(func(*application.Context) {
		go ui.RestoreNetwork(context.Background(), false)
	})
	menu.Add("酒店 Wi-Fi 登录（5 分钟）").OnClick(func(*application.Context) {
		go ui.CaptiveLogin(context.Background(), 5)
	})
	gameItem := menu.AddCheckbox("游戏模式（手动开启）", false)
	gameItem.OnClick(func(c *application.Context) {
		on := c.IsChecked()
		go ui.SetGameMode(context.Background(), on)
	})
	menu.Add("事件").OnClick(func(*application.Context) { show("events") })
	menu.AddSeparator()
	menu.Add("退出界面（防护继续）").OnClick(func(*application.Context) { app.Quit() })
	tray.SetMenu(menu)

	// 托盘提示与菜单跟随状态（State 由前端每秒调用；窗口隐藏时 WebView 也照常运行）
	lastPhase := ""
	ui.onStatus = func(st *core.GuardStatus) {
		phase := "offline"
		if st != nil {
			phase = string(st.Phase)
			if st.GameMode {
				phase += "+game"
				if st.GameReason != nil && *st.GameReason == core.GameReasonManual {
					phase += "+manual"
				}
			}
		}
		if phase == lastPhase {
			return
		}
		lastPhase = phase
		manual := strings.HasSuffix(phase, "+manual")
		phase = strings.TrimSuffix(phase, "+manual")
		game := strings.HasSuffix(phase, "+game")
		phase = strings.TrimSuffix(phase, "+game")
		text := map[string]string{
			"protected": "已受保护",
			"tripped":   "已熔断",
			"starting":  "正在启动保护",
			"disabled":  "守护已关闭",
			"error":     "防护异常",
			"offline":   "防护服务未运行",
		}[phase]
		if game {
			text += " · 游戏模式"
		}
		application.InvokeAsync(func() {
			gameItem.SetChecked(manual)
			gameItem.SetEnabled(phase != "offline" && phase != "disabled")
			statusItem.SetLabel(text)
			tray.SetTooltip("AI 出差管家：" + text)
			tripItem.SetEnabled(phase == "protected" || phase == "starting" || phase == "error")
			restoreItem.SetEnabled(phase == "tripped")
			menu.Update()
		})
	}

	// 从安装目录第一次运行（安装完成后）默认开启登录时启动，与 macOS 版一致
	if runningFromProgramFiles() && slices.Contains(os.Args[1:], "--after-install") {
		go func() {
			time.Sleep(time.Second)
			if st, err := app.Autostart.Status(); err == nil && !st.Enabled {
				app.Autostart.EnableWithOptions(autostartOptions)
			}
		}()
	}
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
