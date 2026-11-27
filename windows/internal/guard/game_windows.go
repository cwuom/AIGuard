//go:build windows

package guard

import (
	"os"
	"path/filepath"
	"strings"

	"aiguard/internal/core"
	"aiguard/internal/winsys"
)

func (s *WindowsSystem) ScanApps(extraAI, extraGame []string) AppScan {
	var out AppScan
	procs, err := winsys.Processes(true)
	if err != nil {
		return out
	}
	if s.profiles == nil {
		s.profiles = winsys.UserProfiles()
	}
	if s.unity == nil || len(s.unity) > 4096 {
		s.unity = map[string]bool{}
	}
	extraAI, extraGame = core.CleanProcessNames(extraAI), core.CleanProcessNames(extraGame)
	seen := map[string]bool{}
	note := func(list *[]string, name string) {
		if !seen[strings.ToLower(name)] {
			seen[strings.ToLower(name)] = true
			*list = append(*list, name)
		}
	}
	for _, p := range procs {
		if p.Exe == "" {
			continue
		}
		// 只认用户会话里的游戏与加速器：加速器装的系统服务（会话 0）常驻后台，算进来会让游戏模式一直开着
		if name, acc := core.DetectGame(p.Exe, extraGame); name != "" && p.Session != 0 {
			if acc {
				note(&out.Accelerators, name)
			} else {
				note(&out.Games, name)
			}
			continue
		}
		if core.IsAIProcess(p.Exe, p.Cmdline, s.profiles, s.systemRoot, s.InstallDir, extraAI) {
			out.AIRunning = true
			// WebView2 是所有 WebView2 应用共用的运行库，按程序拉黑会连带别的应用；它由关闭进程与 TUN 里的 AI 名单兜住
			if core.ExeBaseName(p.Exe) != "msedgewebview2.exe" {
				note(&out.AI, p.Exe)
			}
			continue
		}
		if !core.IsProtected(p.Exe, s.systemRoot, s.InstallDir) && core.IsBrowser(p.Exe) {
			note(&out.Browsers, p.Exe)
			continue
		}
		if p.Session != 0 && !core.IsProtected(p.Exe, s.systemRoot, s.InstallDir) && !core.IsGameHelper(core.ExeBaseName(p.Exe)) && s.isUnityGame(p.Exe) {
			note(&out.Games, strings.TrimSuffix(p.Name, filepath.Ext(p.Name)))
		}
	}
	out.Known = knownBrowsers(s.profiles)
	return out
}

// isUnityGame：Unity 游戏的可执行文件旁边一定有 UnityPlayer.dll；Unity 编辑器与 Hub 不算
func (s *WindowsSystem) isUnityGame(exe string) bool {
	dir := strings.ToLower(filepath.Dir(exe))
	if v, ok := s.unity[dir]; ok {
		return v
	}
	_, err := os.Stat(filepath.Join(filepath.Dir(exe), "UnityPlayer.dll"))
	v := err == nil && !strings.Contains(dir, `\unity hub`) && !strings.Contains(dir, `\editor`)
	s.unity[dir] = v
	return v
}

// knownBrowsers 返回常见浏览器默认安装路径中实际存在的那些，游戏模式一开始就先拉黑
func knownBrowsers(profiles []string) []string {
	var roots []string
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		if v := os.Getenv(env); v != "" {
			roots = append(roots, v)
		}
	}
	for _, p := range profiles {
		roots = append(roots, filepath.Join(p, "AppData", "Local"))
	}
	rel := []string{
		`Google\Chrome\Application\chrome.exe`, `Microsoft\Edge\Application\msedge.exe`, `Mozilla Firefox\firefox.exe`,
		`BraveSoftware\Brave-Browser\Application\brave.exe`, `Vivaldi\Application\vivaldi.exe`, `Programs\Opera\opera.exe`,
		`Chromium\Application\chrome.exe`, `Programs\Arc\Arc.exe`,
	}
	var out []string
	for _, root := range roots {
		for _, r := range rel {
			p := filepath.Join(root, r)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				out = append(out, p)
			}
		}
	}
	return out
}
