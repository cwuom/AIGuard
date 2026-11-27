package core

import (
	"strings"
	"testing"
)

func TestAIKeywordsMatchWholeWords(t *testing.T) {
	for _, s := range []string{
		"com.anthropic.claude", "com.openai.chatgpt", "github.copilot-chat", "claude-code", "/data/x/bin/codex",
		"Cherry Studio.exe", "LM Studio.exe", "roo-cline", "continue.continue", "jetbrains-ai",
		"poe.app", "comet.app", "ChatGPT Atlas", "jan.app", "田 Claude！", "claudex / CLAUDE",
	} {
		check(t, IsAI(s), s)
	}
	for _, s := range []string{
		"decline", "traefik", "com.example.augmented", "com.android.chrome", "中文claude", "claude９", "аcopilot",
		"bard", "xpoe.app", "jan.app2", "openaiⅣ",
	} {
		check(t, !IsAI(s), s)
	}
}

func TestTargetPackagesRespectProtectionAndBrowsers(t *testing.T) {
	type process struct {
		path, cmd string
	}
	procs := []process{
		{`C:\Users\me\Programs\Claude.exe`, ""},
		{`C:\Users\me\Programs\ChatGPT.exe`, ""},
		{`C:\Program Files\Google\Chrome\CHROME.EXE`, ""},
		{`c:\WiNdOwS\OpenAI.exe`, ""},
		{`C:\Program Files\AIGuard\claude.exe`, ""},
		{`C:\Apps\ChatGPT\services.exe`, ""},
		{`C:\Apps\WeChat.exe`, ""},
		{`C:\Apps\My AI.EXE`, ""},
		{`C:\Windows\chrome.exe`, ""},
		{`C:\Program Files\AIGuard\msedge.exe`, ""},
	}
	all := func(includeBrowsers bool, extra []string) []int {
		var matches []int
		for i, p := range procs {
			protected := IsProtected(p.path, `C:\Windows`, `C:\Program Files\AIGuard`)
			if IsAIProcess(p.path, p.cmd, nil, `C:\Windows`, `C:\Program Files\AIGuard`, extra) ||
				(includeBrowsers && !protected && IsBrowser(p.path)) {
				matches = append(matches, i)
			}
		}
		return matches
	}
	want(t, all(true, []string{" My AI "}), []int{0, 1, 2, 7})
	want(t, all(false, nil), []int{0, 1})
}

func TestCommandLinesOnlyMatchRealEntryPoints(t *testing.T) {
	for _, tc := range []struct {
		name, exe, cmd string
		match          bool
	}{
		{"node-claude", `C:\Program Files\nodejs\node.exe`, `"C:\Program Files\nodejs\node.exe" "C:\Users\a\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js" --x`, true},
		{"python-module", `C:\Programs\python3.exe`, `python3.exe -m aider`, true},
		{"native", `C:\Tools\codex.exe`, `codex.exe exec`, true},
		{"editor", `C:\Tools\vim.exe`, `vim.exe C:\Users\a\.claude\x`, false},
		{"node-ordinary-script", `C:\Tools\node.exe`, `node.exe server.js --claude`, false},
		{"no-entry", `C:\cursor\node.exe`, `node.exe -q -m`, false},
		{"no-own-path", `C:\cursor\node.exe`, `node.exe plain.js`, false},
		{"python-code", `C:\Tools\pythonw.exe`, `pythonw.exe -q -c "import anthropic"`, true},
		{"profile-only", `C:\Tools\node.exe`, `node.exe C:/Users/CLAUDE/server.js`, false},
		{"different-profile", `C:\Tools\node.exe`, `node.exe C:/Users/CLAUDE-2/server.js`, true},
		{"ordinary-host", `C:\Tools\app.exe`, `app.exe --webview-exe-name=Claude.exe`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want(t, IsAIProcess(tc.exe, tc.cmd, []string{`c:\users\claude\`}, `C:\Windows`, "", nil), tc.match)
		})
	}
}

func TestSplitCommandLine(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		args        []string
	}{
		{"empty", "", nil},
		{"blank", " \t  ", []string{""}},
		{"leading-blank", " \tprogram abc", []string{"", "program", "abc"}},
		{"quote-argv0", `"a b" c`, []string{"a b", "c"}},
		{"argv0-trailing-backslash", `"C:\dir\" x`, []string{`C:\dir\`, "x"}},
		{"argv0-literal-quote", `a\\\"b`, []string{`a\\\"b`}},
		{"argv0-adjacent", `"a b"c`, []string{"a b", "c"}},
		{"unterminated-argv0", `"a b`, []string{"a b"}},
		{"node-and-claude", `"C:\Program Files\nodejs\node.exe" "C:\Users\a\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js" --x`,
			[]string{`C:\Program Files\nodejs\node.exe`, `C:\Users\a\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js`, "--x"}},
		{"odd-slashes", `p a\\\"b`, []string{"p", `a\"b`}},
		{"even-slashes", `p a\\"b c" d`, []string{"p", `a\b c`, "d"}},
		{"single-slash-before-quote", `p a\"b c`, []string{"p", `a"b`, "c"}},
		{"backslashes-without-quote", `p C:\dir\\files \\server\share`, []string{"p", `C:\dir\\files`, `\\server\share`}},
		{"trailing-backslashes", `p C:\temp\\`, []string{"p", `C:\temp\\`}},
		{"trailing-slashes-in-quotes", `p "a b\\"`, []string{"p", `a b\`}},
		{"trailing-slash-unterminated", `p "a b\`, []string{"p", `a b\`}},
		{"doubled-quote-in-quotes", `p "a"" b" c`, []string{"p", `a" b`, "c"}},
		{"doubled-quote-after-even-slashes", `p "a\\"" b" c`, []string{"p", `a\" b`, "c"}},
		{"doubled-quote-after-odd-slashes", `p "a\"" b`, []string{"p", `a"`, "b"}},
		{"empty-argument", `p "" "" a`, []string{"p", "", "", "a"}},
		{"joined-segments", `p a"b c"d`, []string{"p", "ab cd"}},
		{"tab-and-unicode", "p\t\"以 太网\"\t x \t", []string{"p", "以 太网", "x"}},
		{"nul-terminates", "p x\x00hidden", []string{"p", "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) { want(t, SplitCommandLine(tc.input), tc.args) })
	}
}

func TestWindowsProcessPathsAndProtection(t *testing.T) {
	want(t, ExeBaseName(`C:\Some/Path\CURSOR.ExE`), "cursor.exe")
	want(t, ExeBaseName(`C:\Some/Path\`), "")
	want(t, StripProfile(`c:/Users/CLAUDE/bin/agent.exe`, []string{`C:\Users\claude\`}), "bin/agent.exe")
	want(t, StripProfile(`c:/Users/CLAUDE/bin/agent.exe`, []string{`C:\Users\claude`}), "/bin/agent.exe")
	want(t, StripProfile(`C:\Users\claude2\agent.exe`, []string{`C:\Users\claude`}), `C:\Users\claude2\agent.exe`)
	want(t, StripProfile(`C:\Users\CLAUDE`, []string{`C:\Users\claude`}), "")
	for _, tc := range []struct {
		path string
		safe bool
	}{
		{`c:/wINDOWS/System32/claude.exe`, true},
		{`C:\WindowsApps\codex.exe`, false},
		{`D:\aiguard dir\codex.exe`, true},
		{`D:\AIGuard Dir2\codex.exe`, false},
		{`D:\Programs\SVCHOST.EXE`, true},
		{`D:\Programs\Windows\claude.exe`, false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			want(t, IsProtected(tc.path, `C:\Windows\`, `D:\AIGuard Dir`), tc.safe)
		})
	}
	for _, name := range strings.Fields("system registry smss.exe csrss.exe wininit.exe winlogon.exe services.exe lsass.exe svchost.exe dwm.exe explorer.exe sihost.exe fontdrvhost.exe ctfmon.exe msmpeng.exe nissrv.exe securityhealthservice.exe msedgewebview2.exe aiguard.exe aiguard-service.exe mihomo.exe") {
		path := `D:\Apps\cursor\` + strings.ToUpper(name)
		check(t, IsProtected(path, "", ""), name)
		check(t, !IsAIProcess(path, "", nil, "", "", []string{name}), name)
	}
	for _, path := range []string{`C:\Users\claude\Programs\cursor\Cursor.exe`, `C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_123\ChatGPT.exe`, `C:\Bin\claude.exe`, `C:\Bin\codex.exe`} {
		check(t, IsAIProcess(path, "", []string{`C:\Users\claude`}, `C:\Windows`, "", nil), path)
	}
	check(t, !IsAIProcess(`C:\Users\claude\Programs\agent.exe`, "", []string{`C:\Users\claude`}, "", "", nil), "username alone is not evidence")
}

func TestWebViewAIHostRecognition(t *testing.T) {
	exe := `C:\Windows\Apps\msedgewebview2.exe`
	for _, tc := range []struct {
		cmd   string
		match bool
	}{
		{`"C:\Windows\Apps\msedgewebview2.exe" --webview-exe-name=Claude.exe`, true},
		{`msedgewebview2.exe --webview-exe-name="Cherry Studio.exe"`, true},
		{`msedgewebview2.exe "--webview-exe-name=Custom UI.EXE"`, true},
		{`msedgewebview2.exe --webview-exe-name=App.exe --label=chatgpt`, false},
		{`msedgewebview2.exe --webview-exe-name=App.exe "C:\Claude\data"`, false},
		{`msedgewebview2.exe --webview-exe-name=decline.exe`, false},
		{`msedgewebview2.exe --webview-exe-name Claude.exe`, false},
		{`msedgewebview2.exe`, false},
		{"", false},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			want(t, IsAIProcess(exe, tc.cmd, nil, `C:\Windows`, "", []string{"Custom UI", "msedgewebview2.exe"}), tc.match)
		})
	}
}

func TestWindowsInterpreterAndBrowserNames(t *testing.T) {
	for _, name := range strings.Fields("NODE.exe python.exe python3.exe pythonw.exe py.exe bun.exe deno.exe ruby.exe java.exe javaw.exe uv.exe uvx.exe npx.exe pnpm.exe python3.13.exe node-v22.exe") {
		want(t, IsInterpreter(name), true)
	}
	for _, name := range []string{"python2.exe", "powershell.exe", "vim.exe"} {
		want(t, IsInterpreter(name), false)
	}
	for _, name := range strings.Fields("chrome.exe msedge.exe firefox.exe brave.exe opera.exe vivaldi.exe arc.exe chromium.exe thorium.exe iexplore.exe waterfox.exe librewolf.exe floorp.exe zen.exe comet.exe dia.exe 360se.exe 360chrome.exe qqbrowser.exe sogouexplorer.exe ucbrowser.exe maxthon.exe 2345explorer.exe liebao.exe quark.exe yandex.exe") {
		want(t, IsBrowser(`C:\Program Files\Apps/`+strings.ToUpper(name)), true)
	}
	for _, name := range []string{"msedgewebview2.exe", "aiguard.exe", "chrome", "chrome.exe.tmp"} {
		want(t, IsBrowser(name), false)
	}
}
