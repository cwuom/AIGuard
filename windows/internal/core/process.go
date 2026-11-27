package core

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

var AIKeywords = []string{
	"claude", "anthropic", "chatgpt", "openai", "codex", "cursor", "windsurf", "codeium", "perplexity",
	"copilot", "gemini", "cherrystudio", "cherry studio", "chatbox", "opencode", "trae", "kiro", "grok",
	"ollama", "lmstudio", "lm studio", "aider", "cline", "roo-cline", "kilocode", "continue.continue",
	"tabnine", "augment", "jetbrains-ai", "grazie", "deepseek", "kimi", "moonshot", "poe.app", "mistral",
	"huggingface", "comet.app", "chatgpt atlas", "msty", "jan.app",
}

func IsAI(text string) bool {
	t := strings.ToLower(text)
	word := func(c rune) bool { return unicode.IsLetter(c) || unicode.IsNumber(c) }
	for _, keyword := range AIKeywords {
		from := 0
		for {
			i := strings.Index(t[from:], keyword)
			if i < 0 {
				break
			}
			i += from
			before, _ := utf8.DecodeLastRuneInString(t[:i])
			after, _ := utf8.DecodeRuneInString(t[i+len(keyword):])
			if !word(before) && !word(after) {
				return true
			}
			from = i + 1
		}
	}
	return false
}

func SplitCommandLine(cmd string) []string {
	cmd, _, _ = strings.Cut(cmd, "\x00")
	if cmd == "" {
		// an empty command line supplies no executable path to this parser
		return nil
	}
	blank := func(b byte) bool { return b == ' ' || b == '\t' }
	// argv[0] is a program path, so a backslash never escapes its closing quote
	i := 0
	var program string
	if cmd[0] == '"' {
		i++
		for i < len(cmd) && cmd[i] != '"' {
			i++
		}
		program = cmd[1:i]
		if i < len(cmd) {
			i++
		}
	} else {
		for i < len(cmd) && !blank(cmd[i]) {
			i++
		}
		program = cmd[:i]
	}
	args := []string{program}
	for i < len(cmd) {
		if blank(cmd[i]) {
			i++
			continue
		}
		var arg strings.Builder
		inQuotes := false
		for i < len(cmd) && (inQuotes || !blank(cmd[i])) {
			start := i
			for i < len(cmd) && cmd[i] == '\\' {
				i++
			}
			count := i - start
			if i == len(cmd) || cmd[i] != '"' {
				arg.WriteString(cmd[start:i])
				if i < len(cmd) && (inQuotes || !blank(cmd[i])) {
					arg.WriteByte(cmd[i])
					i++
				}
				continue
			}
			arg.WriteString(cmd[start : start+count/2])
			i++
			switch {
			case count%2 == 1:
				arg.WriteByte('"')
			case inQuotes && i < len(cmd) && cmd[i] == '"':
				arg.WriteByte('"')
				i++
			default:
				inQuotes = !inQuotes
			}
		}
		args = append(args, arg.String())
	}
	return args
}

func ExeBaseName(path string) string {
	return strings.ToLower(path[strings.LastIndexAny(path, `\/`)+1:])
}

func IsInterpreter(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".exe")
	switch name {
	case "node", "python", "python3", "pythonw", "py", "bun", "deno", "ruby", "java", "javaw", "uv", "uvx", "npx", "pnpm":
		return true
	default:
		return strings.HasPrefix(name, "python3.") || strings.HasPrefix(name, "node")
	}
}

func EntryPoint(argv []string) string {
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "-m" || arg == "-c" {
			if i+1 < len(argv) {
				return argv[i+1]
			}
			return ""
		}
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
	}
	return ""
}

func directoryPrefix(path, dir string) (int, bool) {
	dir = strings.TrimRight(strings.ReplaceAll(dir, "/", `\`), `\`)
	if dir == "" {
		return 0, false
	}
	normalized := strings.ReplaceAll(path, "/", `\`)
	if strings.EqualFold(normalized, dir) {
		return len(path), true
	}
	// compare at separator boundaries and keep the byte offset in the original path
	for i, c := range normalized {
		if c == '\\' && strings.EqualFold(normalized[:i], dir) {
			return i, true
		}
	}
	return 0, false
}

func StripProfile(path string, profiles []string) string {
	for _, dir := range profiles {
		if n, ok := directoryPrefix(path, dir); ok {
			if n < len(path) && strings.ContainsAny(dir[len(dir)-1:], `\/`) {
				n++
			}
			return path[n:]
		}
	}
	return path
}

var protectedProcesses = map[string]bool{
	"system": true, "registry": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true,
	"winlogon.exe": true, "services.exe": true, "lsass.exe": true, "svchost.exe": true, "dwm.exe": true,
	"explorer.exe": true, "sihost.exe": true, "fontdrvhost.exe": true, "ctfmon.exe": true,
	"msmpeng.exe": true, "nissrv.exe": true, "securityhealthservice.exe": true, "msedgewebview2.exe": true,
	"aiguard.exe": true, "aiguard-service.exe": true, "mihomo.exe": true,
}

func IsProtected(exePath, systemRoot, installDir string) bool {
	if protectedProcesses[ExeBaseName(exePath)] {
		return true
	}
	_, inSystem := directoryPrefix(exePath, systemRoot)
	_, inInstall := directoryPrefix(exePath, installDir)
	return inSystem || inInstall
}

func IsAIProcess(exePath, cmdline string, profiles []string, systemRoot, installDir string, extra []string) bool {
	name := ExeBaseName(exePath)
	if name == "msedgewebview2.exe" {
		argv := SplitCommandLine(cmdline)
		for i := 1; i < len(argv); i++ {
			if host, ok := strings.CutPrefix(argv[i], "--webview-exe-name="); ok {
				host = strings.TrimSuffix(ExeBaseName(host), ".exe")
				if IsAI(host) || slices.Contains(CleanProcessNames(extra), host+".exe") {
					return true
				}
			}
		}
		return false
	}
	if IsProtected(exePath, systemRoot, installDir) {
		return false
	}
	if slices.Contains(CleanProcessNames(extra), name) {
		return true
	}
	if IsInterpreter(name) {
		entry := EntryPoint(SplitCommandLine(cmdline))
		return entry != "" && (IsAI(ExeBaseName(entry)) || IsAI(StripProfile(entry, profiles)))
	}
	return IsAI(StripProfile(exePath, profiles))
}

var BrowserProcesses = map[string]bool{
	"chrome.exe": true, "msedge.exe": true, "firefox.exe": true, "brave.exe": true, "opera.exe": true,
	"vivaldi.exe": true, "arc.exe": true, "chromium.exe": true, "thorium.exe": true, "iexplore.exe": true,
	"waterfox.exe": true, "librewolf.exe": true, "floorp.exe": true, "zen.exe": true, "comet.exe": true,
	"dia.exe": true, "360se.exe": true, "360chrome.exe": true, "qqbrowser.exe": true, "sogouexplorer.exe": true,
	"ucbrowser.exe": true, "maxthon.exe": true, "2345explorer.exe": true, "liebao.exe": true, "quark.exe": true,
	"yandex.exe": true,
}

// apply IsProtected with the service's directories before selecting browsers
func IsBrowser(exePath string) bool {
	return !IsProtected(exePath, "", "") && BrowserProcesses[ExeBaseName(exePath)]
}
