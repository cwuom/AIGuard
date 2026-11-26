import Foundation

/// 熔断时识别 AI 进程的纯逻辑（守护进程负责枚举和发信号）
public enum ProcessMatch {
    /// AI 关键词：匹配可执行文件路径、进程名和命令行参数（不区分大小写）。
    /// 命令行参数能抓到 node/python 跑的 CLI 和编辑器插件（如 claude-code、copilot 语言服务）
    public static let aiKeywords = [
        "claude", "anthropic", "chatgpt", "openai", "codex", "cursor", "windsurf", "codeium", "perplexity",
        "copilot", "gemini", "cherrystudio", "cherry studio", "chatbox", "opencode", "trae", "kiro", "grok",
        "ollama", "lmstudio", "lm studio", "aider", "cline", "roo-cline", "kilocode", "continue.continue",
        "tabnine", "augment", "jetbrains-ai", "grazie", "deepseek", "kimi", "moonshot", "poe.app", "mistral",
        "huggingface", "comet.app", "chatgpt atlas", "msty", "jan.app",
    ]
    /// 这些位置都是系统自带进程（例如 /System 下的 CursorUIViewService），关键词撞上也不能杀。
    /// /usr/bin、/bin 不在内：python3、zsh 这类解释器跑 AI CLI 时要靠参数识别并关掉
    public static let protectedPrefixes = ["/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/Library/Apple/",
                                           "/Library/PrivilegedHelperTools/", "/Applications/AIGuard.app/"]

    public static func isProtected(path: String) -> Bool {
        protectedPrefixes.contains(where: path.hasPrefix)
    }

    /// 关键词按「完整词」匹配：前后不能是字母或数字。
    /// 这样 Claude.app、claude-code、github.copilot-chat 能命中，decline、traefik 不会误中 cline、trae
    public static func isAI(_ text: String) -> Bool {
        let t = text.lowercased()
        for k in aiKeywords {
            var searchStart = t.startIndex
            while let r = t.range(of: k, range: searchStart..<t.endIndex) {
                let beforeOK = r.lowerBound == t.startIndex || !isWordChar(t[t.index(before: r.lowerBound)])
                let afterOK = r.upperBound == t.endIndex || !isWordChar(t[r.upperBound])
                if beforeOK && afterOK { return true }
                searchStart = t.index(after: r.lowerBound)
            }
        }
        return false
    }

    private static func isWordChar(_ c: Character) -> Bool { c.isLetter || c.isNumber }

    /// 解释器只看它实际运行的脚本/模块，不看普通文件参数（vim ~/.claude/x 不算 AI 进程）
    static let interpreters: Set<String> = ["node", "python", "python3", "bun", "deno", "ruby", "java", "uv", "uvx", "npx", "pnpm"]

    public static func isInterpreter(_ execName: String) -> Bool {
        let n = execName.lowercased()
        return interpreters.contains(n) || n.hasPrefix("python3.") || n.hasPrefix("node")
    }

    /// argv 是 parseArgumentList 的结果。返回解释器真正执行的入口（脚本路径或 -m 模块名）
    public static func entryPoint(of argv: [String]) -> String? {
        var i = 1
        while i < argv.count {
            let a = argv[i]
            if a == "-m" || a == "-c" { return i + 1 < argv.count ? argv[i + 1] : nil }
            if !a.hasPrefix("-") { return a }
            i += 1
        }
        return nil
    }

    /// 是否 AIGuard 自身（任何安装位置的界面都不能被关）
    public static func isSelf(path: String) -> Bool {
        path.contains("/AIGuard.app/")
    }

    /// 格式：Int32 argc | exec 路径 \0 | 若干 \0 填充 | argv[0] \0 ... argv[argc-1] \0 | 环境变量...
    public static func parseArguments(_ buf: [UInt8]) -> String {
        parseArgumentList(buf).joined(separator: " ")
    }

    public static func parseArgumentList(_ buf: [UInt8]) -> [String] {
        let intSize = MemoryLayout<Int32>.size
        guard buf.count > intSize else { return [] }
        let argc = buf[0..<intSize].withUnsafeBytes { Int($0.loadUnaligned(as: Int32.self)) }
        guard argc > 0, argc < 4096 else { return [] }
        var i = intSize
        while i < buf.count, buf[i] != 0 { i += 1 }   // 跳过 exec 路径
        while i < buf.count, buf[i] == 0 { i += 1 }   // 跳过填充
        var args: [String] = []
        while i < buf.count, args.count < argc {
            let start = i
            while i < buf.count, buf[i] != 0 { i += 1 }
            args.append(String(decoding: buf[start..<i], as: UTF8.self))
            i += 1
        }
        return args
    }

}
