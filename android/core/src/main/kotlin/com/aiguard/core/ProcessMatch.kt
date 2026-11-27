package com.aiguard.core

/** 熔断时识别 AI App、浏览器与 AI 命令行进程的纯逻辑（守护进程负责枚举和执行） */
object ProcessMatch {
    /** AI 关键词，按「完整词」匹配包名和命令行：com.anthropic.claude 能命中，decline、traefik 不会误中 cline、trae */
    val aiKeywords = listOf(
        "claude", "anthropic", "chatgpt", "openai", "codex", "cursor", "windsurf", "codeium", "perplexity",
        "copilot", "gemini", "cherrystudio", "chatbox", "opencode", "trae", "kiro", "grok",
        "ollama", "lmstudio", "aider", "cline", "kilocode", "tabnine", "augment", "grazie", "deepseek",
        "kimi", "moonshot", "mistral", "huggingface", "msty", "bard",
    )

    /** 包名里看不出 AI 的主流 AI App */
    val knownAIPackages = setOf(
        "com.google.android.apps.bard", "com.google.android.apps.labs.language.tailwind", "com.microsoft.copilot",
        "ai.perplexity.app.android", "ai.x.grok", "com.quora.poe", "ai.character.app", "com.deepseek.chat",
        "com.moonshot.kimichat", "ai.mistral.chat", "com.microsoft.bing", "com.github.android",
        "com.cherry.studio", "ai.lmstudio", "com.openai.sora",
    )

    /** 熔断瞬间一并关闭的浏览器（含 Google App：Gemini 内嵌其中） */
    val browserPackages = setOf(
        "com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary", "org.chromium.chrome",
        "com.google.android.googlequicksearchbox", "org.mozilla.firefox", "org.mozilla.firefox_beta",
        "org.mozilla.fenix", "org.mozilla.focus", "com.microsoft.emmx", "com.brave.browser", "com.opera.browser",
        "com.opera.mini.native", "com.opera.gx", "com.vivaldi.browser", "com.kiwibrowser.browser",
        "com.duckduckgo.mobile.android", "com.sec.android.app.sbrowser", "com.heytap.browser", "com.coloros.browser",
        "com.oneplus.browser", "com.android.browser", "com.mi.globalbrowser", "com.huawei.browser", "com.vivo.browser",
        "com.UCMobile", "com.UCMobile.intl", "com.tencent.mtt", "com.quark.browser", "mark.via", "mark.via.gp",
        "com.mmbox.xbrowser", "org.bromite.bromite", "app.vanadium.browser", "com.yandex.browser",
        "ai.perplexity.comet", "com.openai.atlas",
    )

    /** 系统核心组件：即使关键词撞上也绝不能停（停了会掉推送、掉网络或整机重启） */
    val protectedPackages = setOf(
        "android", "com.android.systemui", "com.android.phone", "com.android.settings", "com.android.shell",
        "com.google.android.gms", "com.google.android.gsf", "com.android.vending", "com.android.networkstack",
        "com.google.android.networkstack", "com.android.providers.settings", "com.termux",
    )

    fun isAI(text: String): Boolean {
        val t = text.lowercase()
        for (k in aiKeywords) {
            var from = 0
            while (true) {
                val i = t.indexOf(k, from)
                if (i < 0) break
                val beforeOK = i == 0 || !t[i - 1].isLetterOrDigit()
                val end = i + k.length
                val afterOK = end == t.length || !t[end].isLetterOrDigit()
                if (beforeOK && afterOK) return true
                from = i + 1
            }
        }
        return false
    }

    /** 熔断时要强行停止的已安装 App */
    fun targetPackages(installed: Collection<String>, extra: Collection<String>, includeBrowsers: Boolean, self: String): Set<String> {
        val wanted = extra.toSet()
        return installed.filter { p ->
            p != self && p !in protectedPackages &&
                (p in knownAIPackages || p in wanted || isAI(p) || (includeBrowsers && p in browserPackages))
        }.toSet()
    }

    /** 解释器只看它实际运行的脚本/模块，不看普通文件参数（vim ~/.claude/x 不算 AI 进程） */
    private val interpreters = setOf("node", "python", "python3", "bun", "deno", "ruby", "java", "uv", "uvx", "npx", "pnpm")

    fun isInterpreter(execName: String): Boolean {
        val n = execName.lowercase()
        return n in interpreters || n.startsWith("python3.") || n.startsWith("node")
    }

    /** 返回解释器真正执行的入口（脚本路径或 -m 模块名） */
    fun entryPoint(argv: List<String>): String? {
        var i = 1
        while (i < argv.size) {
            val a = argv[i]
            if (a == "-m" || a == "-c") return argv.getOrNull(i + 1)
            if (!a.startsWith("-")) return a
            i++
        }
        return null
    }

    /** /proc/<pid>/cmdline 以 \0 分隔 */
    fun parseCmdline(raw: ByteArray): List<String> =
        String(raw, Charsets.UTF_8).split('\u0000').filter { it.isNotEmpty() }

    /**
     * 普通 App 进程里跑的 AI 命令行（例如 Termux 里的 node claude、python -m aider）。
     * App 主进程的 cmdline 是包名，交给按包名停止处理，这里只认解释器
     */
    fun isAICommandLine(argv: List<String>): Boolean {
        val argv0 = argv.firstOrNull() ?: return false
        // App 进程（包名或 包名:子进程），保护名单由按包名停止的逻辑把关
        if ('/' !in argv0 && '.' in argv0) return false
        val exe = argv0.substringAfterLast('/')
        if (isInterpreter(exe)) {
            val entry = entryPoint(argv) ?: return false
            return isAI(entry.substringAfterLast('/')) || isAI(entry)
        }
        // 直接运行的二进制（codex、claude 原生版）看可执行文件名
        return isAI(exe)
    }
}
