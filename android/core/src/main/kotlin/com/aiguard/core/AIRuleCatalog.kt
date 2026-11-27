package com.aiguard.core

/**
 * 一类 AI 服务的识别规则。数据与 macOS 版 AIRuleCatalog 保持一致（由脚本机械转换），
 * 来源：v2fly/domain-list-community `category-ai-!cn`、blackmatrix7/ios_rule_script 与用户提供的 Claude 清单，按「宁可错杀」合并。
 */
data class AIRuleCategory(
    val id: String,
    val name: String,
    val note: String,
    /** 严格类会顺带覆盖一些非 AI 但与账号/风控强相关的大域名（如整个 Google） */
    val strict: Boolean,
    val suffixes: List<String>,
    val domains: List<String>,
    val keywords: List<String>,
    val regexes: List<String>,
    val ipCIDRs: List<String>,
    /** 内置的 mrs 规则集（rule-provider 名称），来自 MetaCubeX/meta-rules-dat */
    val ruleSets: List<String> = emptyList(),
    /** 直接拼目标的逻辑规则，例如按端口匹配 */
    val extraRules: List<String> = emptyList(),
) {
    val ruleCount: Int
        get() = suffixes.size + domains.size + keywords.size + regexes.size + ipCIDRs.size + ruleSets.size + extraRules.size
}

data class BundledRuleSet(val provider: String, val file: String, val behavior: String)

/** 打包进 APK 的规则集文件 */
object BundledRuleSets {
    val all = listOf(
        BundledRuleSet("cn-site", "geosite-cn.mrs", "domain"),
        BundledRuleSet("cn-ip", "geoip-cn.mrs", "ipcidr"),
        BundledRuleSet("ai-anthropic", "geosite-anthropic.mrs", "domain"),
        BundledRuleSet("ai-ntp", "geosite-category-ntp.mrs", "domain"),
    )
    val files: List<String> get() = all.map { it.file }

    /** 熔断时防火墙放行的大陆 IPv4 段 */
    const val CN_TABLE = "cn4.txt"
}

/**
 * 智能分流下也必须走代理的站点。上游 geosite:cn 混有境外站点（例如 browserleaks.com），命中后会直连并暴露大陆 IP。
 * 这里收录 IP / DNS / WebRTC 泄漏检测与指纹检测站：用户正是靠它们确认自己没有泄漏
 */
object ForceProxyCatalog {
    val suffixes = listOf(
        "browserleaks.com", "browserleaks.net", "browserleaks.org", "ipleak.net", "ipleak.org", "dnsleaktest.com",
        "dnsleak.com", "bash.ws", "whoer.net", "whoer.com", "ipinfo.io", "ip.sb", "ipify.org", "ifconfig.me",
        "ifconfig.co", "icanhazip.com", "ipapi.co", "ip-api.com", "ipdata.co", "ipapi.is", "ipregistry.co",
        "iplocation.net", "whatismyipaddress.com", "whatismyip.com", "whatismybrowser.com", "myip.com",
        "browserscan.net", "pixelscan.net", "iphey.com", "scamalytics.com", "ipqualityscore.com", "ipwho.is",
        "db-ip.com", "ip2location.com", "ip2location.io", "ipgeolocation.io", "maxmind.com", "ipwhois.io",
        "ipcheck.ing", "ippure.com", "test-ipv6.com", "ipv6-test.com", "fingerprint.com", "amiunique.org",
        "coveryourtracks.eff.org",
    )
}

object AIRuleCatalog {
    val all: List<AIRuleCategory> = listOf(
        AIRuleCategory(
            id = "anthropic", name = "Claude / Anthropic", note = "含 Claude Code、MCP、官网 CDN 与 Auth0 租户", strict = false,
            suffixes = listOf("anthropic.com", "anthropic.team", "claude.ai", "claude.com", "claude.app", "claude.dev",
                       "claude.new", "claude.site", "clau.de", "claudeusercontent.com", "claudemcpclient.com",
                       "claudemcpcontent.com", "claudepages.dev", "claudestudio.com", "claudeacademy.com",
                       "chatbotclaude.com", "ant.dev", "antspace.dev"),
            domains = listOf("servd-anthropic-website.b-cdn.net", "anthropic.com.cdn.cloudflare.net", "anthropic.auth0.com",
                      "anthropic-com.ghost.io", "browser-intake-us5-datadoghq.com", "http-intake.logs.us5.datadoghq.com",
                      "o1158394.ingest.us.sentry.io", "cdn.usefathom.com"),
            // 用户要求：遥测/风控关键字并入 Claude 类，关掉第三方类也不影响
            keywords = listOf("anthropic", "claude", "sentry", "datadog", "sift"), regexes = emptyList(),
            ipCIDRs = listOf("160.79.104.0/21", "2607:6bc0::/32"), ruleSets = listOf("ai-anthropic")),

        AIRuleCategory(
            id = "ntp", name = "时间同步（NTP）", note = "geosite:category-ntp 与全部 UDP 123 走 AI 线路；直连模式下会被阻断", strict = true,
            suffixes = listOf("ntp.org", "pool.ntp.org", "time.apple.com", "time.asia.apple.com", "time.euro.apple.com",
                       "time.windows.com", "time.google.com", "time.cloudflare.com", "time.facebook.com",
                       "time.nist.gov", "ntp.ubuntu.com", "time.android.com"),
            domains = emptyList(), keywords = emptyList(), regexes = emptyList(), ipCIDRs = emptyList(), ruleSets = listOf("ai-ntp"),
            extraRules = listOf("AND,((NETWORK,UDP),(DST-PORT,123))")),

        AIRuleCategory(
            id = "openai", name = "ChatGPT / OpenAI", note = "含 Sora、Codex、语音实时通道与 Azure 托管资源", strict = false,
            suffixes = listOf("openai.com", "openai.org", "chatgpt.com", "chatgpt.site", "chat.com", "ai.com", "sora.com",
                       "oaistatic.com", "oaiusercontent.com", "oaistatsig.com", "crixet.com", "openai.azure.com",
                       "chatgpt.livekit.cloud", "host.livekit.cloud", "turn.livekit.cloud"),
            domains = listOf("openai.com.cdn.cloudflare.net", "chat.openai.com.cdn.cloudflare.net", "openaiapi-site.azureedge.net",
                      "openaiassets.blob.core.windows.net", "openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net",
                      "openaicom.imgix.net", "openaicomproductionae4b.blob.core.windows.net",
                      "production-openaicom-storage.azureedge.net", "openai-api.arkoselabs.com",
                      "o33249.ingest.sentry.io", "o33249.ingest.us.sentry.io", "openai.qualtrics.com"),
            keywords = listOf("openai", "chatgpt"),
            regexes = listOf("""^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$"""),
            ipCIDRs = listOf("24.199.123.28/32", "64.23.132.171/32")),

        AIRuleCategory(
            id = "google-ai", name = "Gemini / Google AI", note = "Gemini、AI Studio、NotebookLM、Vertex、Antigravity、Jules", strict = false,
            suffixes = listOf("gemini.google.com", "gemini.google", "gemini.gstatic.com", "bard.google.com", "aistudio.google.com",
                       "ai.studio", "ai.google.dev", "makersuite.google.com", "generativeai.google", "deepmind.com",
                       "deepmind.google", "notebooklm.google", "notebooklm.google.com", "notebook.google",
                       "notebook.google.com", "labs.google", "labs.google.com", "jules.google", "jules.google.com",
                       "flow.google", "flow.google.com", "opal.google", "opal.google.com", "antigravity.google",
                       "antigravity-unleash.goog", "stitch.withgoogle.com", "gemma.ai", "colab.google",
                       "colab.research.google.com", "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
                       "cloudaicompanion.googleapis.com", "cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com",
                       "notebooklm.googleapis.com", "notebooklm-pa.googleapis.com", "proactivebackend-pa.googleapis.com",
                       "robinfrontend-pa.googleapis.com", "geller-pa.googleapis.com", "aisandbox-pa.googleapis.com",
                       "aicode.googleapis.com", "aida.googleapis.com", "antigravity.googleapis.com",
                       "antigravity-pa.googleapis.com", "appsgenaiserver-pa.googleapis.com", "labstailwind.pa.googleapis.com"),
            domains = listOf("alkalicore-pa.clients6.google.com", "alkalimakersuite-pa.clients6.google.com",
                      "webchannel-alkalimakersuite-pa.clients6.google.com", "geminiweb-pa.clients.google.com",
                      "geminiweb-pa.clients6.google.com", "appsgenaiserver-pa.clients.google.com",
                      "appsgenaiserver-pa.clients6.google.com"),
            keywords = listOf("gemini", "generativelanguage", "aiplatform", "colab", "developerprofiles"), regexes = emptyList(), ipCIDRs = emptyList()),

        AIRuleCategory(
            id = "google-strict", name = "Google 账号体系（严格）", note = "Gemini 按账号和 IP 判区，整个 Google 都走 AI 线路", strict = true,
            suffixes = listOf("google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google.dev",
                       "withgoogle.com", "goo.gl", "g.co", "googleblog.com", "googlesource.com", "googlevideo.com",
                       "ggpht.com", "gvt2.com", "google", "youtube.com", "ytimg.com", "youtu.be"),
            domains = emptyList(), keywords = emptyList(), regexes = emptyList(), ipCIDRs = emptyList()),

        AIRuleCategory(
            id = "microsoft", name = "Copilot / Bing / Azure AI", note = "Microsoft Copilot、Bing Chat、Azure AI Foundry", strict = false,
            suffixes = listOf("copilot.microsoft.com", "copilot.cloud.microsoft", "copilot.com", "copilot-stg.com",
                       "m365copilot.com", "sydney.bing.com", "edgeservices.bing.com", "services.bingapis.com",
                       "bing-shopping.microsoft-falcon.io", "api.microsoftapp.net", "ai.azure.com",
                       "cognitiveservices.azure.com", "inference.ai.azure.com", "openai.azure.com"),
            domains = listOf("www.bing.com", "r.bing.com", "gateway.bingviz.microsoft.net", "gateway.bingviz.microsoftapp.net",
                      "location.microsoft.com", "self.events.data.microsoft.com", "in.appcenter.ms",
                      "odc.officeapps.live.com", "api.msn.com", "assets.msn.com"),
            keywords = listOf("copilot"), regexes = emptyList(), ipCIDRs = emptyList()),

        AIRuleCategory(
            id = "github-copilot", name = "GitHub Copilot / GitHub Models", note = "Copilot 补全/Chat/Workspace 与 GitHub Models", strict = false,
            suffixes = listOf("githubcopilot.com", "githubnext.com", "github.ai", "copilot-proxy.githubusercontent.com",
                       "copilot-telemetry.githubusercontent.com", "copilot-telemetry-service.githubusercontent.com"),
            domains = listOf("copilot-workspace.githubnext.com", "production-copilot-host-westus.webpubsub.azure.com",
                      "copilotprodattachments.blob.core.windows.net", "models.inference.ai.azure.com"),
            keywords = emptyList(), regexes = emptyList(), ipCIDRs = emptyList()),

        AIRuleCategory(
            id = "xai", name = "Grok / xAI", note = "含 X（Grok 内嵌于 X）", strict = false,
            suffixes = listOf("x.ai", "grok.com", "grok.x.com", "grokbot.com", "grokipedia.com", "grok.x.ai"),
            domains = emptyList(), keywords = listOf("grok"), regexes = emptyList(), ipCIDRs = emptyList()),

        AIRuleCategory(
            id = "x-strict", name = "X / Twitter（严格）", note = "Grok 账号即 X 账号", strict = true,
            suffixes = listOf("x.com", "twitter.com", "twimg.com", "t.co", "pscp.tv", "periscope.tv"),
            domains = emptyList(), keywords = emptyList(), regexes = emptyList(), ipCIDRs = emptyList()),

        AIRuleCategory(
            id = "assistants", name = "其他对话助手与搜索", note = "Perplexity、Meta AI、Poe、Character.AI、Mistral、Kimi/MiniMax 海外版等", strict = false,
            suffixes = listOf("perplexity.ai", "perplexity.com", "pplx.ai", "meta.ai", "metaaivm.com", "metaaiusercontent.com",
                       "llama.com", "llama.meta.com", "poe.com", "poecdn.net", "character.ai", "c.ai", "characterai.io",
                       "mistral.ai", "you.com", "phind.com", "duck.ai", "kimi.ai", "moonshot.ai", "minimax.io",
                       "hailuoai.video", "hailuoai.com", "z.ai", "manus.im", "manuscdn.com", "genspark.ai",
                       "coze.com", "dola.com", "pi.ai", "inflection.ai", "deepwiki.com",
                       "deepwiki.org", "youmind.com", "sider.ai", "monica.im", "getmerlin.in",
                       "chatbox.ai", "chathub.gg", "typingmind.com", "librechat.ai", "lmarena.ai", "arena.ai",
                       "artificialanalysis.ai", "notegpt.io", "talkai.info", "diabrowser.com", "diabrowser.engineering",
                       "thebrowser.company"),
            domains = listOf("ppl-ai-file-upload.s3.amazonaws.com", "pplx-res.cloudinary.com"),
            keywords = listOf("perplexity"), regexes = emptyList(), ipCIDRs = emptyList()),

        AIRuleCategory(
            id = "dev-tools", name = "AI 编程工具", note = "Cursor、Windsurf、JetBrains AI、Kiro、Amazon Q、v0、Replit 等", strict = false,
            suffixes = listOf("cursor.com", "cursor.sh", "cursorapi.com", "cursor-cdn.com", "cursorvm.com", "codeium.com",
                       "codeiumdata.com", "windsurf.com", "windsurf.build", "grazie.ai", "jetbrains.ai",
                       "grazie.aws.intellij.net", "augmentcode.com", "tabnine.com", "sourcegraph.com", "continue.dev",
                       "cline.bot", "roocode.com", "kilocode.ai", "replit.com", "repl.co", "replit.dev", "v0.dev",
                       "v0.app", "bolt.new", "stackblitz.com", "lovable.dev", "lovable.app", "devin.ai",
                       "cognition.ai", "kiro.dev", "zed.dev", "warp.dev", "trae.ai", "marscode.com", "coderabbit.ai",
                       "qoder.com", "opencode.ai", "factory.ai", "ampcode.com", "codegen.com", "openhands.dev",
                       "all-hands.dev", "commandcode.ai", "agentclientprotocol.com", "context7.com", "openspec.dev",
                       "plannotator.ai", "openclaw.ai", "clawhub.ai", "typesafe.ai"),
            domains = listOf("coderabbit.gallery.vsassets.io"),
            keywords = listOf("codewhisperer", "bedrock-runtime", "bedrock-agent"), regexes = listOf("""^q\.[a-z0-9-]+\.amazonaws\.com$"""), ipCIDRs = emptyList()),

        AIRuleCategory(
            id = "platforms", name = "模型平台与 API 聚合", note = "OpenRouter、Hugging Face、Groq、Together、Replicate、NVIDIA 等", strict = false,
            suffixes = listOf("openrouter.ai", "huggingface.co", "hf.co", "hf.space", "groq.com", "cerebras.ai", "cohere.ai",
                       "cohere.com", "together.ai", "together.xyz", "fireworks.ai", "replicate.com", "replicate.delivery",
                       "deepinfra.com", "anyscale.com", "lepton.ai", "novita.ai", "ai21.com", "writer.com",
                       "build.nvidia.com", "integrate.api.nvidia.com", "ngc.nvidia.com", "nvcf.nvidia.com",
                       "gateway.ai.cloudflare.com", "workers.ai", "chutes.ai", "nousresearch.com", "h2o.ai",
                       "mozilla.ai", "dify.ai", "langchain.com", "langsmith.com", "smith.langchain.com", "crewai.com",
                       "llamaindex.ai", "pinecone.io", "weaviate.io", "modal.com", "runpod.io", "baseten.co",
                       "ollama.com", "lmstudio.ai", "anythingllm.com", "elevenlabs.io", "syntx.ai", "minimaxi.chat"),
            domains = emptyList(), keywords = emptyList(), regexes = emptyList(), ipCIDRs = emptyList()),

        AIRuleCategory(
            id = "creative", name = "AI 创作（图像/视频/音频/写作）", note = "Midjourney、Runway、Suno、ElevenLabs、Gamma 等", strict = false,
            suffixes = listOf("midjourney.com", "leonardo.ai", "ideogram.ai", "runwayml.com", "runway.com", "pika.art",
                       "lumalabs.ai", "suno.com", "suno.ai", "udio.com", "elevenlabs.com", "elevenlabsusercontent.com",
                       "stability.ai", "dreamstudio.ai", "civitai.com", "krea.ai", "playground.com", "openart.ai",
                       "lovart.ai", "heygen.com", "synthesia.io", "gamma.app", "tome.app", "jasper.ai", "clipdrop.co",
                       "copy.ai", "writesonic.com", "magnific.com", "magnific.ai", "freepik.com", "envato.com",
                       "novelai.net", "dreamgen.com", "spicywriter.com", "tapnow.ai", "tripo3d.ai", "comfy.org",
                       "comfyui.com", "muse.ai", "kling.ai", "klingai.com", "hailuo.ai", "higgsfield.ai", "pollo.ai"),
            domains = emptyList(), keywords = listOf("midjourney"), regexes = emptyList(), ipCIDRs = emptyList()),

        AIRuleCategory(
            id = "third-party", name = "第三方关联（风控/鉴权/支付/遥测）",
            note = "AI 服务依赖的风控与验证码、登录、支付、埋点平台，它们同样会看到真实 IP", strict = true,
            suffixes = listOf("sentry.io", "sentry-cdn.com", "datadoghq.com", "datadoghq.eu", "browser-intake-datadoghq.com",
                       "statsig.com", "statsigapi.net", "statsigcdn.com", "featuregates.org", "featureassets.org",
                       "prodregistryv2.org", "segment.io", "segment.com", "intercom.io", "intercomcdn.com",
                       "intercomassets.com", "intercom-attachments.com", "launchdarkly.com", "sift.com", "siftscience.com",
                       "arkoselabs.com", "funcaptcha.com", "hcaptcha.com", "challenges.cloudflare.com",
                       "cloudflareinsights.com", "auth0.com", "workos.com", "clerk.com", "clerk.dev", "stripe.com",
                       "stripe.network", "stripecdn.com", "usefathom.com", "mixpanel.com", "amplitude.com",
                       "posthog.com", "growthbook.io", "honeycomb.io", "algolia.net", "algolianet.com", "identrust.com",
                       "observeit.net", "livekit.cloud", "persona.com", "withpersona.com", "onfido.com"),
            domains = listOf("static.cloudflareinsights.com"),
            keywords = listOf("datadog", "sift", "statsig"), regexes = emptyList(), ipCIDRs = emptyList())
    )

    fun enabledCategories(disabled: List<String>): List<AIRuleCategory> {
        val off = disabled.toSet()
        return all.filter { it.id !in off }
    }

    /** 生成 mihomo 规则行（不含目标策略），供配置生成器拼接目标 */
    fun ruleLines(disabled: List<String>, custom: List<String>): List<String> {
        val lines = LinkedHashSet<String>()
        val categories = enabledCategories(disabled)
        // 关键字最先匹配也无妨：所有 AI 规则指向同一目标，顺序只影响性能
        categories.forEach { c -> c.domains.forEach { lines.add("DOMAIN,$it") } }
        categories.forEach { c -> c.suffixes.forEach { lines.add("DOMAIN-SUFFIX,$it") } }
        custom.forEach { lines.add("DOMAIN-SUFFIX,$it") }
        categories.forEach { c -> c.keywords.forEach { lines.add("DOMAIN-KEYWORD,$it") } }
        categories.forEach { c -> c.regexes.forEach { lines.add("DOMAIN-REGEX,$it") } }
        categories.forEach { c -> c.ruleSets.forEach { lines.add("RULE-SET,$it") } }
        categories.forEach { c -> c.extraRules.forEach { lines.add(it) } }
        categories.forEach { c ->
            c.ipCIDRs.forEach { lines.add(if (':' in it) "IP-CIDR6,$it" else "IP-CIDR,$it") }
        }
        return lines.toList()
    }
}
