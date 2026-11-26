import Foundation

/// 一类 AI 服务的识别规则。来源：v2fly/domain-list-community `category-ai-!cn`、
/// blackmatrix7/ios_rule_script（OpenAI/Claude/Gemini/Copilot）以及用户提供的 Claude 清单，按「宁可错杀」合并。
public struct AIRuleCategory: Sendable, Identifiable, Equatable {
    public let id: String
    public let name: String
    public let note: String
    /// 严格类会顺带覆盖一些非 AI 但与账号/风控强相关的大域名（如整个 Google）
    public let strict: Bool
    public let suffixes: [String]
    public let domains: [String]
    public let keywords: [String]
    public let regexes: [String]
    public let ipCIDRs: [String]
    /// 内置的 mrs 规则集（rule-provider 名称），来自 MetaCubeX/meta-rules-dat
    public var ruleSets: [String] = []
    /// 直接拼目标的逻辑规则，例如按端口匹配
    public var extraRules: [String] = []

    public var ruleCount: Int {
        suffixes.count + domains.count + keywords.count + regexes.count + ipCIDRs.count + ruleSets.count + extraRules.count
    }
}

/// 打包进 App 的规则集文件：provider 名 → 文件名 + 类型
public enum BundledRuleSets {
    public static let all: [(provider: String, file: String, behavior: String)] = [
        ("cn-site", "geosite-cn.mrs", "domain"),
        ("cn-ip", "geoip-cn.mrs", "ipcidr"),
        ("ai-anthropic", "geosite-anthropic.mrs", "domain"),
        ("ai-ntp", "geosite-category-ntp.mrs", "domain"),
    ]
    public static var files: [String] { all.map(\.file) }
}

public enum AIRuleCatalog {
    public static let all: [AIRuleCategory] = [
        AIRuleCategory(
            id: "anthropic", name: "Claude / Anthropic", note: "含 Claude Code、MCP、官网 CDN 与 Auth0 租户", strict: false,
            suffixes: ["anthropic.com", "anthropic.team", "claude.ai", "claude.com", "claude.app", "claude.dev",
                       "claude.new", "claude.site", "clau.de", "claudeusercontent.com", "claudemcpclient.com",
                       "claudemcpcontent.com", "claudepages.dev", "claudestudio.com", "claudeacademy.com",
                       "chatbotclaude.com", "ant.dev", "antspace.dev"],
            domains: ["servd-anthropic-website.b-cdn.net", "anthropic.com.cdn.cloudflare.net", "anthropic.auth0.com",
                      "anthropic-com.ghost.io", "browser-intake-us5-datadoghq.com", "http-intake.logs.us5.datadoghq.com",
                      "o1158394.ingest.us.sentry.io", "cdn.usefathom.com"],
            // 用户要求：遥测/风控关键字并入 Claude 类，关掉第三方类也不影响
            keywords: ["anthropic", "claude", "sentry", "datadog", "sift"], regexes: [],
            ipCIDRs: ["160.79.104.0/21", "2607:6bc0::/32"], ruleSets: ["ai-anthropic"]),

        AIRuleCategory(
            id: "ntp", name: "时间同步（NTP）", note: "geosite:category-ntp 与全部 UDP 123 走 AI 线路；直连模式下会被阻断", strict: true,
            suffixes: ["ntp.org", "pool.ntp.org", "time.apple.com", "time.asia.apple.com", "time.euro.apple.com",
                       "time.windows.com", "time.google.com", "time.cloudflare.com", "time.facebook.com",
                       "time.nist.gov", "ntp.ubuntu.com", "time.android.com"],
            domains: [], keywords: [], regexes: [], ipCIDRs: [], ruleSets: ["ai-ntp"],
            extraRules: ["AND,((NETWORK,UDP),(DST-PORT,123))"]),

        AIRuleCategory(
            id: "openai", name: "ChatGPT / OpenAI", note: "含 Sora、Codex、语音实时通道与 Azure 托管资源", strict: false,
            suffixes: ["openai.com", "openai.org", "chatgpt.com", "chatgpt.site", "chat.com", "ai.com", "sora.com",
                       "oaistatic.com", "oaiusercontent.com", "oaistatsig.com", "crixet.com", "openai.azure.com",
                       "chatgpt.livekit.cloud", "host.livekit.cloud", "turn.livekit.cloud"],
            domains: ["openai.com.cdn.cloudflare.net", "chat.openai.com.cdn.cloudflare.net", "openaiapi-site.azureedge.net",
                      "openaiassets.blob.core.windows.net", "openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net",
                      "openaicom.imgix.net", "openaicomproductionae4b.blob.core.windows.net",
                      "production-openaicom-storage.azureedge.net", "openai-api.arkoselabs.com",
                      "o33249.ingest.sentry.io", "o33249.ingest.us.sentry.io", "openai.qualtrics.com"],
            keywords: ["openai", "chatgpt"],
            regexes: [#"^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$"#],
            ipCIDRs: ["24.199.123.28/32", "64.23.132.171/32"]),

        AIRuleCategory(
            id: "google-ai", name: "Gemini / Google AI", note: "Gemini、AI Studio、NotebookLM、Vertex、Antigravity、Jules", strict: false,
            suffixes: ["gemini.google.com", "gemini.google", "gemini.gstatic.com", "bard.google.com", "aistudio.google.com",
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
                       "antigravity-pa.googleapis.com", "appsgenaiserver-pa.googleapis.com", "labstailwind.pa.googleapis.com"],
            domains: ["alkalicore-pa.clients6.google.com", "alkalimakersuite-pa.clients6.google.com",
                      "webchannel-alkalimakersuite-pa.clients6.google.com", "geminiweb-pa.clients.google.com",
                      "geminiweb-pa.clients6.google.com", "appsgenaiserver-pa.clients.google.com",
                      "appsgenaiserver-pa.clients6.google.com"],
            keywords: ["gemini", "generativelanguage", "aiplatform", "colab", "developerprofiles"], regexes: [], ipCIDRs: []),

        AIRuleCategory(
            id: "google-strict", name: "Google 账号体系（严格）", note: "Gemini 按账号和 IP 判区，整个 Google 都走 AI 线路", strict: true,
            suffixes: ["google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google.dev",
                       "withgoogle.com", "goo.gl", "g.co", "googleblog.com", "googlesource.com", "googlevideo.com",
                       "ggpht.com", "gvt2.com", "google", "youtube.com", "ytimg.com", "youtu.be"],
            domains: [], keywords: [], regexes: [], ipCIDRs: []),

        AIRuleCategory(
            id: "microsoft", name: "Copilot / Bing / Azure AI", note: "Microsoft Copilot、Bing Chat、Azure AI Foundry", strict: false,
            suffixes: ["copilot.microsoft.com", "copilot.cloud.microsoft", "copilot.com", "copilot-stg.com",
                       "m365copilot.com", "sydney.bing.com", "edgeservices.bing.com", "services.bingapis.com",
                       "bing-shopping.microsoft-falcon.io", "api.microsoftapp.net", "ai.azure.com",
                       "cognitiveservices.azure.com", "inference.ai.azure.com", "openai.azure.com"],
            domains: ["www.bing.com", "r.bing.com", "gateway.bingviz.microsoft.net", "gateway.bingviz.microsoftapp.net",
                      "location.microsoft.com", "self.events.data.microsoft.com", "in.appcenter.ms",
                      "odc.officeapps.live.com", "api.msn.com", "assets.msn.com"],
            keywords: ["copilot"], regexes: [], ipCIDRs: []),

        AIRuleCategory(
            id: "github-copilot", name: "GitHub Copilot / GitHub Models", note: "Copilot 补全/Chat/Workspace 与 GitHub Models", strict: false,
            suffixes: ["githubcopilot.com", "githubnext.com", "github.ai", "copilot-proxy.githubusercontent.com",
                       "copilot-telemetry.githubusercontent.com", "copilot-telemetry-service.githubusercontent.com"],
            domains: ["copilot-workspace.githubnext.com", "production-copilot-host-westus.webpubsub.azure.com",
                      "copilotprodattachments.blob.core.windows.net", "models.inference.ai.azure.com"],
            keywords: [], regexes: [], ipCIDRs: []),

        AIRuleCategory(
            id: "xai", name: "Grok / xAI", note: "含 X（Grok 内嵌于 X）", strict: false,
            suffixes: ["x.ai", "grok.com", "grok.x.com", "grokbot.com", "grokipedia.com", "grok.x.ai"],
            domains: [], keywords: ["grok"], regexes: [], ipCIDRs: []),

        AIRuleCategory(
            id: "x-strict", name: "X / Twitter（严格）", note: "Grok 账号即 X 账号", strict: true,
            suffixes: ["x.com", "twitter.com", "twimg.com", "t.co", "pscp.tv", "periscope.tv"],
            domains: [], keywords: [], regexes: [], ipCIDRs: []),

        AIRuleCategory(
            id: "assistants", name: "其他对话助手与搜索", note: "Perplexity、Meta AI、Poe、Character.AI、Mistral、Kimi/MiniMax 海外版等", strict: false,
            suffixes: ["perplexity.ai", "perplexity.com", "pplx.ai", "meta.ai", "metaaivm.com", "metaaiusercontent.com",
                       "llama.com", "llama.meta.com", "poe.com", "poecdn.net", "character.ai", "c.ai", "characterai.io",
                       "mistral.ai", "you.com", "phind.com", "duck.ai", "kimi.ai", "moonshot.ai", "minimax.io",
                       "hailuoai.video", "hailuoai.com", "z.ai", "manus.im", "manuscdn.com", "genspark.ai",
                       "coze.com", "dola.com", "pi.ai", "inflection.ai", "deepwiki.com",
                       "deepwiki.org", "youmind.com", "sider.ai", "monica.im", "getmerlin.in",
                       "chatbox.ai", "chathub.gg", "typingmind.com", "librechat.ai", "lmarena.ai", "arena.ai",
                       "artificialanalysis.ai", "notegpt.io", "talkai.info", "diabrowser.com", "diabrowser.engineering",
                       "thebrowser.company"],
            domains: ["ppl-ai-file-upload.s3.amazonaws.com", "pplx-res.cloudinary.com"],
            keywords: ["perplexity"], regexes: [], ipCIDRs: []),

        AIRuleCategory(
            id: "dev-tools", name: "AI 编程工具", note: "Cursor、Windsurf、JetBrains AI、Kiro、Amazon Q、v0、Replit 等", strict: false,
            suffixes: ["cursor.com", "cursor.sh", "cursorapi.com", "cursor-cdn.com", "cursorvm.com", "codeium.com",
                       "codeiumdata.com", "windsurf.com", "windsurf.build", "grazie.ai", "jetbrains.ai",
                       "grazie.aws.intellij.net", "augmentcode.com", "tabnine.com", "sourcegraph.com", "continue.dev",
                       "cline.bot", "roocode.com", "kilocode.ai", "replit.com", "repl.co", "replit.dev", "v0.dev",
                       "v0.app", "bolt.new", "stackblitz.com", "lovable.dev", "lovable.app", "devin.ai",
                       "cognition.ai", "kiro.dev", "zed.dev", "warp.dev", "trae.ai", "marscode.com", "coderabbit.ai",
                       "qoder.com", "opencode.ai", "factory.ai", "ampcode.com", "codegen.com", "openhands.dev",
                       "all-hands.dev", "commandcode.ai", "agentclientprotocol.com", "context7.com", "openspec.dev",
                       "plannotator.ai", "openclaw.ai", "clawhub.ai", "typesafe.ai"],
            domains: ["coderabbit.gallery.vsassets.io"],
            keywords: ["codewhisperer", "bedrock-runtime", "bedrock-agent"], regexes: [#"^q\.[a-z0-9-]+\.amazonaws\.com$"#], ipCIDRs: []),

        AIRuleCategory(
            id: "platforms", name: "模型平台与 API 聚合", note: "OpenRouter、Hugging Face、Groq、Together、Replicate、NVIDIA 等", strict: false,
            suffixes: ["openrouter.ai", "huggingface.co", "hf.co", "hf.space", "groq.com", "cerebras.ai", "cohere.ai",
                       "cohere.com", "together.ai", "together.xyz", "fireworks.ai", "replicate.com", "replicate.delivery",
                       "deepinfra.com", "anyscale.com", "lepton.ai", "novita.ai", "ai21.com", "writer.com",
                       "build.nvidia.com", "integrate.api.nvidia.com", "ngc.nvidia.com", "nvcf.nvidia.com",
                       "gateway.ai.cloudflare.com", "workers.ai", "chutes.ai", "nousresearch.com", "h2o.ai",
                       "mozilla.ai", "dify.ai", "langchain.com", "langsmith.com", "smith.langchain.com", "crewai.com",
                       "llamaindex.ai", "pinecone.io", "weaviate.io", "modal.com", "runpod.io", "baseten.co",
                       "ollama.com", "lmstudio.ai", "anythingllm.com", "elevenlabs.io", "syntx.ai", "minimaxi.chat"],
            domains: [], keywords: [], regexes: [], ipCIDRs: []),

        AIRuleCategory(
            id: "creative", name: "AI 创作（图像/视频/音频/写作）", note: "Midjourney、Runway、Suno、ElevenLabs、Gamma 等", strict: false,
            suffixes: ["midjourney.com", "leonardo.ai", "ideogram.ai", "runwayml.com", "runway.com", "pika.art",
                       "lumalabs.ai", "suno.com", "suno.ai", "udio.com", "elevenlabs.com", "elevenlabsusercontent.com",
                       "stability.ai", "dreamstudio.ai", "civitai.com", "krea.ai", "playground.com", "openart.ai",
                       "lovart.ai", "heygen.com", "synthesia.io", "gamma.app", "tome.app", "jasper.ai", "clipdrop.co",
                       "copy.ai", "writesonic.com", "magnific.com", "magnific.ai", "freepik.com", "envato.com",
                       "novelai.net", "dreamgen.com", "spicywriter.com", "tapnow.ai", "tripo3d.ai", "comfy.org",
                       "comfyui.com", "muse.ai", "kling.ai", "klingai.com", "hailuo.ai", "higgsfield.ai", "pollo.ai"],
            domains: [], keywords: ["midjourney"], regexes: [], ipCIDRs: []),

        AIRuleCategory(
            id: "third-party", name: "第三方关联（风控/鉴权/支付/遥测）",
            note: "AI 服务依赖的风控与验证码、登录、支付、埋点平台，它们同样会看到真实 IP", strict: true,
            suffixes: ["sentry.io", "sentry-cdn.com", "datadoghq.com", "datadoghq.eu", "browser-intake-datadoghq.com",
                       "statsig.com", "statsigapi.net", "statsigcdn.com", "featuregates.org", "featureassets.org",
                       "prodregistryv2.org", "segment.io", "segment.com", "intercom.io", "intercomcdn.com",
                       "intercomassets.com", "intercom-attachments.com", "launchdarkly.com", "sift.com", "siftscience.com",
                       "arkoselabs.com", "funcaptcha.com", "hcaptcha.com", "challenges.cloudflare.com",
                       "cloudflareinsights.com", "auth0.com", "workos.com", "clerk.com", "clerk.dev", "stripe.com",
                       "stripe.network", "stripecdn.com", "usefathom.com", "mixpanel.com", "amplitude.com",
                       "posthog.com", "growthbook.io", "honeycomb.io", "algolia.net", "algolianet.com", "identrust.com",
                       "observeit.net", "livekit.cloud", "persona.com", "withpersona.com", "onfido.com"],
            domains: ["static.cloudflareinsights.com"],
            keywords: ["datadog", "sift", "statsig"], regexes: [], ipCIDRs: []),
    ]

    public static func enabledCategories(disabled: [String]) -> [AIRuleCategory] {
        let off = Set(disabled)
        return all.filter { !off.contains($0.id) }
    }

    /// 生成 mihomo 规则行（不含目标策略），供配置生成器拼接目标
    public static func ruleLines(disabled: [String], custom: [String]) -> [String] {
        var seen = Set<String>()
        var lines: [String] = []
        func add(_ line: String) { if seen.insert(line).inserted { lines.append(line) } }
        let categories = enabledCategories(disabled: disabled)
        // 关键字最先匹配也无妨：所有 AI 规则指向同一目标，顺序只影响性能
        for c in categories { c.domains.forEach { add("DOMAIN,\($0)") } }
        for c in categories { c.suffixes.forEach { add("DOMAIN-SUFFIX,\($0)") } }
        custom.forEach { add("DOMAIN-SUFFIX,\($0)") }
        for c in categories { c.keywords.forEach { add("DOMAIN-KEYWORD,\($0)") } }
        for c in categories { c.regexes.forEach { add("DOMAIN-REGEX,\($0)") } }
        for c in categories { c.ruleSets.forEach { add("RULE-SET,\($0)") } }
        for c in categories { c.extraRules.forEach { add($0) } }
        for c in categories {
            for cidr in c.ipCIDRs {
                add(cidr.contains(":") ? "IP-CIDR6,\(cidr)" : "IP-CIDR,\(cidr)")
            }
        }
        return lines
    }
}
