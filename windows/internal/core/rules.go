package core

import "strings"

type AIRuleCategory struct {
	ID, Name, Note                                                      string
	Strict                                                              bool
	Suffixes, Domains, Keywords, Regexes, IPCIDRs, RuleSets, ExtraRules []string
}

func (c AIRuleCategory) RuleCount() int {
	return len(c.Suffixes) + len(c.Domains) + len(c.Keywords) + len(c.Regexes) + len(c.IPCIDRs) + len(c.RuleSets) + len(c.ExtraRules)
}

type BundledRuleSet struct {
	Provider, File, Behavior string
}

var BundledRuleSets = []BundledRuleSet{
	{"cn-site", "geosite-cn.mrs", "domain"},
	{"cn-ip", "geoip-cn.mrs", "ipcidr"},
	{"ai-anthropic", "geosite-anthropic.mrs", "domain"},
	{"ai-ntp", "geosite-category-ntp.mrs", "domain"},
}

const CNTable = "cn4.txt"

func BundledRuleFiles() []string {
	files := make([]string, 0, len(BundledRuleSets))
	for _, rule := range BundledRuleSets {
		files = append(files, rule.File)
	}
	return files
}

var ForceProxyCatalog = []string{
	"browserleaks.com", "browserleaks.net", "browserleaks.org", "ipleak.net", "ipleak.org", "dnsleaktest.com",
	"dnsleak.com", "bash.ws", "whoer.net", "whoer.com", "ipinfo.io", "ip.sb", "ipify.org", "ifconfig.me",
	"ifconfig.co", "icanhazip.com", "ipapi.co", "ip-api.com", "ipdata.co", "ipapi.is", "ipregistry.co",
	"iplocation.net", "whatismyipaddress.com", "whatismyip.com", "whatismybrowser.com", "myip.com",
	"browserscan.net", "pixelscan.net", "iphey.com", "scamalytics.com", "ipqualityscore.com", "ipwho.is",
	"db-ip.com", "ip2location.com", "ip2location.io", "ipgeolocation.io", "maxmind.com", "ipwhois.io",
	"ipcheck.ing", "ippure.com", "test-ipv6.com", "ipv6-test.com", "fingerprint.com", "amiunique.org",
	"coveryourtracks.eff.org",
}

var AIRuleCatalog = []AIRuleCategory{
	{
		ID: "anthropic", Name: "Claude / Anthropic", Note: "含 Claude Code、MCP、官网 CDN 与 Auth0 租户", Strict: false,
		Suffixes: []string{"anthropic.com", "anthropic.team", "claude.ai", "claude.com", "claude.app", "claude.dev",
			"claude.new", "claude.site", "clau.de", "claudeusercontent.com", "claudemcpclient.com",
			"claudemcpcontent.com", "claudepages.dev", "claudestudio.com", "claudeacademy.com",
			"chatbotclaude.com", "ant.dev", "antspace.dev"},
		Domains: []string{"servd-anthropic-website.b-cdn.net", "anthropic.com.cdn.cloudflare.net", "anthropic.auth0.com",
			"anthropic-com.ghost.io", "browser-intake-us5-datadoghq.com", "http-intake.logs.us5.datadoghq.com",
			"o1158394.ingest.us.sentry.io", "cdn.usefathom.com"},
		// 用户要求：遥测/风控关键字并入 Claude 类，关掉第三方类也不影响
		Keywords: []string{"anthropic", "claude", "sentry", "datadog", "sift"},
		IPCIDRs:  []string{"160.79.104.0/21", "2607:6bc0::/32"}, RuleSets: []string{"ai-anthropic"},
	},

	{
		ID: "ntp", Name: "时间同步（NTP）", Note: "geosite:category-ntp 与全部 UDP 123 走 AI 线路；直连模式下会被阻断", Strict: true,
		Suffixes: []string{"ntp.org", "pool.ntp.org", "time.apple.com", "time.asia.apple.com", "time.euro.apple.com",
			"time.windows.com", "time.google.com", "time.cloudflare.com", "time.facebook.com",
			"time.nist.gov", "ntp.ubuntu.com", "time.android.com"}, RuleSets: []string{"ai-ntp"},
		ExtraRules: []string{"AND,((NETWORK,UDP),(DST-PORT,123))"},
	},

	{
		ID: "openai", Name: "ChatGPT / OpenAI", Note: "含 Sora、Codex、语音实时通道与 Azure 托管资源", Strict: false,
		Suffixes: []string{"openai.com", "openai.org", "chatgpt.com", "chatgpt.site", "chat.com", "ai.com", "sora.com",
			"oaistatic.com", "oaiusercontent.com", "oaistatsig.com", "crixet.com", "openai.azure.com",
			"chatgpt.livekit.cloud", "host.livekit.cloud", "turn.livekit.cloud"},
		Domains: []string{"openai.com.cdn.cloudflare.net", "chat.openai.com.cdn.cloudflare.net", "openaiapi-site.azureedge.net",
			"openaiassets.blob.core.windows.net", "openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net",
			"openaicom.imgix.net", "openaicomproductionae4b.blob.core.windows.net",
			"production-openaicom-storage.azureedge.net", "openai-api.arkoselabs.com",
			"o33249.ingest.sentry.io", "o33249.ingest.us.sentry.io", "openai.qualtrics.com"},
		Keywords: []string{"openai", "chatgpt"},
		Regexes:  []string{`^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$`},
		IPCIDRs:  []string{"24.199.123.28/32", "64.23.132.171/32"},
	},

	{
		ID: "google-ai", Name: "Gemini / Google AI", Note: "Gemini、AI Studio、NotebookLM、Vertex、Antigravity、Jules", Strict: false,
		Suffixes: []string{"gemini.google.com", "gemini.google", "gemini.gstatic.com", "bard.google.com", "aistudio.google.com",
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
			"antigravity-pa.googleapis.com", "appsgenaiserver-pa.googleapis.com", "labstailwind.pa.googleapis.com"},
		Domains: []string{"alkalicore-pa.clients6.google.com", "alkalimakersuite-pa.clients6.google.com",
			"webchannel-alkalimakersuite-pa.clients6.google.com", "geminiweb-pa.clients.google.com",
			"geminiweb-pa.clients6.google.com", "appsgenaiserver-pa.clients.google.com",
			"appsgenaiserver-pa.clients6.google.com"},
		Keywords: []string{"gemini", "generativelanguage", "aiplatform", "colab", "developerprofiles"},
	},

	{
		ID: "google-strict", Name: "Google 账号体系（严格）", Note: "Gemini 按账号和 IP 判区，整个 Google 都走 AI 线路", Strict: true,
		Suffixes: []string{"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google.dev",
			"withgoogle.com", "goo.gl", "g.co", "googleblog.com", "googlesource.com", "googlevideo.com",
			"ggpht.com", "gvt2.com", "google", "youtube.com", "ytimg.com", "youtu.be"},
	},

	{
		ID: "microsoft", Name: "Copilot / Bing / Azure AI", Note: "Microsoft Copilot、Bing Chat、Azure AI Foundry", Strict: false,
		Suffixes: []string{"copilot.microsoft.com", "copilot.cloud.microsoft", "copilot.com", "copilot-stg.com",
			"m365copilot.com", "sydney.bing.com", "edgeservices.bing.com", "services.bingapis.com",
			"bing-shopping.microsoft-falcon.io", "api.microsoftapp.net", "ai.azure.com",
			"cognitiveservices.azure.com", "inference.ai.azure.com", "openai.azure.com"},
		Domains: []string{"www.bing.com", "r.bing.com", "gateway.bingviz.microsoft.net", "gateway.bingviz.microsoftapp.net",
			"location.microsoft.com", "self.events.data.microsoft.com", "in.appcenter.ms",
			"odc.officeapps.live.com", "api.msn.com", "assets.msn.com"},
		Keywords: []string{"copilot"},
	},

	{
		ID: "github-copilot", Name: "GitHub Copilot / GitHub Models", Note: "Copilot 补全/Chat/Workspace 与 GitHub Models", Strict: false,
		Suffixes: []string{"githubcopilot.com", "githubnext.com", "github.ai", "copilot-proxy.githubusercontent.com",
			"copilot-telemetry.githubusercontent.com", "copilot-telemetry-service.githubusercontent.com"},
		Domains: []string{"copilot-workspace.githubnext.com", "production-copilot-host-westus.webpubsub.azure.com",
			"copilotprodattachments.blob.core.windows.net", "models.inference.ai.azure.com"},
	},

	{
		ID: "xai", Name: "Grok / xAI", Note: "含 X（Grok 内嵌于 X）", Strict: false,
		Suffixes: []string{"x.ai", "grok.com", "grok.x.com", "grokbot.com", "grokipedia.com", "grok.x.ai"}, Keywords: []string{"grok"},
	},

	{
		ID: "x-strict", Name: "X / Twitter（严格）", Note: "Grok 账号即 X 账号", Strict: true,
		Suffixes: []string{"x.com", "twitter.com", "twimg.com", "t.co", "pscp.tv", "periscope.tv"},
	},

	{
		ID: "assistants", Name: "其他对话助手与搜索", Note: "Perplexity、Meta AI、Poe、Character.AI、Mistral、Kimi/MiniMax 海外版等", Strict: false,
		Suffixes: []string{"perplexity.ai", "perplexity.com", "pplx.ai", "meta.ai", "metaaivm.com", "metaaiusercontent.com",
			"llama.com", "llama.meta.com", "poe.com", "poecdn.net", "character.ai", "c.ai", "characterai.io",
			"mistral.ai", "you.com", "phind.com", "duck.ai", "kimi.ai", "moonshot.ai", "minimax.io",
			"hailuoai.video", "hailuoai.com", "z.ai", "manus.im", "manuscdn.com", "genspark.ai",
			"coze.com", "dola.com", "pi.ai", "inflection.ai", "deepwiki.com",
			"deepwiki.org", "youmind.com", "sider.ai", "monica.im", "getmerlin.in",
			"chatbox.ai", "chathub.gg", "typingmind.com", "librechat.ai", "lmarena.ai", "arena.ai",
			"artificialanalysis.ai", "notegpt.io", "talkai.info", "diabrowser.com", "diabrowser.engineering",
			"thebrowser.company"},
		Domains:  []string{"ppl-ai-file-upload.s3.amazonaws.com", "pplx-res.cloudinary.com"},
		Keywords: []string{"perplexity"},
	},

	{
		ID: "dev-tools", Name: "AI 编程工具", Note: "Cursor、Windsurf、JetBrains AI、Kiro、Amazon Q、v0、Replit 等", Strict: false,
		Suffixes: []string{"cursor.com", "cursor.sh", "cursorapi.com", "cursor-cdn.com", "cursorvm.com", "codeium.com",
			"codeiumdata.com", "windsurf.com", "windsurf.build", "grazie.ai", "jetbrains.ai",
			"grazie.aws.intellij.net", "augmentcode.com", "tabnine.com", "sourcegraph.com", "continue.dev",
			"cline.bot", "roocode.com", "kilocode.ai", "replit.com", "repl.co", "replit.dev", "v0.dev",
			"v0.app", "bolt.new", "stackblitz.com", "lovable.dev", "lovable.app", "devin.ai",
			"cognition.ai", "kiro.dev", "zed.dev", "warp.dev", "trae.ai", "marscode.com", "coderabbit.ai",
			"qoder.com", "opencode.ai", "factory.ai", "ampcode.com", "codegen.com", "openhands.dev",
			"all-hands.dev", "commandcode.ai", "agentclientprotocol.com", "context7.com", "openspec.dev",
			"plannotator.ai", "openclaw.ai", "clawhub.ai", "typesafe.ai"},
		Domains:  []string{"coderabbit.gallery.vsassets.io"},
		Keywords: []string{"codewhisperer", "bedrock-runtime", "bedrock-agent"}, Regexes: []string{`^q\.[a-z0-9-]+\.amazonaws\.com$`},
	},

	{
		ID: "platforms", Name: "模型平台与 API 聚合", Note: "OpenRouter、Hugging Face、Groq、Together、Replicate、NVIDIA 等", Strict: false,
		Suffixes: []string{"openrouter.ai", "huggingface.co", "hf.co", "hf.space", "groq.com", "cerebras.ai", "cohere.ai",
			"cohere.com", "together.ai", "together.xyz", "fireworks.ai", "replicate.com", "replicate.delivery",
			"deepinfra.com", "anyscale.com", "lepton.ai", "novita.ai", "ai21.com", "writer.com",
			"build.nvidia.com", "integrate.api.nvidia.com", "ngc.nvidia.com", "nvcf.nvidia.com",
			"gateway.ai.cloudflare.com", "workers.ai", "chutes.ai", "nousresearch.com", "h2o.ai",
			"mozilla.ai", "dify.ai", "langchain.com", "langsmith.com", "smith.langchain.com", "crewai.com",
			"llamaindex.ai", "pinecone.io", "weaviate.io", "modal.com", "runpod.io", "baseten.co",
			"ollama.com", "lmstudio.ai", "anythingllm.com", "elevenlabs.io", "syntx.ai", "minimaxi.chat"},
	},

	{
		ID: "creative", Name: "AI 创作（图像/视频/音频/写作）", Note: "Midjourney、Runway、Suno、ElevenLabs、Gamma 等", Strict: false,
		Suffixes: []string{"midjourney.com", "leonardo.ai", "ideogram.ai", "runwayml.com", "runway.com", "pika.art",
			"lumalabs.ai", "suno.com", "suno.ai", "udio.com", "elevenlabs.com", "elevenlabsusercontent.com",
			"stability.ai", "dreamstudio.ai", "civitai.com", "krea.ai", "playground.com", "openart.ai",
			"lovart.ai", "heygen.com", "synthesia.io", "gamma.app", "tome.app", "jasper.ai", "clipdrop.co",
			"copy.ai", "writesonic.com", "magnific.com", "magnific.ai", "freepik.com", "envato.com",
			"novelai.net", "dreamgen.com", "spicywriter.com", "tapnow.ai", "tripo3d.ai", "comfy.org",
			"comfyui.com", "muse.ai", "kling.ai", "klingai.com", "hailuo.ai", "higgsfield.ai", "pollo.ai"}, Keywords: []string{"midjourney"},
	},

	{
		ID: "third-party", Name: "第三方关联（风控/鉴权/支付/遥测）",
		Note: "AI 服务依赖的风控与验证码、登录、支付、埋点平台，它们同样会看到真实 IP", Strict: true,
		Suffixes: []string{"sentry.io", "sentry-cdn.com", "datadoghq.com", "datadoghq.eu", "browser-intake-datadoghq.com",
			"statsig.com", "statsigapi.net", "statsigcdn.com", "featuregates.org", "featureassets.org",
			"prodregistryv2.org", "segment.io", "segment.com", "intercom.io", "intercomcdn.com",
			"intercomassets.com", "intercom-attachments.com", "launchdarkly.com", "sift.com", "siftscience.com",
			"arkoselabs.com", "funcaptcha.com", "hcaptcha.com", "challenges.cloudflare.com",
			"cloudflareinsights.com", "auth0.com", "workos.com", "clerk.com", "clerk.dev", "stripe.com",
			"stripe.network", "stripecdn.com", "usefathom.com", "mixpanel.com", "amplitude.com",
			"posthog.com", "growthbook.io", "honeycomb.io", "algolia.net", "algolianet.com", "identrust.com",
			"observeit.net", "livekit.cloud", "persona.com", "withpersona.com", "onfido.com"},
		Domains:  []string{"static.cloudflareinsights.com"},
		Keywords: []string{"datadog", "sift", "statsig"},
	},
}

func EnabledCategories(disabled []string) []AIRuleCategory {
	off := make(map[string]bool, len(disabled))
	for _, id := range disabled {
		off[id] = true
	}
	categories := make([]AIRuleCategory, 0, len(AIRuleCatalog))
	for _, category := range AIRuleCatalog {
		if !off[category.ID] {
			categories = append(categories, category)
		}
	}
	return categories
}

func AIRuleLines(disabled, custom []string) []string {
	categories := EnabledCategories(disabled)
	lines := []string{}
	seen := make(map[string]bool)
	add := func(line string) {
		if !seen[line] {
			seen[line] = true
			lines = append(lines, line)
		}
	}
	addGroup := func(prefix string, extract func(AIRuleCategory) []string) {
		for _, category := range categories {
			for _, value := range extract(category) {
				add(prefix + value)
			}
		}
	}
	addGroup("DOMAIN,", func(c AIRuleCategory) []string { return c.Domains })
	addGroup("DOMAIN-SUFFIX,", func(c AIRuleCategory) []string { return c.Suffixes })
	for _, domain := range custom {
		add("DOMAIN-SUFFIX," + domain)
	}
	addGroup("DOMAIN-KEYWORD,", func(c AIRuleCategory) []string { return c.Keywords })
	addGroup("DOMAIN-REGEX,", func(c AIRuleCategory) []string { return c.Regexes })
	addGroup("RULE-SET,", func(c AIRuleCategory) []string { return c.RuleSets })
	addGroup("", func(c AIRuleCategory) []string { return c.ExtraRules })
	for _, category := range categories {
		for _, cidr := range category.IPCIDRs {
			prefix := "IP-CIDR,"
			if strings.Contains(cidr, ":") {
				prefix = "IP-CIDR6,"
			}
			add(prefix + cidr)
		}
	}
	return lines
}

// AIIPv4Ranges 返回 AI 名单里按 IP 段写的规则（只取 IPv4），游戏模式下防火墙直接拦截这些地址的直连
func AIIPv4Ranges(disabled []string) []string {
	var out []string
	for _, line := range AIRuleLines(disabled, nil) {
		if cidr, ok := strings.CutPrefix(line, "IP-CIDR,"); ok {
			cidr, _, _ = strings.Cut(cidr, ",")
			out = append(out, cidr)
		}
	}
	return out
}
