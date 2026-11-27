package com.aiguard.core

import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class SubscriptionTest {
    @Test
    fun clashYamlKeepsOnlyProxies() {
        val yaml = """
            port: 7890
            proxies:
              - {name: "🇺🇸 US 01", type: ss, server: a.example.com, port: 443, cipher: aes-128-gcm, password: x}
              - name: "JP 02"
                type: trojan
                server: b.example.com
                port: 443
                password: y
            proxy-groups:
              - {name: G, type: select, proxies: ["JP 02"]}
            rules:
              - MATCH,DIRECT
        """.trimIndent()
        val p = SubscriptionParser.parse(yaml.toByteArray())
        assertEquals(2, p.nodeCount)
        assertFalse(p.providerContent.contains("rules:"))
        assertFalse(p.providerContent.contains("proxy-groups"))
    }

    @Test
    fun base64UriList() {
        val list = "ss://YWVzLTEyOC1nY206eA@1.2.3.4:8388#US\ntrojan://pw@host.example:443?sni=x#JP\n"
        val p = SubscriptionParser.parse(Base64.getEncoder().encode(list.toByteArray()))
        assertEquals(2, p.nodeCount)
    }

    @Test
    fun rejectsHtmlAndEmpty() {
        val html = assertThrows(SubscriptionException::class.java) { SubscriptionParser.parse("<html><body>login</body></html>".toByteArray()) }
        assertEquals(SubscriptionException.UNRECOGNIZED, html.message)
        val empty = assertThrows(SubscriptionException::class.java) { SubscriptionParser.parse("  \n".toByteArray()) }
        assertEquals(SubscriptionException.EMPTY, empty.message)
    }

    /** 熔断期间给内核留的窄例外：必须能从各种订阅格式里取到节点服务器地址 */
    @Test
    fun serverHostsFromAllFormats() {
        val yaml = """
            proxies:
              - {name: "JP 01", type: ss, server: jp1.example.com, port: 443, cipher: aes-128-gcm, password: x}
              - name: "SG 02"
                type: trojan
                server: 203.0.113.7
                port: 443
                password: y
        """.trimIndent()
        assertEquals(listOf("203.0.113.7", "jp1.example.com"), SubscriptionParser.serverHosts(yaml))
        val vmess = Base64.getEncoder().encodeToString("""{"v":"2","ps":"US","add":"us.example.net","port":"443","id":"x"}""".toByteArray())
        val uris = """
            trojan://pw@tr.example.org:443?sni=x#JP
            vless://uuid@198.51.100.9:8443?type=ws#SG
            hysteria2://auth@hy.example.com:5000/?insecure=1#HY
            vmess://$vmess
        """.trimIndent()
        assertEquals(listOf("198.51.100.9", "hy.example.com", "tr.example.org", "us.example.net"), SubscriptionParser.serverHosts(uris))
        // 恶意内容不能混进防火墙规则
        assertTrue(SubscriptionParser.serverHosts("  - {server: \"evil;-j ACCEPT\", port: 1}").isEmpty())
    }

    @Test
    fun usageHeader() {
        val u = SubscriptionUsage.parse("upload=1024; download=2048; total=10737418240; expire=1767225600")!!
        assertEquals(3072, u.used)
        assertEquals(1767225600L, u.expire)
        assertNull(SubscriptionUsage.parse("foo=bar"))
        assertEquals(Long.MAX_VALUE, SubscriptionUsage(Long.MAX_VALUE, 10, 0).used)
        // 浮点与越界数值不能让守护进程崩溃
        assertEquals(1L, SubscriptionUsage.parse("upload=1.2; download=1e400; total=5")!!.upload)
    }

    @Test
    fun profileNameFromHeaders() {
        val b64 = Base64.getEncoder().encodeToString("我的机场".toByteArray())
        assertEquals("我的机场", SubscriptionParser.profileName(mapOf("Profile-Title" to "base64:$b64")))
        assertEquals("机场", SubscriptionParser.profileName(mapOf("content-disposition" to "attachment; filename*=UTF-8''%E6%9C%BA%E5%9C%BA")))
        assertEquals("sub.yaml", SubscriptionParser.profileName(mapOf("Content-Disposition" to "attachment; filename=\"sub.yaml\"")))
    }

    @Test
    fun urlValidationAndMasking() {
        assertNull(SubscriptionParser.validateUrl("ftp://x.com/a"))
        assertNull(SubscriptionParser.validateUrl("https:///nohost"))
        assertTrue(SubscriptionParser.validateUrl(" https://sub.example.com/api/v1/client/abcd1234?token=x ") != null)
        val info = SubscriptionInfo(url = "https://sub.example.com/api/v1/client/abcd1234")
        assertEquals("https://sub.example.com/••••1234", info.maskedUrl)
        assertEquals("sub.example.com", info.host)
    }

    @Test
    fun exitTraceParsers() {
        assertEquals(ExitTrace("1.2.3.4", "JP"), ExitTrace.parseCloudflare("fl=1\nip=1.2.3.4\nloc=jp\n"))
        assertNull(ExitTrace.parseCloudflare("ip=1.2.3.4\nloc=XYZ\n"))
        assertEquals(ExitTrace("5.6.7.8", "US"), ExitTrace.parseJson("""{"ip":"5.6.7.8","country":"US"}"""))
        assertEquals(ExitTrace("5.6.7.8", "SG"), ExitTrace.parseJson("""{"query":"5.6.7.8","countryCode":"sg"}"""))
        assertNull(ExitTrace.parseJson("""{"ip":"5.6.7.8","country":"1A"}"""))
    }
}

class SettingsAndProtocolTest {
    @Test
    fun oldSettingsFileDecodesWithDefaultsAndUnknownKeys() {
        val s = AIGuardJson.decodeFromString(GuardSettings.serializer(), """{"enabled":false,"futureField":1,"mode":"bogus"}""")
        assertFalse(s.enabled)
        assertEquals("未知枚举值回退默认值", ProxyMode.PROXY, s.mode)
        assertEquals(2, s.probeIntervalSeconds)
    }

    @Test
    fun mainlandAlwaysForbiddenAndValuesClamped() {
        val s = GuardSettings(forbiddenRegions = listOf("hk", "US", "x", "HK"), probeIntervalSeconds = 0, latencyThresholdMs = 99_999).sanitized()
        assertEquals(listOf("CN", "HK", "US"), s.forbiddenRegions)
        assertEquals(1, s.probeIntervalSeconds)
        assertEquals(10_000, s.latencyThresholdMs)
        assertEquals(listOf("CN", "HK", "MO"), GuardSettings().sanitized().forbiddenRegions)
    }

    @Test
    fun domainAndPackageSanitizers() {
        assertEquals(listOf("example.com", "a-b.example.org"),
            DomainSanitizer.clean(listOf("HTTPS://Example.com/path", "*.a-b.example.org", "bad domain.com", "nodot", "x..y.com", "example.com")))
        assertEquals(listOf("com.anthropic.claude"), PackageNames.clean(listOf(" com.anthropic.claude ", "com.x; rm -rf /", "nodot", "1abc.def")))
    }

    @Test
    fun ipcRoundTrip() {
        val req = IpcEnvelope("tok", IpcRequest.UpdateSettings(GuardSettings(customAIDomains = listOf("x.ai"))))
        val text = AIGuardJson.encodeToString(IpcEnvelope.serializer(), req)
        assertEquals(req, AIGuardJson.decodeFromString(IpcEnvelope.serializer(), text))
        val status = GuardStatus(
            phase = GuardPhase.TRIPPED,
            fuse = FuseSnapshot(tripped = true, reason = FuseReason.UnsafeExit("HK")),
            latency = listOf(LatencySample(1, null), LatencySample(2, 120)),
        )
        val resp = IpcResponse(status = status)
        val back = AIGuardJson.decodeFromString(IpcResponse.serializer(), AIGuardJson.encodeToString(IpcResponse.serializer(), resp))
        assertEquals(resp, back)
        assertEquals(IpcRequest.Status, AIGuardJson.decodeFromString(IpcEnvelope.serializer(), """{"token":"t","request":{"type":"status"}}""").request)
    }

    @Test
    fun versionOrdering() {
        assertTrue(compareVersions("1.10.0", "1.9.2") > 0)
        assertEquals(0, compareVersions("1.0", "1.0.0"))
        assertTrue(compareVersions("1.0.0", "1.0.1") < 0)
    }
}

class MihomoParsingTest {
    @Test
    fun providerNodesMergedIntoProxies() {
        val top = """{"proxies":{"自动选择":{"type":"Fallback","now":"JP 01","all":["JP 01","US 01"],"history":[{"delay":51}]},"DIRECT":{"type":"Direct","history":[]}}}"""
        val providers = """{"providers":{"sub":{"proxies":[{"name":"JP 01","type":"Shadowsocks","history":[{"delay":0},{"delay":88}]},{"name":"US 01","type":"Shadowsocks","history":[{"delay":0}]},{"name":"HK 01","type":"Shadowsocks","history":[]}]},"default":{"proxies":[{"name":"DIRECT","type":"Direct","history":[{"delay":9}]}]}}}"""
        val map = MihomoApi.parseProxies(top, providers)
        assertEquals(88, map["JP 01"]?.lastDelay)
        assertTrue(map["US 01"]!!.tested && map["US 01"]!!.lastDelay == null)
        assertFalse(map["HK 01"]!!.tested)
        assertEquals(listOf("JP 01", "US 01"), map["自动选择"]?.all)
        assertFalse("顶层同名项以 /proxies 为准", map["DIRECT"]!!.tested)
        assertEquals(2, MihomoApi.parseProxies(top, null).size)
        assertTrue(MihomoApi.parseProxies(top, """{"error":"x"}""").isEmpty())
        assertTrue(MihomoApi.parseProxies(top, "not json").isEmpty())
    }

    @Test
    fun connectionsParseAndRouteKind() {
        val json = """{"downloadTotal":10,"uploadTotal":5,"connections":[
            {"id":"a","metadata":{"network":"tcp","host":"claude.ai","destinationIP":"198.18.0.9","destinationPort":"443"},
             "upload":1,"download":2,"start":"2026-11-27T10:00:00.123Z","chains":["🇸🇬 SG 01","节点选择","AIGUARD-GATE-AI"],"rule":"DomainSuffix","rulePayload":"claude.ai"},
            {"id":"b","metadata":{"network":"udp","sniffHost":"x.cn","destinationIP":"1.1.1.1","destinationPort":"53"},"chains":["DIRECT"],"rule":"Match","rulePayload":""}]}"""
        val snap = MihomoApi.parseConnections(AIGuardJson.parseToJsonElement(json) as JsonObject)
        assertEquals(2, snap.connections.size)
        val a = snap.connections[0]
        assertEquals("节点选择 → 🇸🇬 SG 01", a.chain)
        assertEquals("DomainSuffix · claude.ai", a.rule)
        assertEquals(MihomoApi.Connection.Route.PROXY, a.route)
        assertTrue(a.start != null)
        assertEquals("x.cn", snap.connections[1].host)
        assertEquals(MihomoApi.Connection.Route.DIRECT, snap.connections[1].route)
        fun conn(leaf: String) = a.copy(leaf = leaf)
        assertEquals(MihomoApi.Connection.Route.REJECT, conn("REJECT-DROP").route)
        assertEquals("节点名以内置出站名开头也按代理算", MihomoApi.Connection.Route.PROXY, conn("DIRECT-HK 备用").route)
    }
}

class ProcessMatchTest {
    @Test
    fun aiKeywordsMatchWholeWords() {
        for (s in listOf("com.anthropic.claude", "com.openai.chatgpt", "github.copilot-chat", "claude-code", "/data/x/bin/codex")) {
            assertTrue(s, ProcessMatch.isAI(s))
        }
        for (s in listOf("decline", "traefik", "com.example.augmented", "com.android.chrome")) {
            assertFalse(s, ProcessMatch.isAI(s))
        }
    }

    @Test
    fun targetPackagesRespectProtectionAndBrowsers() {
        val installed = listOf(
            "com.anthropic.claude", "com.google.android.apps.bard", "com.android.chrome", "com.google.android.gms",
            "com.aiguard.app", "com.termux", "com.tencent.mm", "org.example.myai",
        )
        val all = ProcessMatch.targetPackages(installed, listOf("org.example.myai"), includeBrowsers = true, self = "com.aiguard.app")
        assertEquals(setOf("com.anthropic.claude", "com.google.android.apps.bard", "com.android.chrome", "org.example.myai"), all)
        val aiOnly = ProcessMatch.targetPackages(installed, emptyList(), includeBrowsers = false, self = "com.aiguard.app")
        assertEquals(setOf("com.anthropic.claude", "com.google.android.apps.bard"), aiOnly)
    }

    @Test
    fun commandLinesOnlyMatchRealEntryPoints() {
        assertTrue(ProcessMatch.isAICommandLine(listOf("/data/data/com.termux/files/usr/bin/node", "/data/data/com.termux/files/usr/bin/claude")))
        assertTrue(ProcessMatch.isAICommandLine(listOf("python3", "-m", "aider")))
        assertTrue(ProcessMatch.isAICommandLine(listOf("/data/data/com.termux/files/home/.local/bin/codex", "exec")))
        assertFalse("编辑 AI 目录下的文件不算", ProcessMatch.isAICommandLine(listOf("vim", "/sdcard/.claude/x")))
        assertFalse(ProcessMatch.isAICommandLine(listOf("node", "server.js", "--claude")))
        assertFalse("App 进程交给按包名停止", ProcessMatch.isAICommandLine(listOf("com.anthropic.claude:remote")))
        assertEquals(listOf("node", "a.js"), ProcessMatch.parseCmdline("node\u0000a.js\u0000".toByteArray()))
    }
}
