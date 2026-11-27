package com.aiguard.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit

private val runtime = CoreRuntime(secret = "s3cret", listenerPassword = "pw\"x", hasSubscription = true)

class ConfigBuilderTest {
    @Test
    fun aiRulesComeBeforeMainlandDirectRules() {
        val rules = MihomoConfigBuilder.rules(GuardSettings(), ProxyMode.PROXY)
        val ai = rules.indexOf("DOMAIN-SUFFIX,claude.ai,${GroupName.GATE_AI}")
        val cn = rules.indexOf("RULE-SET,cn-site,${GroupName.GATE_CN}")
        assertTrue(ai in 0 until cn)
        assertEquals("MATCH,${GroupName.GATE_MAIN}", rules.last())
        // 任何模式下 AI 规则都不会指向 DIRECT
        assertFalse(rules.any { it.contains("claude") && it.endsWith(",DIRECT") })
    }

    @Test
    fun directModeRejectsAIAndOnlyAllowsMainland() {
        val rules = MihomoConfigBuilder.rules(GuardSettings(), ProxyMode.DIRECT)
        assertTrue(rules.contains("DOMAIN-SUFFIX,claude.ai,REJECT"))
        assertFalse(rules.any { it.contains(GroupName.PROXY) })
        assertEquals("MATCH,REJECT", rules.last())
        val loose = MihomoConfigBuilder.rules(GuardSettings(directOnlyMainland = false), ProxyMode.DIRECT)
        assertEquals("MATCH,${GroupName.GATE_DIRECT}", loose.last())
    }

    @Test
    fun forceProxySitesBeatMainlandList() {
        val s = GuardSettings(
            customProxyDomains = listOf("HTTPS://Leak.Example.org/x", "both.example.com"),
            customDirectDomains = listOf("both.example.com"),
        ).sanitized()
        val rules = MihomoConfigBuilder.rules(s, ProxyMode.PROXY)
        val cn = rules.indexOf("RULE-SET,cn-site,${GroupName.GATE_CN}")
        for (d in listOf("browserleaks.com", "whatismyip.com", "leak.example.org")) {
            val i = rules.indexOf("DOMAIN-SUFFIX,$d,${GroupName.GATE_MAIN}")
            assertTrue("$d 必须在大陆名单之前强制走代理", i in 0 until cn)
        }
        assertTrue(rules.contains("DOMAIN-SUFFIX,both.example.com,${GroupName.GATE_DIRECT}"))
        assertFalse(rules.contains("DOMAIN-SUFFIX,both.example.com,${GroupName.GATE_MAIN}"))

        val yaml = MihomoConfigBuilder.build(s, runtime)
        val leak = yaml.indexOf("\"+.browserleaks.com\": [\"https://1.1.1.1/dns-query#${GroupName.PROXY}\"")
        val cnPolicy = yaml.indexOf("\"rule-set:cn-site\": [\"https://223.5.5.5")
        assertTrue(leak in 0 until cnPolicy)
        assertFalse(yaml.contains("\"+.both.example.com\": [\"https://1.1.1.1"))

        val parent = GuardSettings(customDirectDomains = listOf("example.net"), customProxyDomains = listOf("a.example.net", "example.network"))
        val forced = MihomoConfigBuilder.forceProxyDomains(parent.sanitized())
        assertFalse(forced.contains("a.example.net"))
        assertTrue("只是后缀字符相同、不是子域的不能被误伤", forced.contains("example.network"))
    }

    @Test
    fun noSubscriptionFallsBackToDirect() {
        val rt = runtime.copy(hasSubscription = false)
        val yaml = MihomoConfigBuilder.build(GuardSettings(), rt)
        assertFalse(yaml.contains(GroupName.PROXY))
        assertFalse(yaml.contains("proxy-providers"))
        assertTrue(yaml.contains("MATCH,REJECT"))
    }

    @Test
    fun quotingEscapesSpecialCharacters() {
        assertEquals("\"a\\\"b\\\\c\\nd\"", q("a\"b\\c\nd"))
        val yaml = MihomoConfigBuilder.build(GuardSettings(), runtime)
        assertTrue(yaml.contains("password: \"pw\\\"x\""))
    }

    @Test
    fun catalogHasNoDuplicateOrMalformedEntries() {
        for (c in AIRuleCatalog.all) {
            // .google 是 Google 自有顶级域，作为后缀是有意为之
            for (d in (c.suffixes + c.domains).filter { it != "google" }) {
                assertEquals("非法域名: $d in ${c.id}", listOf(d.lowercase()), DomainSanitizer.clean(listOf(d)))
            }
        }
        val lines = AIRuleCatalog.ruleLines(emptyList(), emptyList())
        assertEquals(lines.size, lines.toSet().size)
        assertTrue(lines.size > 300)
        for (d in listOf("anthropic.com", "claude.ai", "clau.de", "claudeusercontent.com", "sentry.io", "statsigapi.net", "intercom.io")) {
            assertTrue("缺少 $d", lines.contains("DOMAIN-SUFFIX,$d"))
        }
        assertTrue(lines.contains("DOMAIN-KEYWORD,datadog") && lines.contains("DOMAIN-KEYWORD,sift"))
        assertTrue(lines.contains("RULE-SET,ai-anthropic") && lines.contains("RULE-SET,ai-ntp"))
        assertTrue(lines.contains("AND,((NETWORK,UDP),(DST-PORT,123))"))
        assertEquals(DomainSanitizer.clean(ForceProxyCatalog.suffixes), ForceProxyCatalog.suffixes)
    }

    /** 关掉第三方类后，Claude 类里的遥测关键字和官方规则集仍然生效 */
    @Test
    fun claudeStrictSurvivesThirdPartyToggle() {
        val lines = AIRuleCatalog.ruleLines(listOf("third-party"), emptyList())
        for (k in listOf("sentry", "datadog", "sift")) assertTrue(lines.contains("DOMAIN-KEYWORD,$k"))
        assertTrue(lines.contains("RULE-SET,ai-anthropic"))
        val yaml = MihomoConfigBuilder.build(GuardSettings(), runtime)
        assertFalse("NTP 不能出现在 fake-ip 过滤表里", yaml.contains("ntp.org\""))
    }

    /** 用 Java 正则近似验证（mihomo 用 regexp2，语法兼容这里用到的环视） */
    @Test
    fun nodeFilterFollowsForbiddenRegions() {
        fun matcher(p: String): (String) -> Boolean {
            val re = Regex(p.removePrefix("(?i)"), RegexOption.IGNORE_CASE)
            return { re.containsMatchIn(it) }
        }
        val excluded = matcher(MihomoConfigBuilder.nodeExcludeFilter(GuardSettings()))
        for (name in listOf("🇭🇰 香港 01", "HK01 IEPL", "Hong Kong 02", "广港专线", "澳门 01", "MO-01", "中国 回国",
            "CN 直连", "剩余流量：100G", "套餐到期：2027-01-01", "HKG-BGP", "俄罗斯 01")) {
            assertTrue("应排除: $name", excluded(name))
        }
        for (name in listOf("日本 东京 01", "🇸🇬 Singapore", "Mongolia", "台湾 01", "韩国 首尔", "Germany Frankfurt",
            "🇺🇸 美国 CN2 GIA", "US-LAX-Hysteria", "USA 02")) {
            assertFalse("不应排除: $name", excluded(name))
        }
        val strict = matcher(MihomoConfigBuilder.nodeExcludeFilter(GuardSettings(forbiddenRegions = listOf("CN", "HK", "MO", "US"))))
        assertTrue(strict("🇺🇸 美国 CN2 GIA") && strict("US-LAX-Hysteria") && strict("洛杉矶 01"))
        assertEquals("🇺🇸", RegionNames.flag("US"))
    }

    @Test
    fun androidTunAndDnsListener() {
        val yaml = MihomoConfigBuilder.build(GuardSettings(), runtime)
        assertTrue(yaml.contains("  device: \"aiguard\""))
        assertTrue(yaml.contains("  auto-route: true"))
        assertTrue("防火墙把 App 的 DNS 重定向到这里", yaml.contains("  listen: \"127.0.0.1:${Ports.DNS}\""))
        assertFalse("Android 版不开放本机混合代理端口", yaml.contains("mixed-port"))
        assertFalse(yaml.contains("respect-rules"))
        assertFalse("DNS 服务器必须是 IP，不依赖系统解析", yaml.contains("dns.alidns.com"))
        assertTrue(yaml.contains("name: \"aiguard-probe\""))
    }

    /** 省流量：节点体检要经每个节点握手，必须是稀疏的，靠失败次数触发即时体检保证换线速度 */
    @Test
    fun autoGroupHealthCheckIsSparseButReactive() {
        val yaml = MihomoConfigBuilder.build(GuardSettings(), runtime)
        val auto = yaml.substringAfter("  - name: \"${GroupName.AUTO}\"").substringBefore("  - name:")
        assertTrue(auto.contains("interval: ${MihomoConfigBuilder.AUTO_CHECK_INTERVAL_SECONDS}"))
        assertTrue(MihomoConfigBuilder.AUTO_CHECK_INTERVAL_SECONDS >= 300)
        assertTrue(auto.contains("max-failed-times: 2"))
        assertFalse("订阅节点不能再单独体检一遍", yaml.contains("health-check: {enable: true"))
        // 默认智能分流：大陆域名与大陆 IP 走大陆闸门（直连），不消耗代理流量
        assertEquals(RoutingMode.SMART, GuardSettings().routing)
        val rules = MihomoConfigBuilder.rules(GuardSettings(), ProxyMode.PROXY)
        assertTrue(rules.contains("RULE-SET,cn-ip,${GroupName.GATE_CN}"))
    }

    @Test
    fun captiveUsesDhcpDnsOnlyForPhysicalInterface() {
        val ok = MihomoConfigBuilder.build(GuardSettings(), runtime, captive = true, captiveInterface = "wlan0")
        assertTrue(ok.contains("dhcp://wlan0"))
        val bad = MihomoConfigBuilder.build(GuardSettings(), runtime, captive = true, captiveInterface = "wlan0\"; x")
        assertFalse(bad.contains("dhcp://"))
        val cell = MihomoConfigBuilder.build(GuardSettings(), runtime, captive = true, captiveInterface = "rmnet_data0")
        assertFalse(cell.contains("dhcp://"))
    }

    /** 生成的配置交给真实内核校验：用 macOS 版 mihomo 的 -t（只解析不启动，TUN 不会真的开） */
    @Test
    fun generatedConfigsPassMihomoValidation() {
        val vendor = File(System.getProperty("aiguard.vendor") ?: "../../Vendor")
        val mihomo = File(vendor, "mihomo")
        val osName = System.getProperty("os.name").lowercase()
        assumeTrue("需要先运行仓库根目录的 scripts/fetch-core.sh", mihomo.canExecute() && "mac" in osName)
        val dir = Files.createTempDirectory("aiguard-test").toFile()
        try {
            File(dir, "providers").mkdirs()
            File(dir, "rules").mkdirs()
            for (f in BundledRuleSets.files) File(vendor, "rules/$f").copyTo(File(dir, "rules/$f"))
            File(dir, "providers/sub.yaml").writeText(
                "proxies:\n  - {name: \"US 01\", type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}\n",
            )
            val cases = listOf(
                Triple(ProxyMode.PROXY, RoutingMode.SMART, true),
                Triple(ProxyMode.PROXY, RoutingMode.GLOBAL, true),
                Triple(ProxyMode.DIRECT, RoutingMode.SMART, true),
                Triple(ProxyMode.DIRECT, RoutingMode.SMART, false),
            )
            for ((mode, routing, sub) in cases) {
                val s = GuardSettings(mode = mode, routing = routing, customProxyDomains = listOf("leak.example.org"))
                val file = File(dir, "config-$mode-$routing-$sub.yaml")
                file.writeText(MihomoConfigBuilder.build(s, runtime.copy(hasSubscription = sub)))
                val p = ProcessBuilder(mihomo.path, "-t", "-d", dir.path, "-f", file.path).redirectErrorStream(true).start()
                val out = p.inputStream.bufferedReader().readText()
                assertTrue(p.waitFor(60, TimeUnit.SECONDS))
                assertEquals("mihomo 拒绝了配置 $mode/$routing/$sub: ${out.takeLast(600)}", 0, p.exitValue())
                assertTrue("内核没有真正完成校验: ${out.takeLast(300)}", out.contains("test is successful"))
            }
        } finally {
            dir.deleteRecursively()
        }
    }
}

class FirewallBuilderTest {
    private val ctx = FirewallContext(appUid = 10234)
    private val tun = CoreRuntime.TUN_DEVICE

    private fun rules(text: String?): List<String> = text.orEmpty().lines().filter { it.startsWith("-A ") }

    @Test
    fun noneProducesNothing() {
        assertEquals(null, FirewallBuilder.filter4(FirewallPolicy.None, ctx))
        assertEquals(null, FirewallBuilder.filter6(FirewallPolicy.None))
        assertEquals(null, FirewallBuilder.nat4(FirewallPolicy.None, ctx))
    }

    @Test
    fun invalidTunNameFallsBackToLockdown() {
        val bad = FirewallBuilder.filter4(FirewallPolicy.LeakGuard("x -j ACCEPT"), ctx)
        assertEquals(FirewallBuilder.filter4(FirewallPolicy.Lockdown, ctx), bad)
        assertFalse(FirewallBuilder.isValidInterface("lo"))
        assertTrue(FirewallBuilder.isValidInterface("aiguard"))
    }

    @Test
    fun restoreFormatIsAtomicPerTable() {
        val text = FirewallBuilder.filter4(FirewallPolicy.LeakGuard(tun), ctx)!!
        val lines = text.trim().lines()
        assertEquals("*filter", lines.first())
        assertEquals(":${FirewallBuilder.CHAIN} - [0:0]", lines[1])
        assertEquals("COMMIT", lines.last())
        assertTrue(rules(text).all { it.startsWith("-A ${FirewallBuilder.CHAIN} ") })
    }

    @Test
    fun loopbackControlPortsOnlyForRootAndApp() {
        val r = rules(FirewallBuilder.filter4(FirewallPolicy.LeakGuard(tun), ctx))
        val loAll = r.indexOf("-A AIGUARD_OUT -o lo -j RETURN")
        val appRule = r.indexOfFirst { "--uid-owner 10234" in it && "19097" in it }
        val reject = r.indexOfFirst { "19097" in it && "REJECT" in it }
        assertTrue(appRule in 0 until reject && reject < loAll)
        // 探测入站只允许 root
        val probeLines = r.filter { "17892" in it }
        assertEquals(2, probeLines.size)
        assertTrue(probeLines[0].contains("--uid-owner 0") && probeLines[1].contains("REJECT"))
        // 系统 uid 不能当作界面 App 放行
        val sys = rules(FirewallBuilder.filter4(FirewallPolicy.LeakGuard(tun), FirewallContext(appUid = 1000)))
        assertFalse(sys.any { "--uid-owner 1000 " in it })
    }

    @Test
    fun leakGuardOnlyLetsRootBypassTun() {
        val r = rules(FirewallBuilder.filter4(FirewallPolicy.LeakGuard(tun), ctx))
        val tunPass = r.indexOf("-A AIGUARD_OUT -o aiguard -j RETURN")
        val dnsBlock = r.indexOfFirst { "--dports 53,853 -j REJECT" in it }
        val root = r.indexOf("-A AIGUARD_OUT -m owner --uid-owner 0 -j RETURN")
        assertTrue(tunPass in 0 until dnsBlock && dnsBlock < root)
        assertEquals("-A AIGUARD_OUT -j REJECT", r.last())
        // root 的明文 DNS 只能发往引导 DNS 与局域网
        val rootDns = r.filter { "--dport 53 -m owner --uid-owner 0" in it }
        assertTrue(rootDns.isNotEmpty() && rootDns.all { "223.5.5.5/32" in it || "119.29.29.29/32" in it || FirewallBuilder.lan.any { l -> l in it } })
        assertTrue("基带流量放行，否则 VoLTE 会断", r.any { "--uid-owner ${FirewallBuilder.AID_RADIO} -j RETURN" in it })
    }

    @Test
    fun basicKeepsDnsGuardButNoLeakBlock() {
        val r = rules(FirewallBuilder.filter4(FirewallPolicy.Basic(tun), ctx))
        assertTrue(r.any { "--dports 53,853 -j REJECT" in it })
        assertFalse(r.contains("-A AIGUARD_OUT -j REJECT"))
    }

    @Test
    fun whitelistEndsWithMainlandChainAndGatesTun() {
        val closed = rules(FirewallBuilder.filter4(FirewallPolicy.Whitelist(tun, allowTun = false, allow = listOf("203.0.113.7", "evil;x", "1.2.3.4")), ctx))
        assertFalse("闸门确认前不放行 TUN", closed.any { "-o aiguard -j RETURN" in it })
        assertEquals("-A AIGUARD_OUT -j ${FirewallBuilder.CN_CHAIN}", closed.last())
        assertTrue(closed.contains("-A AIGUARD_OUT -d 203.0.113.7/32 -m owner --uid-owner 0 -j RETURN"))
        assertFalse(closed.any { "evil" in it })
        val open = rules(FirewallBuilder.filter4(FirewallPolicy.Whitelist(tun, allowTun = true, allow = emptyList()), ctx))
        assertTrue(open.contains("-A AIGUARD_OUT -o aiguard -j RETURN"))
        // 节点例外只给 root
        assertFalse(open.any { "-d 203.0.113.7" in it })
        val many = (1..2000).map { "10.${it / 250}.${it % 250}.1" }
        val capped = rules(FirewallBuilder.filter4(FirewallPolicy.Whitelist(tun, true, many), ctx))
        assertEquals(FirewallBuilder.MAX_ALLOW, capped.count { it.endsWith("--uid-owner 0 -j RETURN") && "/32 -m owner" in it && "--dport" !in it })
    }

    @Test
    fun cnChainReturnsForMainlandAndRejectsRest() {
        val r = rules(FirewallBuilder.cnChain(listOf("1.0.1.0/24", "bad", "1.0.1.0/24", "36.0.0.0/8", "300.1.1.1/8")))
        assertEquals(listOf("-A AIGUARD_CN -d 1.0.1.0/24 -j RETURN", "-A AIGUARD_CN -d 36.0.0.0/8 -j RETURN"), r.take(2))
        assertEquals("-A AIGUARD_CN -j REJECT", r.last())
        assertEquals(4, r.size)
    }

    @Test
    fun lockdownNeverPassesTun() {
        val r = rules(FirewallBuilder.filter4(FirewallPolicy.Lockdown, ctx))
        assertFalse(r.any { "-o aiguard" in it })
        assertEquals("-A AIGUARD_OUT -j REJECT", r.last())
    }

    @Test
    fun everyPolicyBlocksIPv6AndRedirectsDns() {
        for (p in listOf(FirewallPolicy.LeakGuard(tun), FirewallPolicy.Basic(tun), FirewallPolicy.Lockdown, FirewallPolicy.Whitelist(tun, true, emptyList()))) {
            val v6 = rules(FirewallBuilder.filter6(p))
            assertEquals("-A AIGUARD_OUT6 -j REJECT", v6.last())
            assertTrue("464XLAT 不能被拦", v6.any { "--uid-owner ${FirewallBuilder.AID_CLAT}" in it })
            val nat = rules(FirewallBuilder.nat4(p, ctx))
            assertEquals("-A AIGUARD_DNS -m owner --uid-owner 0 -j RETURN", nat.first())
            assertTrue(nat.contains("-A AIGUARD_DNS -p udp --dport 53 -j REDIRECT --to-ports ${Ports.DNS}"))
        }
    }

    @Test
    fun cidrValidation() {
        assertTrue(FirewallBuilder.isIPv4Cidr("1.2.3.0/24"))
        assertTrue(FirewallBuilder.isIPv4Cidr("8.8.8.8"))
        assertFalse(FirewallBuilder.isIPv4Cidr("1.2.3.0/33"))
        assertFalse(FirewallBuilder.isIPv4Cidr("1.2.3/24"))
        assertFalse(FirewallBuilder.isIPv4Cidr("::1/128"))
        assertNotNull(FirewallBuilder.cnChain(emptyList()))
    }
}
