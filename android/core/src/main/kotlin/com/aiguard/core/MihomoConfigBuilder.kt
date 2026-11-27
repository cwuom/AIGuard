package com.aiguard.core

/** mihomo 里的策略组名称。闸门组只给守护进程用，界面不展示 */
object GroupName {
    const val PROXY = "节点选择"
    const val AUTO = "自动选择"
    const val GATE_AI = "AIGUARD-GATE-AI"
    const val GATE_MAIN = "AIGUARD-GATE-MAIN"
    const val GATE_DIRECT = "AIGUARD-GATE-DIRECT"

    /** 大陆流量闸门：智能分流=DIRECT，全局=节点选择，白名单熔断=DIRECT，全部断网=REJECT */
    const val GATE_CN = "AIGUARD-GATE-CN"
    const val INTERNAL_PREFIX = "AIGUARD-"
    const val PROVIDER = "sub"
}

/** 守护进程运行期参数（端口、密钥等），与用户设置分开 */
data class CoreRuntime(
    val secret: String,
    val listenerPassword: String,
    val hasSubscription: Boolean,
    val controllerPort: Int = Ports.CONTROLLER,
    val listenerUser: String = "aiguard",
    /** 带认证的探测入站，直通「节点选择」，不经过规则和闸门（心跳长连接、出口检测、订阅下载用） */
    val probePort: Int = Ports.PROBE,
    val directProbePort: Int = Ports.DIRECT_PROBE,
    val dnsPort: Int = Ports.DNS,
    val tunDevice: String = TUN_DEVICE,
) {
    companion object {
        const val TUN_DEVICE = "aiguard"
        const val TUN_ADDRESS = "198.18.0.1"
    }
}

/** 本机回环端口。防火墙只允许 root 与界面 App 连控制端口，探测入站只允许 root */
object Ports {
    const val CONTROLLER = 19097
    const val PROBE = 17892
    const val DIRECT_PROBE = 17893
    const val DNS = 1053
    const val DAEMON = 19190
}

object MihomoConfigBuilder {
    /** 订阅里的流量/到期提示「节点」 */
    private const val INFO_NODE_WORDS = "剩余|流量|到期|过期|有效期|expire|官网|网址|重置|套餐|订阅|traffic|频道|群组|telegram|客服|公告"

    /** 按出口禁区生成节点排除正则：禁区里的地区不会被自动选中，避免反复熔断 */
    fun excludeFilter(regions: List<String>, extra: List<String> = emptyList()): String {
        val parts = regions.map(RegionNames::nodePattern) + extra + INFO_NODE_WORDS
        return "(?i)(" + parts.joinToString("|") + ")"
    }

    /** 单线路的节点排除：出口禁区 + 回国/直连 + AI 服务不支持的俄罗斯 */
    fun nodeExcludeFilter(s: GuardSettings): String =
        excludeFilter(s.sanitized().forbiddenRegions, listOf("回国|直连|俄罗斯|russia"))

    val privateCIDRs = listOf(
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "100.64.0.0/10", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32",
    )
    const val TEST_URL = "http://cp.cloudflare.com/generate_204"
    const val AUTO_CHECK_INTERVAL_SECONDS = 600

    /** 内核自己的明文 DNS 只发往这几个大陆公共 DNS；防火墙据此放行 root 的 53 端口 */
    val bootstrapDNS = listOf("223.5.5.5", "119.29.29.29")

    // DNS 服务器全部用 IP，不依赖系统解析；连接方式写死在 # 后缀里，不经过分流规则和闸门，
    // 熔断时（闸门 REJECT）内核自己的解析仍然可用，订阅下载和节点探测不会被卡住
    val domesticDoH = listOf("https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query")
    val foreignDoH = listOf("https://1.1.1.1/dns-query#${GroupName.PROXY}", "https://8.8.8.8/dns-query#${GroupName.PROXY}")

    /**
     * 智能分流下强制走代理的域名：内置检测站 + 用户名单。
     * 用户直连名单的规则排在前面，被它（本身或父域）覆盖的域名路由上本来就直连，DNS 也不能再给它走代理
     */
    fun forceProxyDomains(s: GuardSettings): List<String> {
        val direct = DomainSanitizer.clean(s.customDirectDomains)
        return DomainSanitizer.clean(ForceProxyCatalog.suffixes + s.customProxyDomains).filter { d ->
            direct.none { d == it || d.endsWith(".$it") }
        }
    }

    fun effectiveMode(settings: GuardSettings, rt: CoreRuntime): ProxyMode =
        if (rt.hasSubscription) settings.mode else ProxyMode.DIRECT

    private val wifiInterface = Regex("^(wlan|eth)[0-9]{1,2}$")

    /**
     * captive=true 表示 Wi-Fi 登录模式：直连且不限大陆，方便打开认证页（AI 仍拒绝）。
     * captiveInterface 是当前物理网卡，登录模式下用它的 DHCP DNS 解析认证页
     */
    fun build(raw: GuardSettings, rt: CoreRuntime, captive: Boolean = false, captiveInterface: String? = null): String {
        val s = raw.sanitized()
        val mode = if (captive) ProxyMode.DIRECT else effectiveMode(s, rt)
        val y = YamlWriter()

        y.line("allow-lan: false")
        y.line("mode: rule")
        y.line("log-level: warning")
        y.line("ipv6: false")
        y.line("unified-delay: true")
        y.line("tcp-concurrent: true")
        y.line("find-process-mode: off")
        y.line("geo-auto-update: false")
        y.line("external-controller: ${q("127.0.0.1:${rt.controllerPort}")}")
        y.line("secret: ${q(rt.secret)}")
        y.line("skip-auth-prefixes: []")
        y.line("profile:")
        y.line("  store-selected: true")
        y.line("  store-fake-ip: true")

        // TUN 接管全部流量（含 root 与系统进程）；绕过 TUN 的流量由防火墙兜底拒绝
        y.line("tun:")
        y.line("  enable: true")
        y.line("  stack: mixed")
        y.line("  device: ${q(rt.tunDevice)}")
        y.line("  auto-route: true")
        y.line("  auto-detect-interface: true")
        y.line("  dns-hijack: [${q("any:53")}, ${q("tcp://any:53")}]")

        y.line("sniffer:")
        y.line("  enable: true")
        y.line("  force-dns-mapping: true")
        y.line("  parse-pure-ip: true")
        y.line("  override-destination: true")
        y.line("  sniff:")
        y.line("    HTTP: {ports: [80, 8080-8880]}")
        y.line("    TLS: {ports: [443, 8443]}")
        y.line("    QUIC: {ports: [443, 8443]}")
        y.line("  skip-domain: [${q("Mijia Cloud")}, ${q("+.push.apple.com")}]")

        y.line("dns:")
        y.line("  enable: true")
        // 防火墙把普通 App 的 53 端口查询全部重定向到这里，TUN 失效时 DNS 也不会漏出
        y.line("  listen: ${q("127.0.0.1:${rt.dnsPort}")}")
        y.line("  ipv6: false")
        y.line("  cache-algorithm: arc")
        y.line("  enhanced-mode: fake-ip")
        y.line("  fake-ip-range: 198.18.0.1/16")
        y.line("  fake-ip-filter-mode: blacklist")
        // NTP 域名不能放进过滤表：拿到真实 IP 后域名规则就匹配不到了
        y.list(
            "  fake-ip-filter",
            listOf(
                "rule-set:cn-site", "*.lan", "*.local", "*.localdomain", "*.home.arpa", "+.msftconnecttest.com",
                "+.msftncsi.com", "localhost.ptlogin2.qq.com", "+.stun.*.*", "+.stun.*.*.*",
            ),
        )
        y.list("  default-nameserver", bootstrapDNS)
        y.list("  proxy-server-nameserver", domesticDoH)
        y.list("  direct-nameserver", domesticDoH)
        if (mode == ProxyMode.PROXY && rt.hasSubscription) {
            // 境外域名经代理走 DoH，运营商看不到查询；大陆域名用国内 DoH
            y.list("  nameserver", foreignDoH)
            y.line("  nameserver-policy:")
            // 按书写顺序取第一个匹配，顺序与分流规则一致：用户直连 > 强制代理 > 大陆名单
            val domestic = domesticDoH.joinToString(", ") { q(it) }
            val foreign = foreignDoH.joinToString(", ") { q(it) }
            for (d in s.customDirectDomains) y.line("    ${q("+.$d")}: [$domestic]")
            // 强制代理的域名必须排在大陆名单前面，否则会被国内 DoH 解析
            for (d in forceProxyDomains(s)) y.line("    ${q("+.$d")}: [$foreign]")
            y.line("    ${q("rule-set:cn-site")}: [$domestic]")
        } else if (captive && captiveInterface != null && wifiInterface.matches(captiveInterface)) {
            // 酒店认证页通常只能用 DHCP 下发的 DNS 解析
            y.list("  nameserver", listOf("dhcp://$captiveInterface") + domesticDoH)
        } else {
            y.list("  nameserver", domesticDoH)
        }

        if (rt.hasSubscription) {
            y.line("proxy-providers:")
            y.line("  ${GroupName.PROVIDER}:")
            y.line("    type: file")
            y.line("    path: ${q("./providers/sub.yaml")}")
            y.line("    health-check: {enable: false}")
        }

        y.line("rule-providers:")
        for (r in BundledRuleSets.all) {
            y.line("  ${r.provider}: {type: file, behavior: ${r.behavior}, format: mrs, path: ${q("./rules/${r.file}")}}")
        }

        y.line("proxy-groups:")
        if (rt.hasSubscription) {
            val exclude = nodeExcludeFilter(s)
            group(y, GroupName.PROXY, "select", listOf(GroupName.AUTO), use = true, exclude = exclude)
            // fallback 只在当前节点失效时才换线，出口 IP 最稳定，AI 账号不容易触发风控。
            // 体检要经每个节点握手一次，是最大的额外流量：平时 10 分钟一次，
            // 当前节点连续失败由内核（max-failed-times）和守护进程（心跳失败）立即触发体检，换线速度不受影响
            group(
                y, GroupName.AUTO, "fallback", emptyList(), use = true, exclude = exclude,
                extra = listOf(
                    "url: ${q(TEST_URL)}", "interval: $AUTO_CHECK_INTERVAL_SECONDS", "timeout: 3000",
                    "max-failed-times: 2", "lazy: false", "expected-status: 204",
                ),
            )
            group(y, GroupName.GATE_AI, "select", listOf(GroupName.PROXY, "REJECT"))
            // 主闸门不含 DIRECT：任何熔断都不会让境外流量（包括名单外的 AI）直连
            group(y, GroupName.GATE_MAIN, "select", listOf(GroupName.PROXY, "REJECT"))
            group(y, GroupName.GATE_CN, "select", listOf("DIRECT", GroupName.PROXY, "REJECT"))
        } else {
            group(y, GroupName.GATE_AI, "select", listOf("REJECT"))
            group(y, GroupName.GATE_MAIN, "select", listOf("REJECT"))
            group(y, GroupName.GATE_CN, "select", listOf("DIRECT", "REJECT"))
        }
        group(y, GroupName.GATE_DIRECT, "select", listOf("DIRECT", "REJECT"))

        // 探测/订阅专用入站：绕过闸门直连指定策略组，带认证，防火墙另外只放 root 连接
        y.line("listeners:")
        fun listener(name: String, port: Int, proxy: String) {
            y.line("  - name: ${q(name)}")
            y.line("    type: http")
            y.line("    listen: ${q("127.0.0.1")}")
            y.line("    port: $port")
            y.line("    proxy: ${q(proxy)}")
            y.line("    users: [{username: ${q(rt.listenerUser)}, password: ${q(rt.listenerPassword)}}]")
        }
        if (rt.hasSubscription) listener("aiguard-probe", rt.probePort, GroupName.PROXY)
        listener("aiguard-direct", rt.directProbePort, "DIRECT")

        y.list("rules", rules(s, mode, captive))
        return y.text
    }

    fun rules(s: GuardSettings, mode: ProxyMode, captive: Boolean = false): List<String> {
        val r = mutableListOf<String>()
        for (cidr in privateCIDRs) r.add("IP-CIDR,$cidr,DIRECT,no-resolve")
        r.add("DOMAIN-SUFFIX,local,DIRECT")
        r.add("DOMAIN-SUFFIX,lan,DIRECT")

        val aiTarget = if (mode == ProxyMode.PROXY) GroupName.GATE_AI else "REJECT"
        if (mode == ProxyMode.PROXY) {
            // 境外 QUIC 经代理不稳定，拒绝后浏览器会立即回落 TCP
            r.add("AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((RULE-SET,cn-site)))),REJECT")
        }
        for (line in AIRuleCatalog.ruleLines(s.disabledAICategories, s.customAIDomains)) {
            r.add(if (line.startsWith("IP-CIDR")) "$line,$aiTarget,no-resolve" else "$line,$aiTarget")
        }
        for (d in s.customDirectDomains) r.add("DOMAIN-SUFFIX,$d,${GroupName.GATE_DIRECT}")

        when {
            mode == ProxyMode.DIRECT && s.directOnlyMainland && !captive -> {
                // 只放行大陆：名单之外的 AI 服务也到不了。大陆名单误收的境外站点在它之前拒绝
                for (d in forceProxyDomains(s)) r.add("DOMAIN-SUFFIX,$d,REJECT")
                r.add("RULE-SET,cn-site,${GroupName.GATE_DIRECT}")
                r.add("RULE-SET,cn-ip,${GroupName.GATE_DIRECT}")
                r.add("MATCH,REJECT")
            }
            mode == ProxyMode.DIRECT -> r.add("MATCH,${GroupName.GATE_DIRECT}")
            else -> {
                // 大陆名单会误收境外站点，强制代理的域名必须排在它前面；走主闸门，熔断时一并拒绝
                for (d in forceProxyDomains(s)) r.add("DOMAIN-SUFFIX,$d,${GroupName.GATE_MAIN}")
                // 智能/全局的区别由大陆闸门决定，切换分流方式不需要重载配置
                r.add("RULE-SET,cn-site,${GroupName.GATE_CN}")
                r.add("RULE-SET,cn-ip,${GroupName.GATE_CN}")
                r.add("MATCH,${GroupName.GATE_MAIN}")
            }
        }
        return r
    }

    private fun group(
        y: YamlWriter, name: String, type: String, proxies: List<String>, use: Boolean = false,
        exclude: String? = null, extra: List<String> = emptyList(),
    ) {
        y.line("  - name: ${q(name)}")
        y.line("    type: $type")
        if (proxies.isNotEmpty()) y.line("    proxies: [${proxies.joinToString(", ") { q(it) }}]")
        if (use) y.line("    use: [${q(GroupName.PROVIDER)}]")
        if (exclude != null) y.line("    exclude-filter: ${q(exclude)}")
        for (e in extra) y.line("    $e")
    }
}

/** YAML 双引号标量与 JSON 字符串兼容，统一用它转义，避免节点名/正则破坏结构 */
fun q(s: String): String = buildString {
    append('"')
    for (ch in s) {
        when {
            ch == '"' -> append("\\\"")
            ch == '\\' -> append("\\\\")
            ch == '\n' -> append("\\n")
            ch == '\r' -> append("\\r")
            ch == '\t' -> append("\\t")
            ch.code < 0x20 -> append("\\u%04X".format(ch.code))
            else -> append(ch)
        }
    }
    append('"')
}

class YamlWriter {
    private val sb = StringBuilder()
    val text: String get() = sb.toString()

    fun line(s: String) {
        sb.append(s).append('\n')
    }

    fun list(key: String, items: List<String>) {
        val indent = key.takeWhile { it == ' ' }
        if (items.isEmpty()) {
            line("$key: []")
            return
        }
        line("$key:")
        for (i in items) line("$indent  - ${q(i)}")
    }
}
