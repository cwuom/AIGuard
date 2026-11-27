package com.aiguard.core

/** 防火墙策略，对应 macOS 版的 pf 策略 */
sealed interface FirewallPolicy {
    /** 不加载任何规则 */
    data object None : FirewallPolicy

    /** 平时：普通进程只能经 TUN 出站，绕过 TUN 直连外网（泄漏）一律拒绝 */
    data class LeakGuard(val tun: String) : FirewallPolicy

    /** 关闭防泄漏层时仍然保留：IPv6 封锁 + DNS 防泄漏 */
    data class Basic(val tun: String) : FirewallPolicy

    /**
     * 熔断（大陆白名单）：任何进程只能连大陆 IP；内核（root）额外可连节点/订阅服务器用于恢复；
     * allowTun 为 true 时放行进入 TUN 的流量，由内核按域名只放大陆直连（闸门确认 REJECT 后才放）
     */
    data class Whitelist(val tun: String, val allowTun: Boolean, val allow: List<String>) : FirewallPolicy

    /** 熔断（全部断网）：只留回环、局域网、DHCP、基带，以及 root（内核需要连节点做探测） */
    data object Lockdown : FirewallPolicy

    val name: String
        get() = when (this) {
            None -> "none"
            is LeakGuard -> "leakGuard"
            is Basic -> "basic"
            is Whitelist -> "whitelist"
            Lockdown -> "lockdown"
        }
}

/** 规则里用到的本机参数；appUid 是界面 App 的 uid，只有它和 root 能连控制端口 */
data class FirewallContext(
    val appUid: Int?,
    val controllerPort: Int = Ports.CONTROLLER,
    val daemonPort: Int = Ports.DAEMON,
    val probePorts: List<Int> = listOf(Ports.PROBE, Ports.DIRECT_PROBE),
    val dnsPort: Int = Ports.DNS,
    val bootstrapDNS: List<String> = MihomoConfigBuilder.bootstrapDNS,
)

object FirewallBuilder {
    const val CHAIN = "AIGUARD_OUT"
    const val CN_CHAIN = "AIGUARD_CN"
    const val CHAIN6 = "AIGUARD_OUT6"
    const val DNS_CHAIN = "AIGUARD_DNS"

    /** 基带（VoLTE/IMS、短信）与 464XLAT 的 uid：运营商流量不是 AI 服务，拦了会打不了电话或断网 */
    const val AID_RADIO = 1001
    const val AID_CLAT = 1029

    val lan = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32")

    /** filter 表 IPv4 主链。None 返回 null，由调用方拆除 */
    fun filter4(policy: FirewallPolicy, ctx: FirewallContext): String? {
        if (policy == FirewallPolicy.None) return null
        val r = mutableListOf<String>()
        fun add(rule: String) = r.add("-A $CHAIN $rule")

        // 控制端口与探测入站：本机其他 App 连不上，避免借道绕过闸门或拿到控制权
        val control = "${ctx.controllerPort},${ctx.daemonPort}"
        add("-o lo -p tcp -m multiport --dports $control -m owner --uid-owner 0 -j RETURN")
        ctx.appUid?.takeIf { it >= 10000 }?.let { add("-o lo -p tcp -m multiport --dports $control -m owner --uid-owner $it -j RETURN") }
        add("-o lo -p tcp -m multiport --dports $control -j REJECT --reject-with tcp-reset")
        val probes = ctx.probePorts.joinToString(",")
        add("-o lo -p tcp -m multiport --dports $probes -m owner --uid-owner 0 -j RETURN")
        add("-o lo -p tcp -m multiport --dports $probes -j REJECT --reject-with tcp-reset")
        add("-o lo -j RETURN")

        val tun = when (policy) {
            is FirewallPolicy.LeakGuard -> policy.tun
            is FirewallPolicy.Basic -> policy.tun
            is FirewallPolicy.Whitelist -> policy.tun
            else -> null
        }
        // 接口名不合法时宁可按全部断网处理，也不能拼出一条放行所有接口的规则
        if (tun != null && !isValidInterface(tun)) return filter4(FirewallPolicy.Lockdown, ctx)
        val passTun = when (policy) {
            is FirewallPolicy.Whitelist -> policy.allowTun
            is FirewallPolicy.LeakGuard, is FirewallPolicy.Basic -> true
            else -> false
        }
        if (passTun) add("-o $tun -j RETURN")

        // DNS 防泄漏：普通进程的 53 端口已在 nat 表重定向到内核；root 只能发往内核的引导 DNS 与局域网（酒店 DHCP DNS）
        val rootDnsTargets = ctx.bootstrapDNS.filter(::isIPv4).map { "$it/32" } + lan
        for (dst in rootDnsTargets) {
            add("-d $dst -p udp --dport 53 -m owner --uid-owner 0 -j RETURN")
            add("-d $dst -p tcp --dport 53 -m owner --uid-owner 0 -j RETURN")
        }
        add("-p udp -m multiport --dports 53,853 -j REJECT")
        add("-p tcp -m multiport --dports 53,853 -j REJECT --reject-with tcp-reset")

        if (policy is FirewallPolicy.Basic) return restore("filter", listOf(CHAIN), r)

        for (dst in lan) add("-d $dst -j RETURN")
        add("-p udp --sport 68 --dport 67 -j RETURN")
        add("-m owner --uid-owner $AID_RADIO -j RETURN")

        when (policy) {
            is FirewallPolicy.LeakGuard, FirewallPolicy.Lockdown -> {
                add("-m owner --uid-owner 0 -j RETURN")
                add("-p tcp -j REJECT --reject-with tcp-reset")
                add("-j REJECT")
            }
            is FirewallPolicy.Whitelist -> {
                for (ip in policy.allow.filter(::isIPv4).distinct().take(MAX_ALLOW)) {
                    add("-d $ip/32 -m owner --uid-owner 0 -j RETURN")
                }
                // 大陆 IP 链：命中返回到这里再放行，其余在链内拒绝，所以它必须是最后一条
                add("-j $CN_CHAIN")
            }
        }
        return restore("filter", listOf(CHAIN), r)
    }

    /** 大陆 IPv4 段链只在规则库变化时重建，避免每次切换策略都重写几千条规则 */
    fun cnChain(cidrs: List<String>): String {
        val r = cidrs.filter(::isIPv4Cidr).distinct().map { "-A $CN_CHAIN -d $it -j RETURN" }.toMutableList()
        r.add("-A $CN_CHAIN -p tcp -j REJECT --reject-with tcp-reset")
        r.add("-A $CN_CHAIN -j REJECT")
        return restore("filter", listOf(CN_CHAIN), r)
    }

    /** IPv6：内核不用 IPv6，除回环、链路本地、组播和运营商流量外全部拒绝 */
    fun filter6(policy: FirewallPolicy): String? {
        if (policy == FirewallPolicy.None) return null
        val r = listOf(
            "-A $CHAIN6 -o lo -j RETURN",
            "-A $CHAIN6 -d fe80::/10 -j RETURN",
            "-A $CHAIN6 -d ff00::/8 -j RETURN",
            "-A $CHAIN6 -m owner --uid-owner $AID_RADIO -j RETURN",
            "-A $CHAIN6 -m owner --uid-owner $AID_CLAT -j RETURN",
            "-A $CHAIN6 -p tcp -j REJECT --reject-with tcp-reset",
            "-A $CHAIN6 -j REJECT",
        )
        return restore("filter", listOf(CHAIN6), r)
    }

    /** nat 表：普通进程发往任何地址的 53 端口查询都重定向到内核 DNS，TUN 劫持失效时 DNS 也不会漏出 */
    fun nat4(policy: FirewallPolicy, ctx: FirewallContext): String? {
        if (policy == FirewallPolicy.None) return null
        val r = listOf(
            "-A $DNS_CHAIN -m owner --uid-owner 0 -j RETURN",
            "-A $DNS_CHAIN -p udp --dport 53 -j REDIRECT --to-ports ${ctx.dnsPort}",
            "-A $DNS_CHAIN -p tcp --dport 53 -j REDIRECT --to-ports ${ctx.dnsPort}",
        )
        return restore("nat", listOf(DNS_CHAIN), r)
    }

    /** iptables-restore --noflush 输入：声明链（已存在则清空）后整体提交，切换策略是原子的 */
    private fun restore(table: String, chains: List<String>, rules: List<String>): String = buildString {
        append("*").append(table).append('\n')
        for (c in chains) append(':').append(c).append(" - [0:0]\n")
        for (rule in rules) append(rule).append('\n')
        append("COMMIT\n")
    }

    const val MAX_ALLOW = 512

    fun isIPv4(s: String): Boolean {
        val parts = s.split('.')
        return parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.length <= 3 && p.all(Char::isDigit) && p.toInt() <= 255 }
    }

    fun isIPv4Cidr(s: String): Boolean {
        val i = s.indexOf('/')
        if (i < 0) return isIPv4(s)
        val bits = s.substring(i + 1)
        return isIPv4(s.substring(0, i)) && bits.isNotEmpty() && bits.length <= 2 && bits.all(Char::isDigit) && bits.toInt() <= 32
    }

    private val ifacePattern = Regex("^[A-Za-z0-9_.-]{1,15}$")

    /** 接口名会拼进规则，只接受内核允许的普通名字 */
    fun isValidInterface(name: String): Boolean = ifacePattern.matches(name) && name != "lo"
}
