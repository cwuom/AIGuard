package com.aiguard.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI

/** 出站模式：代理，或者无代理时的「直连 + 阻断 AI」 */
@Serializable
enum class ProxyMode {
    @SerialName("proxy") PROXY,
    @SerialName("direct") DIRECT,
}

/** 代理模式下的分流方式 */
@Serializable
enum class RoutingMode {
    /** AI 强制走代理，大陆域名/IP 直连，其余走代理 */
    @SerialName("smart") SMART,

    /** 除局域网外全部走代理 */
    @SerialName("global") GLOBAL,
}

/** 熔断时的处置方式 */
@Serializable
enum class FuseAction {
    /** 防火墙切断全部外网 + 内核闸门全部 REJECT */
    @SerialName("cutAll") CUT_ALL,

    /** 大陆白名单：内核按域名、防火墙按 IP 双重把关，只放行大陆 */
    @SerialName("whitelist") WHITELIST,
}

@Serializable
data class SubscriptionUsage(
    val upload: Long,
    val download: Long,
    val total: Long,
    /** 到期时间（epoch 秒） */
    val expire: Long? = null,
) {
    /** 机场给的数值不可信，相加溢出时取上限，避免界面显示负数 */
    val used: Long
        get() {
            val sum = upload + download
            return if (((upload xor sum) and (download xor sum)) < 0) Long.MAX_VALUE else sum
        }

    companion object {
        /** 解析 `subscription-userinfo: upload=1; download=2; total=3; expire=4` */
        fun parse(header: String): SubscriptionUsage? {
            val values = HashMap<String, Long>()
            for (part in header.split(';')) {
                val kv = part.split('=', limit = 2).map { it.trim() }
                if (kv.size != 2) continue
                // 非有限值或越界的浮点数直接丢弃
                val v = kv[1].toLongOrNull()
                    ?: kv[1].toDoubleOrNull()?.takeIf { it.isFinite() && it >= 0 && it < 9.2e18 }?.let { Math.round(it) }
                if (v != null && v >= 0) values[kv[0].lowercase()] = v
            }
            if (values["total"] == null && values["download"] == null) return null
            return SubscriptionUsage(
                upload = values["upload"] ?: 0,
                download = values["download"] ?: 0,
                total = values["total"] ?: 0,
                expire = values["expire"]?.takeIf { it > 0 },
            )
        }
    }
}

@Serializable
data class SubscriptionInfo(
    val url: String,
    val name: String? = null,
    /** epoch 毫秒 */
    val lastUpdated: Long? = null,
    val nodeCount: Int = 0,
    val usage: SubscriptionUsage? = null,
    val lastError: String? = null,
) {
    /** 订阅链接本身就是凭据，界面和日志只展示脱敏版本 */
    val maskedUrl: String
        get() {
            val uri = runCatching { URI(url) }.getOrNull() ?: return "••••"
            val host = uri.host ?: return "••••"
            val path = uri.rawPath.orEmpty()
            val tail = if (path.length > 4) path.takeLast(4) else ""
            return "${uri.scheme ?: "https"}://$host/••••$tail"
        }

    val host: String? get() = runCatching { URI(url).host?.lowercase() }.getOrNull()
}

@Serializable
data class GuardSettings(
    val schema: Int = CURRENT_SCHEMA,
    val enabled: Boolean = true,
    val mode: ProxyMode = ProxyMode.PROXY,
    val routing: RoutingMode = RoutingMode.SMART,

    val fuseEnabled: Boolean = true,
    val fuseAction: FuseAction = FuseAction.WHITELIST,
    val autoRecover: Boolean = true,
    /** 长连接心跳间隔（秒），每次心跳同时校验出口国家 */
    val probeIntervalSeconds: Int = 2,
    val failureThreshold: Int = 2,
    val latencyThresholdMs: Int = 3000,
    val recoverSuccesses: Int = 4,
    /** 网络切换后至少保持熔断的秒数 */
    val networkHoldSeconds: Int = 4,
    /** 出口禁区：出口国家落在这里即熔断，节点名匹配到的地区也不会被自动选中 */
    val forbiddenRegions: List<String> = listOf("CN", "HK", "MO"),
    val autoSwitchUnsafeNode: Boolean = true,
    /** 熔断时强行停止 AI App 与浏览器 */
    val closeAppsOnFuse: Boolean = true,
    /** 启动、换网这类保护性熔断也关闭应用（默认不关：此时防火墙已经只放行大陆） */
    val closeAppsOnGuardTrips: Boolean = false,

    /** 普通 App 绕过 TUN 直连外网一律拒绝 */
    val leakGuard: Boolean = true,
    /** 直连模式只放行大陆域名/IP，其余全部拒绝：名单外的 AI 服务也无法直连 */
    val directOnlyMainland: Boolean = true,
    /** 守护开启时关闭 Wi-Fi/有线网卡的 IPv6（蜂窝网卡保留给 464XLAT），关闭守护时恢复 */
    val disableSystemIPv6: Boolean = true,
    /** 守护开启时关闭系统「私人 DNS」（DoT 会绕过 TUN 的 DNS 劫持），关闭守护时恢复 */
    val lockPrivateDns: Boolean = true,
    val disabledAICategories: List<String> = emptyList(),
    val customAIDomains: List<String> = emptyList(),
    val customDirectDomains: List<String> = emptyList(),
    /** 智能分流下强制走代理的域名，用来纠正大陆名单误收的境外站点 */
    val customProxyDomains: List<String> = emptyList(),
    /** 熔断时额外要强行停止的 App 包名 */
    val extraAIPackages: List<String> = emptyList(),
    val subscription: SubscriptionInfo? = null,
    val subscriptionUpdateHours: Int = 12,
) {
    /** 把越界的数值收回安全范围，防止界面或手改文件导致探测风暴或永不熔断 */
    fun sanitized(): GuardSettings {
        var regions = normalizeRegions(forbiddenRegions)
        // 大陆出口永远视为违规，用户无法把它从禁区里删掉
        if ("CN" !in regions) regions = listOf("CN") + regions
        return copy(
            schema = CURRENT_SCHEMA,
            probeIntervalSeconds = probeIntervalSeconds.coerceIn(1, 10),
            failureThreshold = failureThreshold.coerceIn(1, 20),
            latencyThresholdMs = latencyThresholdMs.coerceIn(300, 10_000),
            recoverSuccesses = recoverSuccesses.coerceIn(1, 30),
            networkHoldSeconds = networkHoldSeconds.coerceIn(0, 60),
            subscriptionUpdateHours = subscriptionUpdateHours.coerceIn(1, 168),
            forbiddenRegions = regions,
            customAIDomains = DomainSanitizer.clean(customAIDomains),
            customDirectDomains = DomainSanitizer.clean(customDirectDomains),
            customProxyDomains = DomainSanitizer.clean(customProxyDomains),
            extraAIPackages = PackageNames.clean(extraAIPackages),
        )
    }

    companion object {
        const val CURRENT_SCHEMA = 1

        fun normalizeRegions(list: List<String>): List<String> {
            val seen = HashSet<String>()
            return list.map { it.trim().uppercase() }
                .filter { it.length == 2 && it.all { c -> c in 'A'..'Z' } && seen.add(it) }
        }
    }
}

object DomainSanitizer {
    /** 只保留合法域名字符，去掉协议、路径、前导点，防止注入到 YAML 规则里 */
    fun clean(list: List<String>): List<String> {
        val seen = LinkedHashSet<String>()
        for (raw in list) {
            var s = raw.trim().lowercase()
            s.indexOf("://").takeIf { it >= 0 }?.let { s = s.substring(it + 3) }
            s.indexOf('/').takeIf { it >= 0 }?.let { s = s.substring(0, it) }
            s = s.trimStart('.', '*', '+')
            if (s.isEmpty() || s.length > 253 || '.' !in s || s.endsWith('.') || ".." in s) continue
            if (!s.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '.' }) continue
            seen.add(s)
        }
        return seen.toList()
    }
}

object PackageNames {
    private val pattern = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$")

    fun isValid(name: String): Boolean = name.length <= 255 && pattern.matches(name)

    /** 包名会拼进 am 命令，只接受合法的 Java 包名 */
    fun clean(list: List<String>): List<String> =
        list.map { it.trim() }.filter(::isValid).distinct()
}
