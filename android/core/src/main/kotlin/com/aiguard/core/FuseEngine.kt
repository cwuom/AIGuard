package com.aiguard.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed interface FuseReason {
    @Serializable @SerialName("starting") data object Starting : FuseReason
    @Serializable @SerialName("networkChanged") data object NetworkChanged : FuseReason
    @Serializable @SerialName("coreDown") data object CoreDown : FuseReason
    @Serializable @SerialName("tunLost") data object TunLost : FuseReason

    /** 能直连公网 IPv6：防火墙的 IPv6 封锁失效 */
    @Serializable @SerialName("ipv6Leak") data object Ipv6Leak : FuseReason
    @Serializable @SerialName("proxyUnstable") data class ProxyUnstable(val failures: Int) : FuseReason
    @Serializable @SerialName("unsafeExit") data class UnsafeExit(val country: String) : FuseReason
    @Serializable @SerialName("manual") data object Manual : FuseReason

    /** 守护类原因：状态恢复正常后总是自动解除，不受「自动恢复」开关影响 */
    val isTransientGuard: Boolean
        get() = when (this) {
            Starting, NetworkChanged, CoreDown, TunLost, Ipv6Leak -> true
            is ProxyUnstable, is UnsafeExit, Manual -> false
        }

    /** 启动/换网：防火墙已只放行大陆的预防性熔断 */
    val isPrecautionary: Boolean get() = this == Starting || this == NetworkChanged

    val title: String
        get() = when (this) {
            Starting -> "启动保护：等待内核与线路就绪"
            NetworkChanged -> "网络切换保护：等待新网络稳定"
            CoreDown -> "代理内核未运行"
            TunLost -> "TUN 路由丢失，流量可能绕过代理"
            Ipv6Leak -> "检测到 IPv6 可以直连公网，防火墙封锁失效"
            is ProxyUnstable -> "代理不稳定：长连接心跳连续 $failures 次失败"
            is UnsafeExit -> "出口落在 ${RegionNames.name(country)}（$country）"
            Manual -> "手动熔断"
        }

    /** 已熔断时，轻微原因不覆盖严重原因的显示 */
    val priority: Int
        get() = when (this) {
            Manual -> 5
            is UnsafeExit -> 4
            CoreDown, TunLost, Ipv6Leak -> 3
            is ProxyUnstable -> 2
            NetworkChanged -> 1
            Starting -> 0
        }
}

data class FuseConfig(
    val enabled: Boolean,
    val action: FuseAction,
    val autoRecover: Boolean,
    val failureThreshold: Int,
    val latencyThresholdMs: Int,
    val recoverSuccesses: Int,
    val networkHoldMs: Long,
    val forbidden: Set<String>,
    val mode: ProxyMode,
) {
    companion object {
        fun from(raw: GuardSettings, effectiveMode: ProxyMode): FuseConfig {
            val s = raw.sanitized()
            return FuseConfig(
                enabled = s.fuseEnabled,
                action = s.fuseAction,
                autoRecover = s.autoRecover,
                failureThreshold = s.failureThreshold,
                latencyThresholdMs = s.latencyThresholdMs,
                recoverSuccesses = s.recoverSuccesses,
                networkHoldMs = s.networkHoldSeconds * 1000L,
                forbidden = s.forbiddenRegions.toSet(),
                mode = effectiveMode,
            )
        }
    }
}

sealed interface FuseSignal {
    data class Health(val coreUp: Boolean, val tunUp: Boolean) : FuseSignal

    /** 长连接心跳：往返毫秒数（null 表示失败） */
    data class Probe(val ms: Int?) : FuseSignal

    /** 出口地区检测：null 表示没测出来（不算违规也不算通过） */
    data class Geo(val country: String?) : FuseSignal
    data class Ipv6(val leaking: Boolean) : FuseSignal
    data object NetworkChanged : FuseSignal
    data object ManualTrip : FuseSignal
    data class ManualRestore(val force: Boolean) : FuseSignal
    data object Reset : FuseSignal
}

/** 时间字段都是单调时钟毫秒（守护进程用 elapsedRealtime，深睡眠也计时），展示前由调用方换算成墙钟 */
@Serializable
data class FuseSnapshot(
    val tripped: Boolean = false,
    val hard: Boolean = false,
    val reason: FuseReason? = null,
    val since: Long? = null,
    val holdUntil: Long? = null,
    val recoverProgress: Int = 0,
    val recoverNeeded: Int = 0,
    val geoVerified: Boolean = false,
    val consecutiveFailures: Int = 0,
) {
    companion object {
        val ARMED = FuseSnapshot()
    }
}

/** 纯逻辑熔断状态机：输入探测信号，输出是否熔断、是否硬切断。所有副作用由守护进程执行 */
class FuseEngine(config: FuseConfig, now: Long, startTripped: Boolean = true) {
    var config: FuseConfig = config
        private set
    var snapshot: FuseSnapshot = FuseSnapshot.ARMED
        private set
    private var coreUp = false
    private var tunUp = false
    private var successes = 0
    private var geoOKSinceTrip = false

    /** 非守护类原因且关闭了自动恢复（或手动熔断）时上锁，只能由用户解除 */
    var isLatched = false
        private set
    private var ipv6Leaking = false

    init {
        if (config.enabled && startTripped) trip(FuseReason.Starting, now, holdMs = 0)
    }

    fun update(new: FuseConfig, now: Long) {
        val modeChanged = new.mode != config.mode
        config = new
        if (!new.enabled) {
            snapshot = FuseSnapshot.ARMED
            return
        }
        // 切换出站模式后需要重新验证线路，按启动保护处理
        if (modeChanged) trip(FuseReason.Starting, now, holdMs = 0)
        if (snapshot.tripped) snapshot = snapshot.copy(hard = new.action == FuseAction.CUT_ALL)
        refreshNeeded()
    }

    /** 内核重启：按启动保护重新验证，但保留手动锁和未到期的保持期 */
    fun coreRestarted(now: Long) {
        if (!config.enabled) return
        coreUp = false
        tunUp = false
        trip(FuseReason.Starting, now, holdMs = 0)
    }

    /** 返回 true 表示熔断状态发生了变化 */
    fun handle(signal: FuseSignal, now: Long): Boolean {
        val before = snapshot
        if (!config.enabled) {
            if (signal is FuseSignal.Health) {
                coreUp = signal.coreUp
                tunUp = signal.tunUp
            }
            snapshot = FuseSnapshot.ARMED
            return before != snapshot
        }
        when (signal) {
            FuseSignal.Reset -> recover()
            is FuseSignal.Health -> {
                coreUp = signal.coreUp
                tunUp = signal.tunUp
                if (!signal.coreUp) trip(FuseReason.CoreDown, now, 0)
                else if (!signal.tunUp) trip(FuseReason.TunLost, now, 0)
                tryRecover(now)
            }
            FuseSignal.NetworkChanged -> trip(FuseReason.NetworkChanged, now, config.networkHoldMs)
            FuseSignal.ManualTrip -> trip(FuseReason.Manual, now, 0, force = true)
            is FuseSignal.ManualRestore -> {
                if (signal.force) {
                    recover()
                } else if (snapshot.tripped) {
                    // 普通的手动恢复只解锁，仍然要通过健康检查和出口验证才放行
                    isLatched = false
                    tryRecover(now)
                }
            }
            is FuseSignal.Probe -> handleProbe(probeOK(signal.ms), now)
            is FuseSignal.Geo -> handleGeo(signal.country, now)
            is FuseSignal.Ipv6 -> {
                ipv6Leaking = signal.leaking
                if (signal.leaking) trip(FuseReason.Ipv6Leak, now, 0) else tryRecover(now)
            }
        }
        return before != snapshot
    }

    private fun probeOK(ms: Int?): Boolean {
        if (config.mode != ProxyMode.PROXY) return true
        return ms != null && ms <= config.latencyThresholdMs
    }

    private fun handleProbe(ok: Boolean, now: Long) {
        if (config.mode == ProxyMode.DIRECT) {
            snapshot = snapshot.copy(consecutiveFailures = 0)
            tryRecover(now)
            return
        }
        if (ok) {
            snapshot = snapshot.copy(consecutiveFailures = 0)
            if (snapshot.tripped) successes += 1
        } else {
            snapshot = snapshot.copy(consecutiveFailures = snapshot.consecutiveFailures + 1)
            successes = 0
            if (snapshot.consecutiveFailures >= config.failureThreshold) {
                trip(FuseReason.ProxyUnstable(snapshot.consecutiveFailures), now, 0)
            }
        }
        snapshot = snapshot.copy(recoverProgress = minOf(successes, snapshot.recoverNeeded))
        tryRecover(now)
    }

    private fun handleGeo(country: String?, now: Long) {
        if (config.mode != ProxyMode.PROXY) return
        if (country != null && country in config.forbidden) {
            trip(FuseReason.UnsafeExit(country), now, 0, force = true)
            return
        }
        // 只有出口明确测到且安全才算验证通过，测不出来不能放行
        if (country != null) {
            geoOKSinceTrip = true
            snapshot = snapshot.copy(geoVerified = true)
        }
        tryRecover(now)
    }

    private fun trip(reason: FuseReason, now: Long, holdMs: Long, force: Boolean = false) {
        // 白名单模式下所有原因都只开大陆白名单（防火墙按 IP 把关，内核/TUN 故障时同样安全）
        val hard = config.action == FuseAction.CUT_ALL
        val current = snapshot.reason
        val keepReason = snapshot.tripped && !force && current != null && reason.priority < current.priority
        val wasTripped = snapshot.tripped
        if (reason == FuseReason.Manual || (!reason.isTransientGuard && !config.autoRecover)) isLatched = true
        val until = now + holdMs
        snapshot = snapshot.copy(
            tripped = true,
            reason = if (keepReason) current else reason,
            // 硬切断一旦生效，直到恢复前都不降级为软熔断
            hard = if (wasTripped) snapshot.hard || hard else hard,
            since = if (wasTripped) snapshot.since else now,
            holdUntil = maxOf(snapshot.holdUntil ?: until, until),
            geoVerified = false,
            recoverProgress = 0,
        )
        successes = 0
        geoOKSinceTrip = false
        refreshNeeded()
    }

    private fun refreshNeeded() {
        snapshot = snapshot.copy(recoverNeeded = if (config.mode == ProxyMode.PROXY) config.recoverSuccesses else 0)
    }

    private fun tryRecover(now: Long) {
        if (!snapshot.tripped || snapshot.reason == null || isLatched) return
        val hold = snapshot.holdUntil
        if (hold != null && now < hold) return
        if (!coreUp || !tunUp || ipv6Leaking) return
        if (config.mode == ProxyMode.PROXY && (successes < config.recoverSuccesses || !geoOKSinceTrip)) return
        recover()
    }

    private fun recover() {
        snapshot = FuseSnapshot.ARMED
        successes = 0
        geoOKSinceTrip = false
        isLatched = false
    }
}

object RegionNames {
    private val table = mapOf(
        "CN" to "中国大陆", "HK" to "香港", "MO" to "澳门", "TW" to "台湾", "JP" to "日本", "KR" to "韩国",
        "SG" to "新加坡", "US" to "美国", "GB" to "英国", "DE" to "德国", "FR" to "法国", "NL" to "荷兰",
        "CA" to "加拿大", "AU" to "澳大利亚", "RU" to "俄罗斯", "IN" to "印度", "MY" to "马来西亚", "TH" to "泰国",
        "VN" to "越南", "PH" to "菲律宾", "ID" to "印度尼西亚", "TR" to "土耳其", "AE" to "阿联酋", "IR" to "伊朗",
        "KP" to "朝鲜", "CH" to "瑞士", "SE" to "瑞典", "IT" to "意大利", "ES" to "西班牙",
    )

    fun name(code: String): String = table[code.uppercase()] ?: code

    /** 节点名里常见的地区写法（中文、英文、代码、城市/机场代码、旗帜） */
    private val nodeWords = mapOf(
        "CN" to "中国|大陆|china|(?<![a-z])cn(?![a-z0-9])|上海|北京|广州|深圳|杭州|🇨🇳",
        "HK" to "港|hong ?kong|(?<![a-z])hk(?![a-z])|hkg|🇭🇰",
        "MO" to "澳门|澳門|macau|macao|(?<![a-z])mo(?![a-z0-9])|🇲🇴",
        "US" to "美国|美國|united ?states|america|(?<![a-z])usa?(?![a-z])|洛杉矶|圣何塞|硅谷|西雅图|纽约|芝加哥|达拉斯|凤凰城|波特兰|弗吉尼亚|迈阿密|亚特兰大|(?<![a-z])(lax|sjc|sea|nyc|jfk|ord|dfw|iad|mia|atl|pdx)(?![a-z])|🇺🇸",
        "TW" to "台湾|台灣|taiwan|(?<![a-z])tw(?![a-z])|🇹🇼",
        "JP" to "日本|japan|(?<![a-z])jp(?![a-z])|东京|大阪|🇯🇵",
        "SG" to "新加坡|狮城|singapore|(?<![a-z])sg(?![a-z])|🇸🇬",
        "KR" to "韩国|韓國|korea|(?<![a-z])kr(?![a-z])|首尔|🇰🇷",
        "RU" to "俄罗斯|russia|(?<![a-z])ru(?![a-z])|🇷🇺",
        "GB" to "英国|united ?kingdom|(?<![a-z])(uk|gb)(?![a-z])|伦敦|🇬🇧",
        "DE" to "德国|germany|(?<![a-z])de(?![a-z])|法兰克福|🇩🇪",
    )

    fun nodePattern(code: String): String {
        val c = code.uppercase()
        nodeWords[c]?.let { return it }
        // 未收录的地区：中文名 + 国家代码 + 旗帜
        val parts = mutableListOf("(?<![a-z])${c.lowercase()}(?![a-z])", flag(c))
        table[c]?.let { parts.add(0, it) }
        return parts.joinToString("|")
    }

    fun flag(code: String): String = buildString {
        for (ch in code.uppercase()) appendCodePoint(0x1F1E6 + (ch - 'A'))
    }
}
