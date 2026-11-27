package com.aiguard.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** 界面与守护进程之间的协议版本；不一致时界面提示升级守护进程 */
const val PROTOCOL_VERSION = 1

val AIGuardJson = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    explicitNulls = false
    coerceInputValues = true
    classDiscriminator = "type"
}

/** 守护进程在 root 下的文件布局 */
object DaemonPaths {
    const val ROOT = "/data/adb/aiguard"
    const val APK = "$ROOT/aiguard.apk"
    const val TOKEN = "$ROOT/ipc_token"
    const val APP_UID = "$ROOT/app_uid"
    const val UNINSTALL_FLAG = "$ROOT/uninstalling"
    const val SERVICE_SCRIPT = "/data/adb/service.d/aiguard.sh"
}

@Serializable
enum class GuardPhase {
    @SerialName("disabled") DISABLED,
    @SerialName("starting") STARTING,
    @SerialName("protected") PROTECTED,
    @SerialName("tripped") TRIPPED,
    @SerialName("error") ERROR,
}

@Serializable
data class ExitStatus(
    val trace: ExitTrace? = null,
    /** epoch 毫秒 */
    val checkedAt: Long? = null,
    val error: String? = null,
)

@Serializable
data class LatencySample(
    /** epoch 毫秒 */
    val at: Long,
    /** 长连接心跳往返毫秒数，null 表示失败 */
    val ms: Int? = null,
)

@Serializable
data class GuardStatus(
    val version: String = "",
    val protocol: Int = PROTOCOL_VERSION,
    val phase: GuardPhase = GuardPhase.STARTING,
    val effectiveMode: ProxyMode = ProxyMode.DIRECT,
    val routing: RoutingMode = RoutingMode.SMART,
    val fuse: FuseSnapshot = FuseSnapshot.ARMED,
    /** 熔断开始的墙钟时间（epoch 毫秒） */
    val fuseSince: Long? = null,
    /** 距离保持期结束还剩多少毫秒 */
    val fuseHoldRemainingMs: Long? = null,
    val fuseLatched: Boolean = false,
    val coreRunning: Boolean = false,
    val coreVersion: String? = null,
    val coreRestarts: Int = 0,
    val tunUp: Boolean = false,
    val tunInterface: String? = null,
    val firewallPolicy: String = "none",
    /** null 表示还没检测过 */
    val ipv6Blocked: Boolean? = null,
    /** 系统层面已关闭 IPv6 的网卡数 */
    val ipv6DisabledInterfaces: Int = 0,
    val privateDnsLocked: Boolean = false,
    val exit: ExitStatus = ExitStatus(),
    val heartbeatAlive: Boolean = false,
    val latency: List<LatencySample> = emptyList(),
    val primaryInterface: String? = null,
    val conflicts: List<String> = emptyList(),
    val subscription: SubscriptionInfo? = null,
    /** Wi-Fi 登录模式结束时间（epoch 毫秒） */
    val captiveUntil: Long? = null,
    val lastError: String? = null,
    val nodeCount: Int? = null,
    val updatedAt: Long = 0,
)

@Serializable
enum class EventLevel {
    @SerialName("info") INFO,
    @SerialName("warning") WARNING,
    @SerialName("critical") CRITICAL,
}

@Serializable
data class GuardEvent(val id: Int, val at: Long, val level: EventLevel, val message: String)

@Serializable
data class ControllerInfo(val baseUrl: String, val secret: String)

@Serializable
sealed interface IpcRequest {
    @Serializable @SerialName("status") data object Status : IpcRequest
    @Serializable @SerialName("getSettings") data object GetSettings : IpcRequest
    @Serializable @SerialName("updateSettings") data class UpdateSettings(val settings: GuardSettings) : IpcRequest
    @Serializable @SerialName("importSubscription") data class ImportSubscription(val url: String) : IpcRequest
    @Serializable @SerialName("refreshSubscription") data object RefreshSubscription : IpcRequest
    @Serializable @SerialName("removeSubscription") data object RemoveSubscription : IpcRequest
    @Serializable @SerialName("tripFuse") data object TripFuse : IpcRequest
    @Serializable @SerialName("restoreNetwork") data class RestoreNetwork(val force: Boolean) : IpcRequest
    @Serializable @SerialName("captiveLogin") data class CaptiveLogin(val minutes: Int) : IpcRequest
    @Serializable @SerialName("endCaptiveLogin") data object EndCaptiveLogin : IpcRequest
    @Serializable @SerialName("controllerInfo") data object ControllerInfoRequest : IpcRequest
    @Serializable @SerialName("events") data class Events(val after: Int) : IpcRequest
    @Serializable @SerialName("clearEvents") data object ClearEvents : IpcRequest
    @Serializable @SerialName("flushConnections") data object FlushConnections : IpcRequest
    @Serializable @SerialName("restartCore") data object RestartCore : IpcRequest
}

/** 一行 JSON：token 由界面在安装守护进程时生成，root 保存，其他 App 读不到 */
@Serializable
data class IpcEnvelope(val token: String, val request: IpcRequest)

@Serializable
data class IpcResponse(
    val ok: Boolean = true,
    val error: String? = null,
    val status: GuardStatus? = null,
    val settings: GuardSettings? = null,
    val controller: ControllerInfo? = null,
    val events: List<GuardEvent>? = null,
    /** 事件列表代号：变化说明守护进程重启或清空过，旧的增量游标作废 */
    val eventsGeneration: String? = null,
) {
    companion object {
        fun failure(message: String) = IpcResponse(ok = false, error = message)
        const val MAX_MESSAGE_BYTES = 4 * 1024 * 1024
    }
}

/** 按数字逐段比较版本号（"1.10.0" > "1.9.2"），非数字段按 0 处理 */
fun compareVersions(a: String, b: String): Int {
    val x = a.split('.').map { it.toIntOrNull() ?: 0 }
    val y = b.split('.').map { it.toIntOrNull() ?: 0 }
    for (i in 0 until maxOf(x.size, y.size)) {
        val l = x.getOrElse(i) { 0 }
        val r = y.getOrElse(i) { 0 }
        if (l != r) return l.compareTo(r)
    }
    return 0
}
