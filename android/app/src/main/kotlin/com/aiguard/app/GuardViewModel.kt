package com.aiguard.app

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aiguard.core.GroupName
import com.aiguard.core.GuardEvent
import com.aiguard.core.GuardSettings
import com.aiguard.core.GuardStatus
import com.aiguard.core.IpcRequest
import com.aiguard.core.IpcResponse
import com.aiguard.core.MihomoApi
import com.aiguard.core.PROTOCOL_VERSION
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.IOException

sealed interface DaemonState {
    data object Checking : DaemonState

    /** 从没装过，或者 App 数据被清除丢了 token */
    data object NotInstalled : DaemonState
    data class Unreachable(val reason: String) : DaemonState
    data object AuthFailed : DaemonState
    data object Connected : DaemonState
}

class GuardViewModel(app: Application) : AndroidViewModel(app) {
    private val client = DaemonClient(app)
    private val installer = RootInstaller(app, client)

    private val _daemon = MutableStateFlow<DaemonState>(DaemonState.Checking)
    val daemon: StateFlow<DaemonState> = _daemon.asStateFlow()
    private val _status = MutableStateFlow<GuardStatus?>(null)
    val status: StateFlow<GuardStatus?> = _status.asStateFlow()
    private val _settings = MutableStateFlow<GuardSettings?>(null)
    val settings: StateFlow<GuardSettings?> = _settings.asStateFlow()
    private val _events = MutableStateFlow<List<GuardEvent>>(emptyList())
    val events: StateFlow<List<GuardEvent>> = _events.asStateFlow()

    /** 正在执行的操作名，界面据此禁用按钮并显示进度 */
    private val _busy = MutableStateFlow<String?>(null)
    val busy: StateFlow<String?> = _busy.asStateFlow()
    private val _installLog = MutableStateFlow<String?>(null)
    val installLog: StateFlow<String?> = _installLog.asStateFlow()
    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 8)
    val messages: SharedFlow<String> = _messages.asSharedFlow()

    private var eventsCursor = 0
    private var eventsGeneration: String? = null
    private var controller: MihomoApi? = null

    @Volatile
    private var foreground = false

    val appVersion: String = BuildConfig.VERSION_NAME

    init {
        viewModelScope.launch {
            var tick = 0
            while (isActive) {
                if (foreground) {
                    refresh(withEvents = tick % 3 == 0)
                    tick++
                }
                delay(1000)
            }
        }
    }

    fun setForeground(value: Boolean) {
        foreground = value
    }

    private suspend fun refresh(withEvents: Boolean) {
        if (client.token == null) {
            _daemon.value = DaemonState.NotInstalled
            return
        }
        try {
            val r = client.request(IpcRequest.Status, timeoutMs = 5000)
            if (!r.ok && r.error?.startsWith("认证失败") == true) {
                _daemon.value = DaemonState.AuthFailed
                return
            }
            r.status?.let { _status.value = it }
            _daemon.value = DaemonState.Connected
            if (_settings.value == null) client.request(IpcRequest.GetSettings).settings?.let { _settings.value = it }
            if (withEvents) loadEvents()
        } catch (e: CancellationException) {
            throw e
        } catch (e: IOException) {
            _daemon.value = DaemonState.Unreachable(e.message ?: "连接失败")
            controller = null
        } catch (e: kotlinx.serialization.SerializationException) {
            _daemon.value = DaemonState.Unreachable("守护进程版本与 App 不兼容，请升级守护进程")
        }
    }

    private suspend fun loadEvents() {
        val r = client.request(IpcRequest.Events(eventsCursor))
        val list = r.events ?: return
        if (r.eventsGeneration != eventsGeneration) {
            eventsGeneration = r.eventsGeneration
            _events.value = list
        } else if (list.isNotEmpty()) {
            _events.value = (_events.value + list).takeLast(300)
        }
        eventsCursor = _events.value.lastOrNull()?.id ?: 0
    }

    val daemonOutdated: Boolean
        get() {
            val s = _status.value ?: return false
            return s.protocol != PROTOCOL_VERSION || s.version != appVersion
        }

    /** 统一执行控制请求：失败时弹出原因，成功时用返回的状态刷新界面 */
    private fun act(label: String, req: IpcRequest, success: String? = null, after: (IpcResponse) -> Unit = {}) {
        if (_busy.value != null) return
        viewModelScope.launch {
            _busy.value = label
            try {
                val r = client.request(req, timeoutMs = 60_000)
                r.status?.let { _status.value = it }
                r.settings?.let { _settings.value = it }
                if (r.ok) {
                    success?.let { _messages.tryEmit(it) }
                    after(r)
                } else {
                    _messages.tryEmit(r.error ?: "$label 失败")
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: IOException) {
                _messages.tryEmit("$label 失败：${e.message}")
            } finally {
                _busy.value = null
            }
        }
    }

    fun updateSettings(transform: (GuardSettings) -> GuardSettings) {
        val cur = _settings.value ?: return
        val next = transform(cur)
        if (next == cur) return
        // 先乐观更新，失败时守护进程返回的设置会覆盖回来
        _settings.value = next
        act("保存设置", IpcRequest.UpdateSettings(next))
    }

    fun importSubscription(url: String) = act("导入订阅", IpcRequest.ImportSubscription(url.trim()), "订阅已导入")
    fun refreshSubscription() = act("更新订阅", IpcRequest.RefreshSubscription, "订阅已更新")
    fun removeSubscription() = act("移除订阅", IpcRequest.RemoveSubscription, "订阅已移除")
    fun tripFuse() = act("手动熔断", IpcRequest.TripFuse)
    fun restore(force: Boolean) = act(if (force) "强制恢复" else "重新验证", IpcRequest.RestoreNetwork(force))
    fun captiveLogin(minutes: Int) = act("Wi-Fi 登录模式", IpcRequest.CaptiveLogin(minutes), "$minutes 分钟内直连，AI 仍被阻断")
    fun endCaptiveLogin() = act("结束 Wi-Fi 登录", IpcRequest.EndCaptiveLogin)
    fun restartCore() = act("重启内核", IpcRequest.RestartCore, "内核已重启，正在重新验证线路")
    fun flushConnections() = act("断开全部连接", IpcRequest.FlushConnections, "已断开全部连接")
    fun clearEvents() = act("清空事件", IpcRequest.ClearEvents) {
        _events.value = emptyList()
        eventsCursor = 0
        eventsGeneration = it.eventsGeneration
    }

    fun installDaemon() {
        if (_busy.value != null) return
        viewModelScope.launch {
            _busy.value = "安装守护进程"
            try {
                val root = installer.checkRoot()
                if (!root.ok) {
                    _installLog.value = "没有拿到 root 权限。请在 KernelSU 管理器 →「超级用户」里允许「AI 出差管家」，然后重试。\n\n${root.log}"
                    return@launch
                }
                val r = installer.install()
                _installLog.value = if (r.ok) null else "安装失败：\n${r.log}"
                if (r.ok) {
                    _messages.tryEmit("守护进程已安装，开机会自动启动")
                    _settings.value = null
                    controller = null
                    _daemon.value = DaemonState.Checking
                }
            } finally {
                _busy.value = null
            }
        }
    }

    fun uninstallDaemon(purge: Boolean) {
        if (_busy.value != null) return
        viewModelScope.launch {
            _busy.value = "卸载守护进程"
            try {
                val r = installer.uninstall(purge)
                _messages.tryEmit(if (r.ok) "守护进程已卸载，防火墙与系统设置已恢复" else "卸载失败：${r.log.takeLast(300)}")
                if (r.ok) {
                    _status.value = null
                    _settings.value = null
                    _daemon.value = DaemonState.Unreachable("守护进程已卸载")
                }
            } finally {
                _busy.value = null
            }
        }
    }

    fun dismissInstallLog() {
        _installLog.value = null
    }

    // region 内核控制接口（节点、连接）

    private suspend fun api(): MihomoApi? {
        controller?.let { return it }
        val info = runCatching { client.request(IpcRequest.ControllerInfoRequest).controller }.getOrNull() ?: return null
        return MihomoApi(info.baseUrl, info.secret).also { controller = it }
    }

    suspend fun proxies(): Map<String, MihomoApi.ProxyItem> = api()?.proxies().orEmpty()

    suspend fun selectNode(name: String): Boolean {
        val ok = api()?.select(GroupName.PROXY, name) == true
        _messages.tryEmit(if (ok) "已切换到「$name」，正在重新验证出口" else "切换失败")
        return ok
    }

    suspend fun testGroup(group: String): Map<String, Int>? = api()?.groupDelay(group, TEST_URL, 5000)

    suspend fun connections(): MihomoApi.ConnectionsSnapshot? = api()?.connections()

    suspend fun closeConnection(id: String) {
        api()?.closeConnection(id)
    }

    // endregion

    companion object {
        const val TEST_URL = "http://cp.cloudflare.com/generate_204"
    }
}
