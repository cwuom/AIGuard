package com.aiguard.daemon

import android.os.SystemClock
import com.aiguard.core.AIGuardJson
import com.aiguard.core.ControllerInfo
import com.aiguard.core.CoreRuntime
import com.aiguard.core.EventLevel
import com.aiguard.core.ExitStatus
import com.aiguard.core.FirewallBuilder
import com.aiguard.core.FirewallContext
import com.aiguard.core.FirewallPolicy
import com.aiguard.core.FuseConfig
import com.aiguard.core.FuseEngine
import com.aiguard.core.FuseReason
import com.aiguard.core.FuseSignal
import com.aiguard.core.GroupName
import com.aiguard.core.GuardEvent
import com.aiguard.core.GuardPhase
import com.aiguard.core.GuardSettings
import com.aiguard.core.GuardStatus
import com.aiguard.core.IpcRequest
import com.aiguard.core.IpcResponse
import com.aiguard.core.LatencySample
import com.aiguard.core.MihomoApi
import com.aiguard.core.MihomoConfigBuilder
import com.aiguard.core.ParsedSubscription
import com.aiguard.core.ProxiedFetcher
import com.aiguard.core.ProxyMode
import com.aiguard.core.RegionNames
import com.aiguard.core.RoutingMode
import com.aiguard.core.SubscriptionException
import com.aiguard.core.SubscriptionInfo
import com.aiguard.core.SubscriptionParser
import com.aiguard.core.SubscriptionUsage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import java.io.File
import java.io.IOException
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Serializable
private data class RuntimeSecrets(val secret: String, val listenerPassword: String)

/**
 * 守护进程总控：所有状态都在同一个单线程调度器上修改（等价于 macOS 版的 actor），
 * 挂起点之间可能插入别的请求，跨挂起点的结果用 epoch / gateGeneration 判断是否过期。
 * 两个循环：1 秒一次的健康检查（内核、TUN 路由、IPv6、换网），以及经代理的长连接心跳（延迟 + 出口国家）
 */
class Guardian(private val selfPackage: String, private val version: String) {
    private val ctx = Executors.newSingleThreadExecutor { Thread(it, "guardian") }.asCoroutineDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + ctx)
    private val io = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var settings: GuardSettings
    private var runtime: CoreRuntime
    private val api: MihomoApi
    private val fetcher: ProxiedFetcher
    private val firewall = Firewall(Paths.cnTable)
    private val core = CoreProcess(Paths.mihomo, Paths.coreHome, Paths.coreConfig, Paths.logs)
    private val ipv6Switch = Ipv6Switch(File(Paths.state, "ipv6.json"))
    private val privateDns = PrivateDnsLock(File(Paths.state, "private_dns.json"))
    private val closer = AppCloser(selfPackage)
    private var engine: FuseEngine
    private val appUid: Int? = runCatching { Paths.appUid.readText().trim().toInt() }.getOrNull()

    private var events = ArrayList<GuardEvent>()
    private var nextEventId = 1
    private var eventsGeneration = UUID.randomUUID().toString()
    private var eventsDirty = false
    private val latency = ArrayList<LatencySample>()
    private var exitStatus = ExitStatus()
    private var heartbeatAlive = false
    private var coreVersion: String? = null
    private var apiUp = false
    private var tunUp = false
    private var tunInterface: String? = null
    private var primaryInterface: String? = null
    private var lastFingerprint: String? = null
    private var conflicts: List<String> = emptyList()
    private var lastError: String? = null
    private var nodeCount: Int? = null

    /** 单调时钟（elapsedRealtime，深睡眠也计时） */
    private var captiveUntil: Long? = null
    private var apiFailures = 0
    private var wantCore = false
    private var nextRestartAt: Long? = null
    private var restartBackoffMs = 1000L
    private var coreStartedAt: Long? = null
    private val appliedGates = HashMap<String, String>()
    private var switchingNode = false
    private var lastTripped = false

    /** 本次熔断是否已经关过应用：同一次熔断只关一次浏览器，用户手动重开的不会被反复关掉 */
    private var appsClosedThisTrip = false

    /** 启动后第一次恢复之前不关应用：启动/升级阶段内核还没起来，不是真实故障 */
    private var armedOnce = false

    /** 最近一次由我们主动启动或重载内核的时间，之后 20 秒内的内核/TUN 异常属于正常过渡 */
    private var lastCoreTransition: Long? = null

    /** 白名单熔断时闸门是否已确认写成 REJECT；确认之前不放行进入 TUN 的流量 */
    private var softGatesConfirmed = false

    /** 进出熔断、内核重启/重载时加一；跨挂起点的闸门确认据此丢弃过期结果 */
    private var gateGeneration = 0

    /** 内核启动/重载进行中（可嵌套）：这期间闸门回读不可信，不允许确认放行 TUN */
    private var coreTransitions = 0
    private var configApplyPending = false
    private var firewallFailing = false
    private var lastAIScan: Long? = null
    private var tunLostSince: Long? = null
    private var lastAutoRestart: Long? = null
    private var autoRestartCount = 0
    private var restarting = false
    private val trippedFlag = AtomicBoolean(false)
    private var nodeDownLogged = false

    /** 熔断期间允许内核连接的节点服务器/订阅服务器 IPv4（大陆白名单的窄例外） */
    private var allowIPs: List<String> = emptyList()
    private var lastAllowRefresh: Long? = null
    private var lastResolvedNode: String? = null
    private var lastForcedCheck: Long? = null

    /** 网络/节点/配置的代次：探测发出后代次变了，结果作废，防止旧线路的结果为新线路解锁 */
    private var epoch = 0
    private var hookWarningShown = false
    private var ipv6Blocked: Boolean? = null
    private var lastIPv6Check: Long? = null
    private var lastSlowWork: Long? = null
    private var lastSubscriptionCheck: Long? = null
    private var lastFirewallVerify: Long? = null
    private var lastPrivateDnsCheck: Long? = null
    private var bootedAt = 0L
    private var lastTickMono: Long? = null
    private var lastTickUptime = 0L

    init {
        Paths.ensureDirs()
        val loaded = runCatching { AIGuardJson.decodeFromString(GuardSettings.serializer(), Paths.settings.readText()) }.getOrNull()
        settings = (loaded ?: GuardSettings()).sanitized()
        val secrets = runCatching { AIGuardJson.decodeFromString(RuntimeSecrets.serializer(), Paths.runtime.readText()) }.getOrNull()
            ?: RuntimeSecrets(Secrets.random(), Secrets.random()).also {
                runCatching { writeAtomic(Paths.runtime, AIGuardJson.encodeToString(RuntimeSecrets.serializer(), it)) }
            }
        val hasSub = settings.subscription != null && Paths.providerFile.isFile
        runtime = CoreRuntime(secret = secrets.secret, listenerPassword = secrets.listenerPassword, hasSubscription = hasSub)
        api = MihomoApi("http://127.0.0.1:${runtime.controllerPort}", secrets.secret)
        fetcher = ProxiedFetcher(runtime.listenerUser, secrets.listenerPassword)
        engine = FuseEngine(fuseConfig(), mono(), startTripped = settings.enabled)
        runCatching { AIGuardJson.decodeFromString(ListSerializer(GuardEvent.serializer()), Paths.events.readText()) }.getOrNull()?.let {
            events = ArrayList(it.takeLast(300))
            nextEventId = (events.lastOrNull()?.id ?: 0) + 1
        }
    }

    private fun mono() = SystemClock.elapsedRealtime()
    private fun wall() = System.currentTimeMillis()

    // region 生命周期

    fun start() {
        scope.launch {
            boot()
            scope.launch {
                while (isActive) {
                    guarded("健康检查") { tick() }
                    delay(1000)
                }
            }
            scope.launch {
                while (isActive) {
                    var next = 1000L
                    guarded("心跳") { next = heartbeat() }
                    delay(next)
                }
            }
        }
    }

    private suspend fun guarded(what: String, block: suspend () -> Unit) {
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.write("[error] $what 异常：${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private suspend fun boot() {
        bootedAt = mono()
        // 先上防火墙再启动内核：启动阶段默认熔断，内核还没起来时只放行大陆
        firewall.context = FirewallContext(appUid = appUid)
        try {
            val changed = withContext(Dispatchers.IO) { AssetSync.sync(Paths.apk) }
            if (changed.isNotEmpty()) Log.write("[info] 已从 APK 同步：${changed.joinToString()}")
        } catch (e: IOException) {
            lastError = "内核文件同步失败：${e.message}"
            log(EventLevel.CRITICAL, lastError!!)
        }
        core.killStale()
        coreVersion = core.version()
        core.onExit = { code -> scope.launch { coreExited(code) } }
        log(EventLevel.INFO, "守护进程已启动（v$version，mihomo ${coreVersion ?: "版本未知"}）")
        if (appUid == null) log(EventLevel.WARNING, "没有读到界面 App 的 uid，界面可能连不上控制端口；请在 App 里重新安装守护进程")
        saveSettings()
        firewall.apply(desiredPolicy(), force = true)
        applyProtection()
        syncSystemNetwork()
        val ifaces = NetInspector.interfaces()
        lastFingerprint = NetInspector.fingerprint(ifaces)
        primaryInterface = NetInspector.primary(ifaces)
        if (settings.enabled) startCore()
    }

    // endregion

    // region 内核

    private val effectiveMode: ProxyMode
        get() = if (captiveUntil != null) ProxyMode.DIRECT else MihomoConfigBuilder.effectiveMode(settings, runtime)

    private fun buildYaml(): String =
        MihomoConfigBuilder.build(settings, runtime, captive = captiveUntil != null, captiveInterface = primaryInterface)

    private suspend fun startCore() {
        coreTransitions++
        var transitionEnded = false
        try {
            wantCore = true
            lastCoreTransition = mono()
            epoch++
            // 新内核的闸门要重新确认，确认前白名单不放行 TUN；旧内核的闸门缓存一并作废
            softGatesConfirmed = false
            gateGeneration++
            appliedGates.clear()
            try {
                core.writeConfig(buildYaml())
            } catch (e: IOException) {
                lastError = e.message
                log(EventLevel.CRITICAL, "配置生成失败：${e.message}")
                if (!Paths.coreConfig.isFile) return
            }
            try {
                core.start()
                coreStartedAt = mono()
                appliedGates.clear()
            } catch (e: IOException) {
                lastError = "内核启动失败：${e.message}"
                log(EventLevel.CRITICAL, lastError!!)
                nextRestartAt = mono() + restartBackoffMs
                return
            }
            var tries = 0
            while (tries++ < 40) {
                if (api.version() != null) {
                    apiUp = true
                    break
                }
                delay(150)
            }
            transitionEnded = true
            coreTransitions--
            applyProtection()
            applyGates()
        } finally {
            if (!transitionEnded) coreTransitions--
        }
    }

    private fun coreExited(code: Int) {
        apiUp = false
        epoch++
        if (!wantCore) return
        core.noteRestart()
        log(EventLevel.WARNING, "代理内核意外退出（退出码 $code），${restartBackoffMs / 1000} 秒后自动重启")
        engine.handle(FuseSignal.Health(coreUp = false, tunUp = false), mono())
        applyProtection()
        nextRestartAt = mono() + restartBackoffMs
        restartBackoffMs = minOf(restartBackoffMs * 2, 30_000)
    }

    /** 配置相关设置变化后重载；重载失败则整体重启内核。返回 false 表示新配置没能写出，内核仍在用旧规则 */
    private suspend fun reloadCore(reason: String): Boolean {
        if (!wantCore) return true
        coreTransitions++
        var transitionEnded = false
        try {
            epoch++
            lastCoreTransition = mono()
            softGatesConfirmed = false
            gateGeneration++
            appliedGates.clear()
            applyProtection()
            try {
                core.writeConfig(buildYaml())
            } catch (e: IOException) {
                lastError = e.message
                log(EventLevel.CRITICAL, "新配置未生效：${e.message}")
                configApplyPending = true
                return false
            }
            configApplyPending = false
            if (core.isRunning && api.reloadConfig(Paths.coreConfig.path)) {
                log(EventLevel.INFO, "代理配置已更新（$reason）")
            } else {
                log(EventLevel.WARNING, "配置热更新失败，改为重启内核（$reason）${api.lastReloadError?.let { "：$it" } ?: ""}")
                core.stop()
                startCore()
            }
            appliedGates.clear()
            api.flushConnections()
            transitionEnded = true
            coreTransitions--
            applyGates()
            return true
        } finally {
            if (!transitionEnded) coreTransitions--
        }
    }

    // endregion

    // region 防护执行

    private fun desiredPolicy(): FirewallPolicy {
        if (!settings.enabled) return FirewallPolicy.None
        val s = engine.snapshot
        val tun = tunInterface ?: runtime.tunDevice
        if (s.tripped) {
            if (s.hard) return FirewallPolicy.Lockdown
            // 大陆白名单：任何进程只能连大陆 IP；闸门确认 REJECT 之前连 TUN 都不放
            return FirewallPolicy.Whitelist(tun, allowTun = softGatesConfirmed, allow = allowIPs)
        }
        // 关闭防泄漏层也始终封锁 IPv6 和明文 DNS
        return if (settings.leakGuard) FirewallPolicy.LeakGuard(tun) else FirewallPolicy.Basic(tun)
    }

    private fun desiredGates(): Map<String, String> {
        val s = engine.snapshot
        val hasSub = runtime.hasSubscription
        val tripped = s.tripped
        val hard = s.tripped && s.hard
        val cnNormal = if (hasSub && settings.routing == RoutingMode.GLOBAL) GroupName.PROXY else "DIRECT"
        return mapOf(
            GroupName.GATE_AI to if (tripped || !hasSub) "REJECT" else GroupName.PROXY,
            // 白名单熔断只保留大陆直连，境外（包括名单外的 AI）一律拒绝
            GroupName.GATE_MAIN to if (tripped || !hasSub) "REJECT" else GroupName.PROXY,
            GroupName.GATE_CN to if (hard) "REJECT" else if (tripped) "DIRECT" else cnNormal,
            GroupName.GATE_DIRECT to if (hard) "REJECT" else "DIRECT",
        )
    }

    /** 防火墙同步执行（熔断必须立刻生效），内核闸门异步执行 */
    private fun applyProtection() {
        val ok = firewall.apply(desiredPolicy())
        if (!ok && !firewallFailing) {
            lastError = "防火墙规则加载失败：${firewall.lastError ?: "未知原因"}"
            log(EventLevel.CRITICAL, "$lastError，仅剩内核闸门一层防护")
        } else if (ok && firewallFailing) {
            log(EventLevel.INFO, "防火墙规则已恢复正常")
        }
        firewallFailing = !ok
        val snap = engine.snapshot
        trippedFlag.set(snap.tripped)
        if (snap.tripped != lastTripped) {
            lastTripped = snap.tripped
            gateGeneration++
            softGatesConfirmed = false
            if (snap.tripped) {
                log(EventLevel.CRITICAL, "已熔断：${snap.reason?.title.orEmpty()}${if (snap.hard) "（全部断网）" else "（只放行大陆白名单）"}")
            } else {
                appsClosedThisTrip = false
                armedOnce = true
                nodeDownLogged = false
                log(EventLevel.INFO, if (effectiveMode == ProxyMode.PROXY) "已恢复：线路与出口验证通过" else "已恢复：内核与 TUN 就绪，AI 保持阻断")
            }
            scope.launch { applyGates(flush = snap.tripped) }
        }
        closeAppsIfNeeded()
    }

    /** 熔断期间能否关闭应用：启动/重载过渡期、控制接口偶发抖动、保护性熔断（默认）都不关 */
    private fun closeEligible(): Boolean {
        val snap = engine.snapshot
        val reason = snap.reason ?: return false
        if (!snap.tripped || !armedOnce || !settings.enabled || !settings.closeAppsOnFuse) return false
        if (reason.isPrecautionary && !settings.closeAppsOnGuardTrips) return false
        if ((reason == FuseReason.CoreDown || reason == FuseReason.TunLost) &&
            lastCoreTransition?.let { mono() - it < 20_000 } == true) return false
        if (reason == FuseReason.CoreDown && core.isRunning && apiFailures < 3) return false
        return true
    }

    /** 熔断瞬间关一次浏览器 + AI App；之后每 3 秒再扫一遍 AI，确保熔断期间没有 AI 在运行 */
    private fun closeAppsIfNeeded() {
        if (!closeEligible()) return
        val now = mono()
        val kinds = when {
            !appsClosedThisTrip -> {
                appsClosedThisTrip = true
                setOf(AppCloser.Kind.AI, AppCloser.Kind.BROWSER)
            }
            lastAIScan?.let { now - it >= 3000 } ?: true -> setOf(AppCloser.Kind.AI)
            else -> return
        }
        lastAIScan = now
        killApps(kinds, "熔断")
    }

    private fun killApps(kinds: Set<AppCloser.Kind>, reason: String, requireTripped: Boolean = true) {
        val extra = settings.extraAIPackages
        val flag = trippedFlag
        io.launch {
            val closed = runCatching { closer.close(kinds, extra, appUid) { !requireTripped || flag.get() } }.getOrDefault(emptyList())
            if (closed.isNotEmpty()) scope.launch { log(EventLevel.WARNING, "$reason：已关闭 ${closed.joinToString("、")}") }
        }
    }

    /** 手动或自动重启内核：先清场 AI，再按启动保护重新验证线路 */
    private suspend fun restartCore(reason: String) {
        if (restarting) return
        restarting = true
        try {
            log(EventLevel.WARNING, "重启内核：$reason")
            if (settings.closeAppsOnFuse) killApps(setOf(AppCloser.Kind.AI), "重启内核前清场", requireTripped = false)
            epoch++
            // 就地按启动保护重新验证（保留手动锁和保持期），线路和出口都通过才放行
            engine.coreRestarted(mono())
            applyProtection()
            core.stop()
            core.noteRestart()
            apiUp = false
            apiFailures = 0
            tunLostSince = null
            lastAutoRestart = mono()
            fetcher.reset(runtime.probePort)
            lastResolvedNode = null
            startCore()
        } finally {
            restarting = false
        }
    }

    /**
     * 挂起期间可能处理别的请求，旧的放行写入可能晚于新的 REJECT 到达内核。
     * 每次写完都重新核对期望值，不一致就再写一轮
     */
    private suspend fun applyGates(flush: Boolean = false) {
        if (!apiUp) return
        for (round in 0 until 3) {
            var stale = false
            for (group in desiredGates().keys.sorted()) {
                val target = desiredGates()[group] ?: continue
                if (appliedGates[group] == target) continue
                val generation = gateGeneration
                val ok = api.select(group, target)
                // 写入期间内核重启/重载过：结果属于旧内核，不能记账
                if (generation != gateGeneration) {
                    stale = true
                    continue
                }
                if (desiredGates()[group] == target) {
                    if (ok) appliedGates[group] = target
                } else {
                    appliedGates.remove(group)
                    stale = true
                }
            }
            if (!stale) break
            if (round == 2) Log.write("[warning] 闸门三轮写入仍未与期望一致，下一轮健康检查重试")
        }
        // 切换闸门只影响新连接，熔断时必须掐断已有连接
        if (flush) api.flushConnections()
        if (!softGatesReady()) return
        // 先确认熔断前的连接已全部断开再放行 TUN；挂起期间可能又恢复/再熔断，回来后按同一代熔断重新核对
        val generation = gateGeneration
        if (!api.flushConnections() || generation != gateGeneration || !softGatesReady()) return
        softGatesConfirmed = true
        applyProtection()
    }

    private fun softGatesReady(): Boolean {
        val snap = engine.snapshot
        return snap.tripped && !snap.hard && !softGatesConfirmed && coreTransitions == 0 &&
            appliedGates[GroupName.GATE_AI] == "REJECT" && appliedGates[GroupName.GATE_MAIN] == "REJECT"
    }

    /** 守护开启时关闭 Wi-Fi IPv6、关闭私人 DNS；关闭时恢复（settings 命令较慢，放到 IO 线程） */
    private suspend fun syncSystemNetwork() {
        val enabled = settings.enabled
        val v6 = settings.disableSystemIPv6
        val dns = settings.lockPrivateDns
        val ifaces = NetInspector.interfaces().map { it.name }
        val (failed, dnsChanged) = withContext(Dispatchers.IO) {
            val failed = if (enabled && v6) ipv6Switch.disableAll(ifaces) else {
                ipv6Switch.restoreAll()
                emptyList()
            }
            val changed = if (enabled && dns) privateDns.lock() else {
                privateDns.restore()
                false
            }
            failed to changed
        }
        if (failed.isNotEmpty()) log(EventLevel.WARNING, "以下网卡的 IPv6 无法关闭，仅靠防火墙封锁：${failed.joinToString("、")}")
        if (dnsChanged) log(EventLevel.INFO, "已关闭系统「私人 DNS」，DNS 全部交给内核解析（关闭守护时恢复）")
    }

    // endregion

    // region 健康检查（每秒）

    private suspend fun tick() {
        val now = mono()
        captiveUntil?.let { until ->
            if (now >= until) {
                captiveUntil = null
                log(EventLevel.INFO, "Wi-Fi 登录模式结束，恢复正常出站")
                engine.update(fuseConfig(), now)
                applyProtection()
                reloadCore("Wi-Fi 登录结束")
            }
        }
        detectSuspend(now)
        if (!settings.enabled) return

        val restartAt = nextRestartAt
        if (wantCore && !core.isRunning && restartAt != null && now >= restartAt) {
            nextRestartAt = null
            startCore()
        }

        if (core.isRunning) {
            val v = api.version()
            if (v != null) {
                apiUp = true
                apiFailures = 0
            } else {
                apiUp = false
                apiFailures++
                if (apiFailures >= 5) {
                    log(EventLevel.WARNING, "代理内核没有响应，已强制重启")
                    apiFailures = 0
                    core.stop()
                    core.noteRestart()
                    startCore()
                }
            }
        } else {
            apiUp = false
        }
        coreStartedAt?.let { if (now - it > 60_000 && apiUp) restartBackoffMs = 1000 }

        val ifaces = NetInspector.interfaces()
        tunInterface = NetInspector.tunInterface(ifaces)
        val routeIface = if (tunInterface != null) NetInspector.routeInterface(appUid ?: 10000) else null
        // 进程死了立刻判定；进程活着时控制接口要连续 2 次失败才算内核故障，避免一次抖动就熔断
        val coreUp = core.isRunning && apiFailures < 2
        tunUp = coreUp && tunInterface != null && routeIface == tunInterface
        engine.handle(FuseSignal.Health(coreUp, tunUp), mono())

        val fp = NetInspector.fingerprint(ifaces)
        if (lastFingerprint != null && fp != lastFingerprint) {
            lastFingerprint = fp
            networkChanged(NetInspector.primary(ifaces))
        }
        lastFingerprint = fp

        // 其他代理软件会抢路由：内核正常但 TUN 路由持续丢失，就自动重启内核重建
        if (coreUp && !tunUp) {
            if (tunLostSince == null) tunLostSince = now
            val settled = lastCoreTransition?.let { now - it > 20_000 } ?: true
            val cooldown = minOf(60_000L shl autoRestartCount, 600_000L)
            val cooled = lastAutoRestart?.let { now - it > cooldown } ?: true
            if (autoRestartCount >= 5) {
                // 同一次连续故障最多自动重启 5 次，之后交给用户处理，避免无限循环
                if (autoRestartCount == 5) {
                    autoRestartCount++
                    log(EventLevel.CRITICAL, "TUN 路由一直被占用，已停止自动重启。请关闭其他 VPN/代理后点「重启内核」")
                }
            } else if (tunLostSince?.let { now - it >= 8000 } == true && settled && cooled) {
                autoRestartCount++
                restartCore("TUN 路由被破坏（可能是其他 VPN 或代理模块抢占了路由），自动重建")
                return
            }
        } else {
            tunLostSince = null
            if (tunUp && lastAutoRestart?.let { now - it > 120_000 } == true) autoRestartCount = 0
        }

        // IPv6 泄漏：平时 30 秒查一次，熔断中 5 秒一次
        val ipv6Interval = if (engine.snapshot.tripped) 5000 else 30_000
        if (lastIPv6Check?.let { now - it >= ipv6Interval } != false) {
            lastIPv6Check = now
            val leaking = withContext(Dispatchers.IO) { Ipv6Probe.canReachInternet() }
            if (leaking && ipv6Blocked != false) log(EventLevel.CRITICAL, "IPv6 能直连公网，已熔断")
            ipv6Blocked = !leaking
            engine.handle(FuseSignal.Ipv6(leaking), mono())
        }

        // netd 重启会清空 OUTPUT 链：开机头 2 分钟每秒核对，之后每 5 秒
        val verifyInterval = if (now - bootedAt < 120_000) 1000 else 5000
        if (lastFirewallVerify?.let { now - it >= verifyInterval } != false) {
            lastFirewallVerify = now
            firewall.verify()?.let { issue ->
                if (!hookWarningShown) log(EventLevel.CRITICAL, issue)
                hookWarningShown = true
            } ?: run { hookWarningShown = false }
        }

        applyProtection()
        applyGates()
        closeAppsIfNeeded()

        if (lastSlowWork?.let { now - it >= 30_000 } != false) {
            lastSlowWork = now
            slowWork()
        }
        val subCheck = lastSubscriptionCheck
        if (subCheck == null) {
            lastSubscriptionCheck = now
        } else if (now - subCheck > 600_000) {
            lastSubscriptionCheck = now
            autoRefreshSubscription()
        }
    }

    /** 深睡眠后旧的长连接多半已失效：直接丢弃重建，不然头几次心跳会因为死连接超时而误熔断 */
    private fun detectSuspend(now: Long) {
        val up = SystemClock.uptimeMillis()
        val last = lastTickMono
        if (last != null && (now - last) - (up - lastTickUptime) > 10_000) {
            fetcher.resetAll()
            epoch++
            lastIPv6Check = null
        }
        lastTickMono = now
        lastTickUptime = up
    }

    /** 30 秒一次：闸门重下发、冲突软件扫描、节点数、熔断例外地址、私人 DNS 核对、事件落盘 */
    private suspend fun slowWork() {
        // 缓存只用来省请求；定期清空强制重下发，防止内核侧闸门被外部改动后长期不一致
        appliedGates.clear()
        applyGates()
        val mine = core.pids() + android.os.Process.myPid()
        val found = withContext(Dispatchers.IO) { ConflictScanner.scan(mine, Paths.mihomo.path) }
        if (found != conflicts) {
            conflicts = found
            if (found.isNotEmpty()) log(EventLevel.WARNING, "检测到其他代理软件：${found.joinToString("、")}，可能抢占路由")
        }
        if (runtime.hasSubscription && apiUp) {
            nodeCount = api.group(GroupName.PROXY)?.all?.count { it != GroupName.AUTO }
            if (lastAllowRefresh?.let { mono() - it > 600_000 } != false) refreshAllowList()
        }
        if (settings.lockPrivateDns && lastPrivateDnsCheck?.let { mono() - it > 60_000 } != false) {
            lastPrivateDnsCheck = mono()
            if (withContext(Dispatchers.IO) { privateDns.lock() }) {
                log(EventLevel.WARNING, "「私人 DNS」被重新打开，已再次关闭（它会绕过内核的 DNS 防泄漏）")
            }
        }
        persistEvents()
    }

    /** 解析订阅里的节点服务器和订阅服务器，作为白名单熔断的窄例外（只对 root 内核生效）。结果为空时保留上一次的列表 */
    private suspend fun refreshAllowList() {
        val content = runCatching { Paths.providerFile.readText() }.getOrNull() ?: return
        val hosts = (SubscriptionParser.serverHosts(content) + listOfNotNull(settings.subscription?.host)).distinct().sorted().take(2000)
        val port = runtime.directProbePort
        val ips = sortedSetOf<String>()
        for (batch in hosts.chunked(16)) {
            val lists = coroutineScope {
                batch.map { h ->
                    async { if (FirewallBuilder.isIPv4(h)) listOf(h) else fetcher.resolveDirect(h, port) }
                }.awaitAll()
            }
            // 198.18.x 是 fake-ip，不是真实服务器地址
            lists.flatten().filter { FirewallBuilder.isIPv4(it) && !it.startsWith("198.18.") && !it.startsWith("198.19.") }.forEach { ips.add(it) }
        }
        lastAllowRefresh = mono()
        if (ips.isEmpty()) return
        allowIPs = ips.toList()
        applyProtection()
    }

    // endregion

    // region 长连接心跳

    /**
     * 经带认证的探测入站（直通节点选择、不经过闸门）在同一条 TLS 长连接上请求 Cloudflare trace：
     * 一次请求同时得到「代理是否通」「往返延迟」「出口 IP 与国家」。返回下一次心跳前等待的毫秒数
     */
    private suspend fun heartbeat(): Long {
        val interval = settings.probeIntervalSeconds * 1000L
        if (!settings.enabled || !apiUp || effectiveMode != ProxyMode.PROXY || switchingNode) {
            heartbeatAlive = false
            return 1000
        }
        val startEpoch = epoch
        // 先确认当前实际出口节点：「自动选择」换线后旧长连接仍挂在旧节点上，必须重建并作废旧结果
        val resolved = resolvedNode()
        if (startEpoch != epoch) return 200
        if (resolved == null && lastResolvedNode != null) {
            lastResolvedNode = null
            fetcher.reset(runtime.probePort)
            epoch++
        }
        if (resolved != null && resolved.first != lastResolvedNode) {
            lastResolvedNode?.let { log(EventLevel.INFO, "出口节点切换：$it → ${resolved.first}") }
            lastResolvedNode = resolved.first
            fetcher.reset(runtime.probePort)
            epoch++
        }
        // 内核已判定当前节点连不上：不用等心跳超时，直接按失败计。熔断中必须做真实心跳，否则恢复永远攒不够成功次数
        if (!engine.snapshot.tripped && resolved != null && api.isAlive(resolved.second) == false) {
            if (!nodeDownLogged) log(EventLevel.CRITICAL, "当前节点「${resolved.second}」无法连接")
            nodeDownLogged = true
            heartbeatAlive = false
            engine.handle(FuseSignal.Probe(null), mono())
            addLatency(null)
            applyProtection()
            applyGates()
            return minOf(interval, 1000)
        }
        nodeDownLogged = false
        val beatEpoch = epoch
        val timeout = settings.latencyThresholdMs.toLong()
        val start = mono()
        var trace = fetcher.heartbeat(runtime.probePort, timeout)
        if (trace == null) {
            // Cloudflare 偶发失败时用备用源确认一次，与主请求共用同一个超时预算
            trace = fetcher.ipinfo(runtime.probePort, timeout - (mono() - start))
        }
        val ms = trace?.let { (mono() - start).toInt() }
        if (beatEpoch != epoch || !settings.enabled) return 200
        heartbeatAlive = trace != null
        if (trace == null) forceAutoHealthCheck()
        engine.handle(FuseSignal.Probe(ms), mono())
        if (trace != null) {
            exitStatus.trace?.takeIf { it.ip != trace.ip }?.let { old ->
                log(EventLevel.WARNING, "出口 IP 变化：${old.ip}（${old.country}）→ ${trace.ip}（${trace.country}）")
            }
            exitStatus = ExitStatus(trace, wall())
            engine.handle(FuseSignal.Geo(trace.country), mono())
        } else {
            exitStatus = exitStatus.copy(error = "心跳失败")
        }
        addLatency(ms)
        // 先落实熔断（防火墙 + 闸门 + 掐断连接），再慢慢找安全节点
        applyProtection()
        applyGates()
        val country = trace?.country
        if (country != null && country in settings.forbiddenRegions && settings.autoSwitchUnsafeNode) findSafeNode(country)
        // 熔断中加快心跳，恢复更快
        return if (engine.snapshot.tripped) minOf(interval, 1000) else interval
    }

    /**
     * 心跳失败时立刻体检「自动选择」：平时体检 10 分钟一次（省流量），不能等它自己发现节点坏了。
     * 20 秒内只触发一次，避免节点全挂时变成体检风暴；用户手动固定了节点时不需要
     */
    private fun forceAutoHealthCheck() {
        if (lastForcedCheck?.let { mono() - it < 20_000 } == true) return
        lastForcedCheck = mono()
        scope.launch {
            if (api.group(GroupName.PROXY)?.now == GroupName.AUTO) api.groupDelay(GroupName.AUTO, PROBE_URL, 3000)
        }
    }

    private fun addLatency(ms: Int?) {
        latency.add(LatencySample(wall(), ms))
        if (latency.size > 120) latency.subList(0, latency.size - 120).clear()
    }

    /** 「节点选择」最终落到的具体节点（穿透「自动选择」）：first 用于记录切换，second 是真正的节点 */
    private suspend fun resolvedNode(): Pair<String, String>? {
        val now = api.group(GroupName.PROXY)?.now ?: return null
        if (now == GroupName.AUTO) {
            val leaf = api.group(GroupName.AUTO)?.now ?: return null
            return "${GroupName.AUTO}/$leaf" to leaf
        }
        return now to now
    }

    /** 出口落在禁区时逐个试其他节点，找到出口安全的就固定下来 */
    private suspend fun findSafeNode(badCountry: String) {
        if (switchingNode) return
        val info = api.group(GroupName.PROXY) ?: return
        switchingNode = true
        try {
            log(EventLevel.WARNING, "出口落在${RegionNames.name(badCountry)}（禁区），正在寻找出口安全的节点")
            val candidates = info.all.filter { it != GroupName.AUTO && it != info.now }.take(16)
            val ranked = coroutineScope {
                candidates.map { c -> async { c to api.delay(c, PROBE_URL, 3000) } }.awaitAll()
            }.mapNotNull { (n, ms) -> ms?.let { n to it } }.sortedBy { it.second }
            for ((name, _) in ranked.take(6)) {
                if (!api.select(GroupName.PROXY, name)) continue
                epoch++
                // 新节点必须用新连接测，复用旧长连接会测到旧节点的出口
                fetcher.reset(runtime.probePort)
                val candidateEpoch = epoch
                val t = fetcher.exitTrace(runtime.probePort)
                if (t != null && candidateEpoch == epoch && t.country !in settings.forbiddenRegions) {
                    lastResolvedNode = name
                    exitStatus = ExitStatus(t, wall())
                    log(EventLevel.INFO, "已自动切换到「$name」（${RegionNames.name(t.country)}）")
                    engine.handle(FuseSignal.Geo(t.country), mono())
                    return
                }
            }
            api.select(GroupName.PROXY, GroupName.AUTO)
            log(EventLevel.CRITICAL, "没有找到出口安全的节点，继续保持熔断")
        } finally {
            switchingNode = false
        }
    }

    // endregion

    // region 网络

    private suspend fun networkChanged(primary: String?) {
        primaryInterface = primary
        if (!settings.enabled) return
        epoch++
        engine.handle(FuseSignal.NetworkChanged, mono())
        applyProtection()
        log(EventLevel.INFO, "网络已切换（${primary ?: "无网络"}），重新验证线路")
        fetcher.resetAll()
        // 新接入的网卡（USB 网卡、Wi-Fi）也要关 IPv6
        syncSystemNetwork()
        lastIPv6Check = null
        api.flushConnections()
    }

    // endregion

    // region 订阅

    /** 下载顺序：内核直连入站（熔断时也可用，DNS 不经过闸门）→ 代理入站 → 系统网络 */
    private suspend fun downloadSubscription(url: String): Pair<ParsedSubscription, SubscriptionInfo> {
        val ports = buildList {
            if (apiUp) add(runtime.directProbePort)
            if (apiUp && runtime.hasSubscription) add(runtime.probePort)
            add(null)
        }
        var lastErr: Exception = SubscriptionException(SubscriptionException.EMPTY)
        for (port in ports) {
            try {
                val r = fetcher.fetch(url, port, 20_000, maxBytes = 16 shl 20, headers = mapOf("User-Agent" to SUBSCRIPTION_UA))
                if (r.code != 200) throw SubscriptionException.http(r.code)
                val parsed = SubscriptionParser.parse(r.body)
                val usage = r.headers.entries.firstOrNull { it.key.equals("subscription-userinfo", true) }?.let { SubscriptionUsage.parse(it.value) }
                val info = SubscriptionInfo(url, SubscriptionParser.profileName(r.headers), wall(), parsed.nodeCount, usage)
                return parsed to info
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                lastErr = e
                Log.write("订阅下载失败（${port?.let { "入站 $it" } ?: "系统网络"}）：${e.message}")
            }
        }
        throw lastErr
    }

    private suspend fun installSubscription(parsed: ParsedSubscription, info: SubscriptionInfo) {
        val backup = File(Paths.providerFile.path + ".bak")
        if (Paths.providerFile.isFile) Paths.providerFile.copyTo(backup, overwrite = true)
        writeAtomic(Paths.providerFile, parsed.providerContent)
        settings = settings.copy(subscription = info)
        saveSettings()

        epoch++
        if (!runtime.hasSubscription) {
            runtime = runtime.copy(hasSubscription = true)
            engine.update(fuseConfig(), mono())
            applyProtection()
            reloadCore("导入订阅")
        } else if (apiUp) {
            api.reloadProvider(GroupName.PROVIDER)
        }
        // 内核实际解析出 0 个节点时回滚，绝不用坏订阅覆盖能用的旧订阅
        val count = if (apiUp) api.providerCount(GroupName.PROVIDER) else null
        if (count == 0) {
            if (backup.isFile) {
                backup.copyTo(Paths.providerFile, overwrite = true)
                api.reloadProvider(GroupName.PROVIDER)
            }
            throw SubscriptionException(SubscriptionException.NO_NODES)
        }
        if (count != null) {
            settings = settings.copy(subscription = settings.subscription?.copy(nodeCount = count))
            saveSettings()
        }
        refreshAllowList()
    }

    private suspend fun importSubscription(raw: String): IpcResponse {
        val url = SubscriptionParser.validateUrl(raw)?.toString() ?: return IpcResponse.failure(SubscriptionException.INVALID_URL)
        return try {
            val (parsed, info) = downloadSubscription(url)
            installSubscription(parsed, info)
            log(EventLevel.INFO, "订阅已导入：${info.name ?: info.maskedUrl}，${settings.subscription?.nodeCount ?: parsed.nodeCount} 个节点")
            IpcResponse(status = snapshotStatus())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            log(EventLevel.WARNING, "订阅导入失败：${e.message}")
            IpcResponse.failure(e.message ?: "订阅导入失败")
        }
    }

    private suspend fun refreshSubscription(manual: Boolean): IpcResponse {
        val sub = settings.subscription ?: return IpcResponse.failure("还没有导入订阅")
        return try {
            val (parsed, info) = downloadSubscription(sub.url)
            installSubscription(parsed, info.copy(name = info.name ?: sub.name))
            log(EventLevel.INFO, "订阅已更新，${settings.subscription?.nodeCount ?: parsed.nodeCount} 个节点")
            IpcResponse(status = snapshotStatus())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            settings = settings.copy(subscription = sub.copy(lastError = e.message))
            saveSettings()
            log(if (manual) EventLevel.WARNING else EventLevel.INFO, "订阅更新失败（继续使用旧节点）：${e.message}")
            IpcResponse.failure(e.message ?: "订阅更新失败")
        }
    }

    private suspend fun autoRefreshSubscription() {
        val sub = settings.subscription ?: return
        val age = sub.lastUpdated?.let { wall() - it } ?: Long.MAX_VALUE
        if (age > settings.subscriptionUpdateHours * 3_600_000L) refreshSubscription(manual = false)
    }

    // endregion

    // region 控制请求

    suspend fun handle(req: IpcRequest): IpcResponse = withContext(ctx) {
        when (req) {
            IpcRequest.Status -> IpcResponse(status = snapshotStatus())
            IpcRequest.GetSettings -> IpcResponse(settings = settings)
            is IpcRequest.UpdateSettings -> {
                // 设置已落盘但规则没能生效时必须告诉界面，否则用户以为新名单已经在保护
                val error = updateSettings(req.settings)
                IpcResponse(ok = error == null, error = error, status = snapshotStatus(), settings = settings)
            }
            is IpcRequest.ImportSubscription -> importSubscription(req.url)
            IpcRequest.RefreshSubscription -> refreshSubscription(manual = true)
            IpcRequest.RemoveSubscription -> {
                Paths.providerFile.delete()
                File(Paths.providerFile.path + ".bak").delete()
                settings = settings.copy(subscription = null)
                runtime = runtime.copy(hasSubscription = false)
                saveSettings()
                engine.update(fuseConfig(), mono())
                applyProtection()
                reloadCore("移除订阅")
                log(EventLevel.INFO, "订阅已移除，进入直连阻断模式")
                IpcResponse(status = snapshotStatus())
            }
            IpcRequest.TripFuse -> {
                engine.handle(FuseSignal.ManualTrip, mono())
                applyProtection()
                IpcResponse(status = snapshotStatus())
            }
            is IpcRequest.RestoreNetwork -> {
                engine.handle(FuseSignal.ManualRestore(req.force), mono())
                if (req.force) log(EventLevel.WARNING, "用户强制恢复网络（跳过线路验证）")
                applyProtection()
                IpcResponse(status = snapshotStatus())
            }
            is IpcRequest.CaptiveLogin -> {
                val minutes = req.minutes.coerceIn(1, 10)
                captiveUntil = mono() + minutes * 60_000L
                log(EventLevel.INFO, "Wi-Fi 登录模式：$minutes 分钟内直连，AI 仍被阻断")
                engine.update(fuseConfig(), mono())
                applyProtection()
                reloadCore("Wi-Fi 登录")
                IpcResponse(status = snapshotStatus())
            }
            IpcRequest.EndCaptiveLogin -> {
                if (captiveUntil != null) {
                    captiveUntil = mono()
                    tick()
                }
                IpcResponse(status = snapshotStatus())
            }
            IpcRequest.ControllerInfoRequest -> IpcResponse(controller = ControllerInfo(api.baseUrl, runtime.secret))
            is IpcRequest.Events -> {
                // 游标比现有最大编号还大，说明界面拿的是旧编号，返回全部让界面重建
                val cursor = if (req.after >= nextEventId) 0 else req.after
                IpcResponse(events = events.filter { it.id > cursor }, eventsGeneration = eventsGeneration)
            }
            IpcRequest.ClearEvents -> {
                // 先确认空列表已落盘再清内存，否则重启后旧事件会回来；编号不回退
                if (!writeEvents(emptyList())) IpcResponse.failure("事件记录没能写入磁盘，未清空") else {
                    events.clear()
                    eventsDirty = false
                    eventsGeneration = UUID.randomUUID().toString()
                    Log.write("[info] 用户清空了事件记录")
                    IpcResponse(eventsGeneration = eventsGeneration)
                }
            }
            IpcRequest.FlushConnections -> {
                api.flushConnections()
                IpcResponse()
            }
            IpcRequest.RestartCore -> when {
                !settings.enabled -> IpcResponse.failure("守护已关闭")
                restarting -> IpcResponse.failure("内核正在重启")
                else -> {
                    autoRestartCount = 0
                    restartCore("用户手动重启")
                    if (apiUp) IpcResponse(status = snapshotStatus()) else IpcResponse.failure("内核没有启动成功，查看「事件」里的原因")
                }
            }
        }
    }

    /** 返回 null 表示已生效；否则是给用户看的失败原因（设置本身已保存） */
    private suspend fun updateSettings(incoming: GuardSettings): String? {
        val new = incoming.sanitized().copy(subscription = settings.subscription)
        val old = settings
        settings = new
        saveSettings()
        engine.update(fuseConfig(), mono())
        if (old.enabled != new.enabled || old.disableSystemIPv6 != new.disableSystemIPv6 || old.lockPrivateDns != new.lockPrivateDns) {
            syncSystemNetwork()
        }
        if (old.enabled != new.enabled) {
            if (new.enabled) {
                log(EventLevel.INFO, "守护已开启")
                engine = FuseEngine(fuseConfig(), mono(), startTripped = true)
                applyProtection()
                startCore()
            } else {
                log(EventLevel.WARNING, "守护已关闭：防火墙、TUN、私人 DNS 锁定全部撤销，AI 不再受保护")
                wantCore = false
                core.stop()
                apiUp = false
                engine.handle(FuseSignal.Reset, mono())
                applyProtection()
            }
            return null
        }
        applyProtection()
        if (old.routing != new.routing) log(EventLevel.INFO, if (new.routing == RoutingMode.SMART) "已切换到智能分流" else "已切换到全局代理")
        // 分流方式只影响大陆闸门，不需要重载配置
        val configChanged = old.mode != new.mode || old.directOnlyMainland != new.directOnlyMainland ||
            old.disabledAICategories != new.disabledAICategories || old.customAIDomains != new.customAIDomains ||
            old.customDirectDomains != new.customDirectDomains || old.customProxyDomains != new.customProxyDomains ||
            old.forbiddenRegions != new.forbiddenRegions
        var failure: String? = null
        if ((configChanged || configApplyPending) && !reloadCore("设置变更")) {
            failure = "设置已保存，但新规则没能生效（${lastError ?: "配置写入失败"}），内核仍按旧规则运行"
        }
        applyGates()
        return failure
    }

    // endregion

    // region 状态与持久化

    private fun fuseConfig() = FuseConfig.from(settings, effectiveMode)

    private fun snapshotStatus(): GuardStatus {
        val snap = engine.snapshot
        val monoNow = mono()
        val wallNow = wall()
        val phase = when {
            !settings.enabled -> GuardPhase.DISABLED
            snap.tripped -> GuardPhase.TRIPPED
            !apiUp -> if (wantCore) GuardPhase.STARTING else GuardPhase.ERROR
            // 防火墙加载失败或挂载点被移除时只剩内核闸门一层，不能显示「已受保护」
            firewallFailing || hookWarningShown -> GuardPhase.ERROR
            else -> GuardPhase.PROTECTED
        }
        return GuardStatus(
            version = version,
            phase = phase,
            effectiveMode = effectiveMode,
            routing = settings.routing,
            fuse = snap,
            fuseSince = snap.since?.let { wallNow - (monoNow - it) },
            fuseHoldRemainingMs = snap.holdUntil?.let { it - monoNow }?.takeIf { it > 0 },
            fuseLatched = engine.isLatched,
            coreRunning = apiUp,
            coreVersion = coreVersion,
            coreRestarts = core.restarts,
            tunUp = tunUp,
            tunInterface = tunInterface,
            firewallPolicy = firewall.current.name,
            ipv6Blocked = ipv6Blocked,
            ipv6DisabledInterfaces = ipv6Switch.disabledCount,
            privateDnsLocked = settings.enabled && settings.lockPrivateDns && privateDns.locked,
            exit = exitStatus,
            heartbeatAlive = heartbeatAlive,
            latency = latency.takeLast(60),
            primaryInterface = primaryInterface,
            conflicts = conflicts,
            subscription = settings.subscription,
            captiveUntil = captiveUntil?.let { wallNow + (it - monoNow) },
            lastError = lastError,
            nodeCount = nodeCount,
            updatedAt = wallNow,
        )
    }

    private fun saveSettings() {
        runCatching { writeAtomic(Paths.settings, AIGuardJson.encodeToString(GuardSettings.serializer(), settings)) }
            .onFailure { Log.write("[error] 设置保存失败：${it.message}") }
    }

    private fun log(level: EventLevel, message: String) {
        Log.write("[${level.name.lowercase()}] $message")
        events.add(GuardEvent(nextEventId++, wall(), level, message))
        if (events.size > 300) events.subList(0, events.size - 300).clear()
        eventsDirty = true
        if (level == EventLevel.CRITICAL) persistEvents(force = true)
    }

    private fun persistEvents(force: Boolean = false) {
        if (!eventsDirty && !force) return
        // 写失败就保留脏标记，下一轮再试
        if (writeEvents(events)) eventsDirty = false
    }

    private fun writeEvents(list: List<GuardEvent>): Boolean = runCatching {
        writeAtomic(Paths.events, AIGuardJson.encodeToString(ListSerializer(GuardEvent.serializer()), list))
    }.isSuccess

    // endregion

    companion object {
        const val PROBE_URL = "http://cp.cloudflare.com/generate_204"
        const val SUBSCRIPTION_UA = "clash.meta mihomo/1.19 AIGuard-Android"
    }
}
