import AIGuardCore
import Darwin
import Foundation

struct DaemonPaths {
    let helperDir: String
    let supportDir: String
    let logDir: String
    var coreHome: String { supportDir + "/core" }
    var settingsFile: String { supportDir + "/settings.json" }
    var runtimeFile: String { supportDir + "/runtime.json" }
    var eventsFile: String { supportDir + "/events.json" }
    var providerFile: String { coreHome + "/providers/sub.yaml" }
    var mihomo: String { helperDir + "/mihomo" }
    var bundledRules: String { helperDir + "/rules" }
    var cnTable: String { bundledRules + "/cn4.txt" }
}

private struct RuntimeSecrets: Codable {
    var secret: String
    var listenerPassword: String
}

/// 守护进程的总控：串行处理所有探测信号和控制请求，决定防火墙与内核闸门的状态。
/// 两个循环：1 秒一次的健康检查（内核、TUN 路由、IPv6），以及经代理的长连接心跳（延迟 + 出口国家）
actor Guardian {
    private let paths: DaemonPaths
    nonisolated let pf: PFController
    private let core: CoreProcess
    private let api: MihomoAPI
    private let fetcher: ProxiedFetcher
    private let ipv6Switch: SystemIPv6Switch
    private let dnsLock: SystemDNSLock
    private let allowedUIDs: Set<uid_t>
    private let dev: Bool
    private var settings: GuardSettings
    private var runtime: CoreRuntime
    private var engine: FuseEngine

    private var events: [GuardEvent] = []
    private var nextEventID = 1
    private var eventsDirty = false
    private var latency: [LatencySample] = []
    private var exitStatus = ExitStatus()
    private var heartbeatAlive = false
    private var coreVersion: String?
    private var apiUp = false
    private var tunUp = false
    private var tunInterface: String?
    private var primaryInterface: String?
    private var conflicts: [String] = []
    private var lastError: String?
    private var nodeCount: Int?

    private var captiveUntil: Date?
    private var apiFailures = 0
    private var wantCore = false
    private var nextRestartAt: Date?
    private var restartBackoff: TimeInterval = 1
    private var coreStartedAt: Date?
    private var appliedGates: [String: String] = [:]
    private var switchingNode = false
    private var lastTripped = false
    /// 本次熔断是否已经关过应用：同一次熔断只关一次，用户手动重开的应用不会被反复关掉
    private var appsClosedThisTrip = false
    /// 启动后第一次恢复之前不关应用：启动/升级阶段内核还没起来，不是真实故障
    private var armedOnce = false
    /// 最近一次由我们主动启动或重载内核的时间，之后 20 秒内的内核/TUN 异常属于正常过渡
    private var lastCoreTransition: Date?
    /// 白名单熔断时闸门是否已确认写成 REJECT；确认之前不放行进入 TUN 的流量
    private var softGatesConfirmed = false
    /// pf 加载失败只在状态变化时记一次，避免每秒刷屏
    private var pfFailing = false
    private var lastAIScan: Date?
    /// TUN 路由丢失但内核正常的起始时间：被其他代理软件破坏路由时据此自动重启内核
    private var tunLostSince: Date?
    private var lastAutoRestart: Date?
    /// 连续自动重启次数：其他代理一直霸占路由时按 60s、120s… 退避，最长 10 分钟
    private var autoRestartCount = 0
    private var restarting = false
    /// 给后台关应用任务读的熔断状态（延迟 SIGKILL 前确认熔断还在）
    private let trippedFlag = LockedValue(false)
    private var nodeDownLogged = false
    /// 熔断期间允许内核连接的节点服务器/订阅服务器 IPv4（美国封禁的窄例外）
    private var allowIPs: [String] = []
    private var lastAllowRefresh: Date?
    /// 心跳上一次看到的实际出口节点；变化时作废长连接
    private var lastResolvedNode: String?
    /// 网络/节点/配置的代次：探测发出后代次变了，结果作废，防止旧线路的结果为新线路解锁
    private var epoch = 0
    private var anchorWarningShown = false
    private var ipv6Blocked: Bool?
    private var lastIPv6Check: Date?
    private var lastSlowWork: Date?
    private var lastSubscriptionCheck: Date?
    private var loopTask: Task<Void, Never>?
    private var heartbeatTask: Task<Void, Never>?

    static let probeURL = "http://cp.cloudflare.com/generate_204"
    static let subscriptionUA = "clash.meta mihomo/1.19 AIGuard/\(AIGuardVersion)"

    init(paths: DaemonPaths, allowedUIDs: Set<uid_t>, dev: Bool = false) {
        self.paths = paths
        self.dev = dev
        self.allowedUIDs = allowedUIDs
        let fm = FileManager.default
        for dir in [paths.supportDir, paths.coreHome, paths.coreHome + "/providers", paths.coreHome + "/rules"] {
            try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            chmod(dir, 0o700)
        }
        let loaded = (try? Data(contentsOf: URL(fileURLWithPath: paths.settingsFile)))
            .flatMap { try? JSONDecoder.iso.decode(GuardSettings.self, from: $0) } ?? GuardSettings()
        settings = loaded.sanitized()

        let secrets: RuntimeSecrets
        if let data = try? Data(contentsOf: URL(fileURLWithPath: paths.runtimeFile)),
           let s = try? JSONDecoder().decode(RuntimeSecrets.self, from: data) {
            secrets = s
        } else {
            secrets = RuntimeSecrets(secret: Secrets.random(), listenerPassword: Secrets.random())
            if let data = try? JSONEncoder().encode(secrets) {
                fm.createFile(atPath: paths.runtimeFile, contents: data, attributes: [.posixPermissions: 0o600])
            }
        }
        let hasSub = settings.subscription != nil && fm.fileExists(atPath: paths.providerFile)
        runtime = CoreRuntime(secret: secrets.secret, listenerPassword: secrets.listenerPassword, tunEnabled: !dev,
                              hasSubscription: hasSub)
        if dev {
            // 避开正式版守护进程占用的端口
            runtime.controllerPort += 100
            runtime.probePort += 100
            runtime.directProbePort += 100
        }
        pf = PFController(supportDir: paths.supportDir, dryRun: dev)
        ipv6Switch = SystemIPv6Switch(supportDir: paths.supportDir)
        dnsLock = SystemDNSLock(supportDir: paths.supportDir)
        core = CoreProcess(binary: paths.mihomo, home: paths.coreHome, logDir: paths.logDir)
        api = MihomoAPI(port: runtime.controllerPort, secret: secrets.secret)
        fetcher = ProxiedFetcher(user: runtime.listenerUser, password: secrets.listenerPassword)
        engine = FuseEngine(config: FuseConfig(settings: settings, effectiveMode: MihomoConfigBuilder.effectiveMode(settings, runtime)),
                            now: Date(), startTripped: settings.enabled)
        if let data = try? Data(contentsOf: URL(fileURLWithPath: paths.eventsFile)),
           let old = try? JSONDecoder.iso.decode([GuardEvent].self, from: data) {
            events = Array(old.suffix(300))
            nextEventID = (events.last?.id ?? 0) + 1
        }
    }

    // MARK: - 生命周期

    func boot() async {
        syncBundledRules()
        core.killStale()
        coreVersion = core.version()
        core.onExit = { [weak self] code in
            Task { await self?.coreExited(code) }
        }
        log(.info, "守护进程启动 v\(AIGuardVersion)，内核 \(coreVersion ?? "未知")")
        // 设置文件按新格式写回（1.0 → 1.1 的迁移结果落盘）
        saveSettings()
        pf.removeLegacyAnchors()
        // 先上防火墙再启动内核：启动阶段默认熔断
        applyProtection()
        syncSystemNetwork()
        if settings.enabled { await startCore() }
        loopTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.tick()
                try? await Task.sleep(for: .seconds(1))
            }
        }
        heartbeatTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let interval = await self.heartbeat()
                try? await Task.sleep(for: .seconds(interval))
            }
        }
    }

    func shutdown() {
        loopTask?.cancel()
        heartbeatTask?.cancel()
        core.stop()
        pf.teardown()
        if !dev {
            ipv6Switch.restoreAll()
            dnsLock.restoreAll()
        }
        log(.info, "守护进程退出，防火墙、系统 DNS 与 IPv6 设置已恢复")
        persistEvents(force: true)
    }

    private func syncBundledRules() {
        let fm = FileManager.default
        for name in BundledRuleSets.files {
            let src = paths.bundledRules + "/" + name
            let dst = paths.coreHome + "/rules/" + name
            guard let data = fm.contents(atPath: src) else { continue }
            if fm.contents(atPath: dst) != data {
                fm.createFile(atPath: dst, contents: data, attributes: [.posixPermissions: 0o600])
            }
        }
    }

    // MARK: - 内核

    private var effectiveMode: ProxyMode {
        if captiveUntil != nil { return .direct }
        return MihomoConfigBuilder.effectiveMode(settings, runtime)
    }

    private func buildYAML() -> String {
        MihomoConfigBuilder.build(settings: settings, runtime: runtime, captive: captiveUntil != nil,
                                  captiveInterface: primaryInterface)
    }

    private func startCore() async {
        wantCore = true
        lastCoreTransition = Date()
        epoch += 1
        // 新内核的闸门要重新确认，确认前白名单不放行 TUN
        softGatesConfirmed = false
        do {
            try core.writeConfig(buildYAML())
        } catch {
            lastError = error.localizedDescription
            log(.critical, "配置生成失败：\(error.localizedDescription)")
            if !FileManager.default.fileExists(atPath: core.configPath) { return }
        }
        do {
            try core.start()
            coreStartedAt = Date()
            appliedGates = [:]
        } catch {
            lastError = "内核启动失败：\(error.localizedDescription)"
            log(.critical, lastError!)
            nextRestartAt = Date().addingTimeInterval(restartBackoff)
            return
        }
        for _ in 0..<40 {
            if await api.version() != nil { apiUp = true; break }
            try? await Task.sleep(for: .milliseconds(150))
        }
        applyProtection()
        await applyGates()
    }

    private func coreExited(_ code: Int32) {
        apiUp = false
        epoch += 1
        guard wantCore else { return }
        core.noteRestart()
        log(.warning, "内核意外退出（\(code)），\(Int(restartBackoff)) 秒后重启")
        engine.handle(.health(coreUp: false, tunUp: false), now: Date())
        applyProtection()
        nextRestartAt = Date().addingTimeInterval(restartBackoff)
        restartBackoff = min(restartBackoff * 2, 30)
    }

    /// 配置相关设置变化后重载；重载失败则整体重启内核
    private func reloadCore(reason: String) async {
        guard wantCore else { return }
        epoch += 1
        lastCoreTransition = Date()
        softGatesConfirmed = false
        applyProtection()
        do {
            try core.writeConfig(buildYAML())
        } catch {
            lastError = error.localizedDescription
            log(.critical, "新配置未生效：\(error.localizedDescription)")
            return
        }
        if core.isRunning, await api.reloadConfig(path: core.configPath) {
            log(.info, "配置已重载（\(reason)）")
        } else {
            log(.warning, "热重载失败，重启内核（\(reason)）\(api.lastReloadError.get().map { "：\($0)" } ?? "")")
            core.stop()
            await startCore()
        }
        appliedGates = [:]
        await api.flushConnections()
        await applyGates()
    }

    // MARK: - 防护执行

    private var desiredPF: PFPolicy {
        guard settings.enabled else { return .none }
        let s = engine.snapshot
        let tun = tunInterface ?? runtime.tunDevice
        if s.tripped {
            if s.hard { return .lockdown }
            // 大陆白名单：任何进程只能连大陆 IP；闸门确认 REJECT 之前连 TUN 都不放
            return .whitelist(tun: tun, allowTUN: softGatesConfirmed, cnTable: paths.cnTable, allow: allowIPs)
        }
        // 关闭防泄漏层也始终封锁 IPv6 和明文 DNS
        return settings.leakGuard ? .leakGuard(tun: tun) : .basic(tun: tun)
    }

    private func desiredGates() -> [String: String] {
        let s = engine.snapshot
        let hasSub = runtime.hasSubscription
        let tripped = s.tripped
        let hard = s.tripped && s.hard
        let cnNormal = hasSub && settings.routing == .global ? GroupName.proxy : "DIRECT"
        return [
            GroupName.gateAI: tripped || !hasSub ? "REJECT" : GroupName.proxy,
            // 白名单熔断只保留大陆直连，境外（包括名单外的 AI）一律拒绝
            GroupName.gateMain: tripped || !hasSub ? "REJECT" : GroupName.proxy,
            GroupName.gateCN: hard ? "REJECT" : (tripped ? "DIRECT" : cnNormal),
            GroupName.gateDirect: hard ? "REJECT" : "DIRECT",
        ]
    }

    /// 防火墙同步执行（睡眠前必须立刻生效），内核闸门异步执行
    private func applyProtection() {
        let ok = pf.apply(desiredPF)
        if !ok && !pfFailing {
            lastError = "防火墙规则加载失败：\(pf.lastError ?? "未知原因")"
            log(.critical, "\(lastError!)，仅剩内核闸门一层防护")
        } else if ok && pfFailing {
            log(.info, "防火墙规则已恢复正常")
        }
        pfFailing = !ok
        let snap = engine.snapshot
        trippedFlag.set(snap.tripped)
        if snap.tripped != lastTripped {
            lastTripped = snap.tripped
            softGatesConfirmed = false
            if snap.tripped {
                log(.critical, "已熔断：\(snap.reason?.title ?? "")\(snap.hard ? "（全部断网）" : "（只放行大陆白名单）")")
            } else {
                appsClosedThisTrip = false
                armedOnce = true
                nodeDownLogged = false
                log(.info, effectiveMode == .proxy ? "已恢复：线路与出口验证通过" : "已恢复：内核与 TUN 就绪，AI 保持阻断")
            }
            Task { await self.applyGates(flush: snap.tripped) }
        }
        closeAppsIfNeeded()
    }

    /// 熔断期间能否关闭应用：启动/重载过渡期、控制接口偶发抖动、保护性熔断（默认）都不关
    private func closeEligible() -> Bool {
        let snap = engine.snapshot
        guard snap.tripped, armedOnce, settings.enabled, settings.closeAppsOnFuse, !dev,
              let reason = snap.reason, !reason.isPrecautionary || settings.closeAppsOnGuardTrips else { return false }
        if reason == .coreDown || reason == .tunLost,
           let t = lastCoreTransition, Date().timeIntervalSince(t) < 20 { return false }
        if reason == .coreDown, core.isRunning, apiFailures < 3 { return false }
        return true
    }

    /// 熔断瞬间关一次浏览器 + AI 进程；之后每 3 秒再扫一遍 AI 进程，确保熔断期间没有 AI 在运行
    private func closeAppsIfNeeded() {
        guard closeEligible() else { return }
        let now = Date()
        let kinds: Set<AppCloser.Kind>
        if !appsClosedThisTrip {
            appsClosedThisTrip = true
            kinds = [.ai, .browser]
        } else if lastAIScan.map({ now.timeIntervalSince($0) >= 3 }) ?? true {
            kinds = [.ai]
        } else {
            return
        }
        lastAIScan = now
        killApps(kinds, reason: "熔断")
    }

    private func killApps(_ kinds: Set<AppCloser.Kind>, reason: String, requireTripped: Bool = true) {
        let uids = allowedUIDs
        let flag = trippedFlag
        Task.detached { [weak self] in
            let closed = AppCloser.close(kinds, uids: uids, stillWanted: { !requireTripped || flag.get() })
            if !closed.isEmpty { await self?.log(.warning, "\(reason)：已关闭 \(closed.joined(separator: "、"))") }
        }
    }

    /// 手动或自动重启内核：先清场 AI 进程，再按启动保护重新验证线路
    private func restartCore(reason: String) async {
        guard !restarting else { return }
        restarting = true
        defer { restarting = false }
        log(.warning, "重启内核：\(reason)")
        if settings.closeAppsOnFuse && !dev {
            killApps([.ai], reason: "重启内核前清场", requireTripped: false)
        }
        epoch += 1
        // 就地按启动保护重新验证（保留手动锁、睡眠状态和保持期），线路和出口都通过才放行
        engine.coreRestarted(now: Date())
        applyProtection()
        core.stop()
        core.noteRestart()
        apiUp = false
        apiFailures = 0
        tunLostSince = nil
        lastAutoRestart = Date()
        fetcher.reset(port: runtime.probePort)
        lastResolvedNode = nil
        await startCore()
    }

    /// actor 在 await 期间可能处理别的请求，旧的放行写入可能晚于新的 REJECT 到达内核。
    /// 每次写完都重新核对期望值，不一致就再写一轮
    private func applyGates(flush: Bool = false) async {
        guard apiUp else { return }
        for _ in 0..<3 {
            var stale = false
            for group in desiredGates().keys.sorted() {
                guard let target = desiredGates()[group], appliedGates[group] != target else { continue }
                let ok = await api.select(group: group, proxy: target)
                if desiredGates()[group] == target {
                    if ok { appliedGates[group] = target }
                } else {
                    appliedGates[group] = nil
                    stale = true
                }
            }
            if !stale { break }
        }
        // 切换闸门只影响新连接，熔断时必须掐断已有连接
        if flush { await api.flushConnections() }
        let snap = engine.snapshot
        if snap.tripped, !snap.hard, !softGatesConfirmed,
           appliedGates[GroupName.gateAI] == "REJECT", appliedGates[GroupName.gateMain] == "REJECT" {
            softGatesConfirmed = true
            await api.flushConnections()
            applyProtection()
        }
    }

    /// 守护开启时关闭系统 IPv6、锁定系统 DNS；关闭时恢复。开发模式不动系统配置
    private func syncSystemNetwork() {
        guard !dev else { return }
        if settings.enabled && settings.disableSystemIPv6 {
            let skipped = ipv6Switch.disableAll()
            if !skipped.isEmpty {
                log(.warning, "以下网络服务的 IPv6 为手动配置或无法修改，仅靠防火墙封锁：\(skipped.joined(separator: "、"))")
            }
        } else {
            ipv6Switch.restoreAll()
        }
        if settings.enabled && settings.lockSystemDNS {
            dnsLock.lockAll()
        } else {
            dnsLock.restoreAll()
        }
    }

    // MARK: - 健康检查（每秒）

    private func tick() async {
        let now = Date()
        if let until = captiveUntil, now >= until {
            captiveUntil = nil
            log(.info, "Wi-Fi 登录模式结束，恢复正常出站")
            engine.update(config: fuseConfig(), now: now)
            applyProtection()
            await reloadCore(reason: "Wi-Fi 登录结束")
        }
        guard settings.enabled else { return }

        if wantCore, !core.isRunning, let at = nextRestartAt, now >= at {
            nextRestartAt = nil
            await startCore()
        }

        if core.isRunning {
            if let v = await api.version() {
                apiUp = true
                apiFailures = 0
                if !v.isEmpty { coreVersion = v }
            } else {
                apiUp = false
                apiFailures += 1
                if apiFailures >= 5 {
                    log(.warning, "内核无响应，强制重启")
                    apiFailures = 0
                    core.stop()
                    core.noteRestart()
                    await startCore()
                }
            }
        } else {
            apiUp = false
        }
        if let started = coreStartedAt, now.timeIntervalSince(started) > 60, apiUp { restartBackoff = 1 }

        // 路由检查是纯系统调用，每秒一次的开销可以忽略
        tunInterface = RouteInspector.interfaces().first { $0.ipv4 == "198.18.0.1" }?.name
        let routeIface = RouteInspector.interface(for: "1.1.1.1")
        // 进程死了立刻判定；进程活着时控制接口要连续 2 次失败才算内核故障，避免一次抖动就全部断网
        let coreUp = core.isRunning && apiFailures < 2
        tunUp = dev ? coreUp : (coreUp && tunInterface != nil && routeIface == tunInterface)
        engine.handle(.health(coreUp: coreUp, tunUp: tunUp), now: now)

        // 其他代理软件退出时会把路由一起删掉：内核正常但 TUN 路由持续丢失，就自动重启内核重建
        if coreUp && !tunUp && !dev {
            if tunLostSince == nil { tunLostSince = now }
            let settled = lastCoreTransition.map { now.timeIntervalSince($0) > 20 } ?? true
            let cooldown = min(60 * pow(2, Double(autoRestartCount)), 600)
            let cooled = lastAutoRestart.map { now.timeIntervalSince($0) > cooldown } ?? true
            if autoRestartCount >= 5 {
                // 同一次连续故障最多自动重启 5 次，之后交给用户处理，避免无限循环
                if autoRestartCount == 5 {
                    autoRestartCount += 1
                    log(.critical, "TUN 路由一直被占用，已停止自动重启。请退出其他代理软件后点「重启内核」")
                }
            } else if let since = tunLostSince, now.timeIntervalSince(since) >= 8, settled, cooled {
                autoRestartCount += 1
                await restartCore(reason: "TUN 路由被破坏（可能是其他代理软件抢占或删掉了路由），自动重建")
                return
            }
        } else {
            tunLostSince = nil
            if tunUp, let last = lastAutoRestart, now.timeIntervalSince(last) > 120 { autoRestartCount = 0 }
        }

        // IPv6 泄漏：平时 30 秒查一次，熔断中 5 秒一次。开发模式不加载 pf，跳过
        let ipv6Interval: TimeInterval = engine.snapshot.tripped ? 5 : 30
        if !dev, lastIPv6Check.map({ now.timeIntervalSince($0) >= ipv6Interval }) ?? true {
            lastIPv6Check = now
            let leaking = await Task.detached { IPv6Probe.canReachInternet() }.value
            if leaking && ipv6Blocked != false { log(.critical, "IPv6 能直连公网，已熔断") }
            ipv6Blocked = !leaking
            engine.handle(.ipv6(leaking: leaking), now: Date())
        }

        applyProtection()
        await applyGates()
        closeAppsIfNeeded()

        if lastSlowWork.map({ now.timeIntervalSince($0) >= 30 }) ?? true {
            lastSlowWork = now
            await slowWork()
        }
        if lastSubscriptionCheck.map({ now.timeIntervalSince($0) > 600 }) ?? false {
            lastSubscriptionCheck = now
            await autoRefreshSubscription(now: now)
        } else if lastSubscriptionCheck == nil {
            lastSubscriptionCheck = now
        }
    }

    /// 30 秒一次：闸门重下发、pf 核对、冲突软件扫描、节点数、事件落盘
    private func slowWork() async {
        // 缓存只用来省请求；定期清空强制重下发，防止内核侧闸门被外部改动后长期不一致
        appliedGates = [:]
        await applyGates()
        if let issue = pf.verify() {
            if !anchorWarningShown { log(.critical, issue) }
            anchorWarningShown = true
        } else {
            anchorWarningShown = false
        }
        let mine = Set([core.pid, getpid()].compactMap { $0 })
        let found = ProcessScanner.runningConflicts(excluding: mine)
        if found != conflicts {
            conflicts = found
            if !found.isEmpty { log(.warning, "检测到其他代理软件：\(found.joined(separator: "、"))，可能抢占路由") }
        }
        if runtime.hasSubscription, apiUp {
            nodeCount = await api.group(GroupName.proxy)?.all.filter { $0 != GroupName.auto }.count
            if lastAllowRefresh.map({ Date().timeIntervalSince($0) > 600 }) ?? true { await refreshAllowList() }
        }
        persistEvents()
    }

    /// 解析订阅里的节点服务器和订阅服务器，作为美国封禁的窄例外（只对 root 内核生效）。
    /// 用内核 DNS 解析，熔断期间也能用；结果为空时保留上一次的列表
    private func refreshAllowList() async {
        guard let content = try? String(contentsOfFile: paths.providerFile, encoding: .utf8) else { return }
        var hosts = SubscriptionParser.serverHosts(providerContent: content)
        if let subHost = settings.subscription.flatMap({ URL(string: $0.url)?.host }) { hosts.append(subHost.lowercased()) }
        hosts = Array(Set(hosts)).sorted().prefix(2000).map { $0 }
        var ips = Set<String>()
        var pending = hosts[...]
        while !pending.isEmpty {
            let batch = Array(pending.prefix(16))
            pending = pending.dropFirst(16)
            await withTaskGroup(of: [String].self) { group in
                for h in batch {
                    if PFRulesBuilder.isIPv4(h) { ips.insert(h); continue }
                    group.addTask { [fetcher, runtime] in await fetcher.resolveDirect(h, viaPort: runtime.directProbePort) }
                }
                // 198.18.x 是 fake-ip，不是真实服务器地址
                for await list in group {
                    list.filter { PFRulesBuilder.isIPv4($0) && !$0.hasPrefix("198.18.") && !$0.hasPrefix("198.19.") }
                        .forEach { ips.insert($0) }
                }
            }
        }
        lastAllowRefresh = Date()
        guard !ips.isEmpty else { return }
        allowIPs = ips.sorted()
        applyProtection()
    }

    // MARK: - 长连接心跳

    /// 经带认证的探测入站（直通节点选择、不经过闸门）在同一条 TLS 长连接上请求 Cloudflare trace：
    /// 一次请求同时得到「代理是否通」「往返延迟」「出口 IP 与国家」。返回下一次心跳的间隔
    private func heartbeat() async -> Double {
        let interval = Double(settings.probeIntervalSeconds)
        guard settings.enabled, apiUp, effectiveMode == .proxy, !switchingNode else {
            heartbeatAlive = false
            return 1
        }
        let startEpoch = epoch
        // 先确认当前实际出口节点：「自动选择」换线后旧长连接仍挂在旧节点上，必须重建并作废旧结果
        let resolved = await resolvedNode()
        guard startEpoch == epoch else { return 0.2 }
        if resolved == nil, lastResolvedNode != nil {
            lastResolvedNode = nil
            fetcher.reset(port: runtime.probePort)
            epoch += 1
        }
        if let node = resolved?.display, node != lastResolvedNode {
            if let old = lastResolvedNode { log(.info, "出口节点切换：\(old) → \(node)") }
            lastResolvedNode = node
            fetcher.reset(port: runtime.probePort)
            epoch += 1
        }
        // 内核已判定当前节点连不上：不用等心跳超时，直接按失败计。
        // 只用于加快熔断；熔断中必须做真实心跳，否则内核的判断滞后会让恢复永远攒不够成功次数
        if !engine.snapshot.tripped, let leaf = resolved?.leaf, await api.isAlive(leaf) == false {
            if !nodeDownLogged { log(.critical, "当前节点「\(leaf)」连不上") }
            nodeDownLogged = true
            heartbeatAlive = false
            engine.handle(.probe(ms: nil), now: Date())
            latency.append(LatencySample(at: Date(), ms: nil))
            if latency.count > 120 { latency.removeFirst(latency.count - 120) }
            applyProtection()
            await applyGates()
            return min(interval, 1)
        }
        nodeDownLogged = false
        let beatEpoch = epoch
        let timeout = Double(settings.latencyThresholdMs) / 1000
        let start = Date()
        var trace = await fetcher.heartbeat(viaPort: runtime.probePort, timeout: timeout)
        if trace == nil {
            // Cloudflare 偶发失败时用备用源确认一次，与主请求共用同一个超时预算
            trace = await fetcher.ipinfo(viaPort: runtime.probePort, timeout: timeout - Date().timeIntervalSince(start))
        }
        let ms = trace.map { _ in Int(Date().timeIntervalSince(start) * 1000) }
        guard beatEpoch == epoch, settings.enabled else { return 0.2 }
        let now = Date()
        heartbeatAlive = trace != nil
        engine.handle(.probe(ms: ms), now: now)
        if let t = trace {
            if let old = exitStatus.trace, old.ip != t.ip {
                log(.warning, "出口 IP 变化：\(old.ip)（\(old.country)）→ \(t.ip)（\(t.country)）")
            }
            exitStatus = ExitStatus(trace: t, checkedAt: now)
            engine.handle(.geo(country: t.country), now: now)
        } else {
            exitStatus.error = "心跳失败"
        }
        latency.append(LatencySample(at: now, ms: ms))
        if latency.count > 120 { latency.removeFirst(latency.count - 120) }

        // 先落实熔断（防火墙 + 闸门 + 掐断连接），再慢慢找安全节点
        applyProtection()
        await applyGates()
        if let c = trace?.country, settings.forbiddenRegions.contains(c), settings.autoSwitchUnsafeNode {
            await findSafeNode(badCountry: c)
        }
        // 熔断中加快心跳，恢复更快
        return engine.snapshot.tripped ? min(interval, 1) : interval
    }

    /// 「节点选择」最终落到的具体节点（穿透「自动选择」）：display 用于记录切换，leaf 是真正的节点
    private func resolvedNode() async -> (display: String, leaf: String)? {
        guard let g = await api.group(GroupName.proxy), let now = g.now else { return nil }
        if now == GroupName.auto {
            guard let leaf = await api.group(GroupName.auto)?.now else { return nil }
            return ("\(GroupName.auto)/\(leaf)", leaf)
        }
        return (now, now)
    }

    /// 出口落在禁区时逐个试其他节点，找到出口安全的就固定下来
    private func findSafeNode(badCountry: String) async {
        guard !switchingNode, let info = await api.group(GroupName.proxy) else { return }
        switchingNode = true
        defer { switchingNode = false }
        log(.warning, "出口在 \(RegionNames.name(badCountry))，开始寻找安全节点")
        let candidates = Array(info.all.filter { $0 != GroupName.auto && $0 != info.now }.prefix(16))
        var ranked: [(String, Int)] = []
        await withTaskGroup(of: (String, Int?).self) { group in
            for c in candidates {
                group.addTask { [api] in (c, await api.delay(c, url: Self.probeURL, timeoutMs: 3000)) }
            }
            for await (name, ms) in group { if let ms { ranked.append((name, ms)) } }
        }
        ranked.sort { $0.1 < $1.1 }
        for (name, _) in ranked.prefix(6) {
            guard await api.select(group: GroupName.proxy, proxy: name) else { continue }
            epoch += 1
            // 新节点必须用新连接测，复用旧长连接会测到旧节点的出口
            fetcher.reset(port: runtime.probePort)
            let candidateEpoch = epoch
            if let t = await fetcher.exitTrace(viaPort: runtime.probePort), candidateEpoch == epoch,
               !settings.forbiddenRegions.contains(t.country) {
                lastResolvedNode = name
                exitStatus = ExitStatus(trace: t, checkedAt: Date())
                log(.info, "已自动切换到「\(name)」（\(RegionNames.name(t.country))）")
                engine.handle(.geo(country: t.country), now: Date())
                return
            }
        }
        await api.select(group: GroupName.proxy, proxy: GroupName.auto)
        log(.critical, "没有找到出口安全的节点，保持熔断")
    }

    // MARK: - 电源与网络

    func prepareForSleep() {
        guard settings.enabled else {
            pf.releaseForcedLockdown()
            pf.apply(.none)
            return
        }
        epoch += 1
        engine.handle(.sleep, now: Date())
        // 状态机已记录睡眠，硬切断由正常流程接管，解除电源回调里的强制断网
        pf.releaseForcedLockdown()
        applyProtection()
        log(.info, "系统即将睡眠，已预先断网")
    }

    func didWake() async {
        guard settings.enabled else { return }
        epoch += 1
        engine.handle(.wake, now: Date())
        applyProtection()
        log(.info, "系统已唤醒，等待网络稳定（至少 \(settings.wakeHoldSeconds) 秒）")
        lastIPv6Check = nil
        await api.flushConnections()
    }

    func networkChanged(primary: String?) async {
        primaryInterface = primary
        guard settings.enabled else {
            pf.releaseForcedLockdown()
            pf.apply(.none)
            return
        }
        epoch += 1
        engine.handle(.networkChanged, now: Date())
        pf.releaseForcedLockdown()
        applyProtection()
        log(.info, "网络已切换（\(primary ?? "无网络")），重新验证线路")
        // 新接入的网卡（USB 网卡、手机热点）也要关 IPv6、锁 DNS
        syncSystemNetwork()
        lastIPv6Check = nil
        await api.flushConnections()
    }

    // MARK: - 订阅

    /// 下载顺序：内核直连入站（熔断时也可用，DNS 不经过闸门）→ 代理入站 → 系统网络
    private func downloadSubscription(_ url: URL) async throws -> (ParsedSubscription, SubscriptionInfo) {
        var ports: [Int?] = []
        if apiUp { ports.append(runtime.directProbePort) }
        if apiUp && runtime.hasSubscription { ports.append(runtime.probePort) }
        ports.append(nil)
        var lastErr: Error = SubscriptionError.empty
        for port in ports {
            do {
                let (data, resp) = try await fetcher.fetch(url, viaPort: port, timeout: 20,
                                                           headers: ["User-Agent": Self.subscriptionUA])
                guard resp.statusCode == 200 else { throw SubscriptionError.http(resp.statusCode) }
                let parsed = try SubscriptionParser.parse(data)
                let headers = resp.allHeaderFields.reduce(into: [String: String]()) { $0["\($1.key)"] = "\($1.value)" }
                let usage = headers.first { $0.key.lowercased() == "subscription-userinfo" }.flatMap {
                    SubscriptionUsage.parse(header: $0.value)
                }
                let info = SubscriptionInfo(url: url.absoluteString, name: SubscriptionParser.profileName(headers: headers),
                                            lastUpdated: Date(), nodeCount: parsed.nodeCount, usage: usage)
                return (parsed, info)
            } catch {
                lastErr = error
                Log.write("订阅下载失败（\(port.map { "入站 \($0)" } ?? "系统网络")）：\(error.localizedDescription)")
            }
        }
        throw lastErr
    }

    private func installSubscription(_ parsed: ParsedSubscription, info: SubscriptionInfo) async throws {
        let fm = FileManager.default
        let backup = paths.providerFile + ".bak"
        if fm.fileExists(atPath: paths.providerFile) {
            try? fm.removeItem(atPath: backup)
            try? fm.copyItem(atPath: paths.providerFile, toPath: backup)
        }
        try parsed.providerContent.write(toFile: paths.providerFile, atomically: true, encoding: .utf8)
        chmod(paths.providerFile, 0o600)
        settings.subscription = info
        saveSettings()

        epoch += 1
        if !runtime.hasSubscription {
            runtime.hasSubscription = true
            engine.update(config: fuseConfig(), now: Date())
            applyProtection()
            await reloadCore(reason: "导入订阅")
        } else if apiUp {
            _ = await api.reloadProvider(GroupName.providerName)
        }
        // 内核实际解析出 0 个节点时回滚，绝不用坏订阅覆盖能用的旧订阅
        if apiUp, let count = await api.providerCount(GroupName.providerName), count == 0 {
            if fm.fileExists(atPath: backup) {
                try? fm.removeItem(atPath: paths.providerFile)
                try? fm.moveItem(atPath: backup, toPath: paths.providerFile)
                _ = await api.reloadProvider(GroupName.providerName)
            }
            throw SubscriptionError.noNodes
        }
        if apiUp, let count = await api.providerCount(GroupName.providerName) {
            settings.subscription?.nodeCount = count
            saveSettings()
        }
        await refreshAllowList()
    }

    private func importSubscription(_ urlString: String) async -> IPCResponse {
        guard let url = SubscriptionParser.validateURL(urlString) else { return .failure(SubscriptionError.invalidURL.localizedDescription) }
        do {
            let (parsed, info) = try await downloadSubscription(url)
            try await installSubscription(parsed, info: info)
            log(.info, "订阅已导入：\(info.name ?? info.maskedURL)，\(settings.subscription?.nodeCount ?? parsed.nodeCount) 个节点")
            return IPCResponse(status: snapshotStatus())
        } catch {
            log(.warning, "订阅导入失败：\(error.localizedDescription)")
            return .failure(error.localizedDescription)
        }
    }

    private func refreshSubscription(manual: Bool) async -> IPCResponse {
        guard var sub = settings.subscription, let url = URL(string: sub.url) else { return .failure("还没有导入订阅") }
        do {
            let (parsed, info) = try await downloadSubscription(url)
            var merged = info
            merged.name = info.name ?? sub.name
            try await installSubscription(parsed, info: merged)
            log(.info, "订阅已更新，\(settings.subscription?.nodeCount ?? parsed.nodeCount) 个节点")
            return IPCResponse(status: snapshotStatus())
        } catch {
            sub.lastError = error.localizedDescription
            settings.subscription = sub
            saveSettings()
            log(manual ? .warning : .info, "订阅更新失败（继续使用旧节点）：\(error.localizedDescription)")
            return .failure(error.localizedDescription)
        }
    }

    private func autoRefreshSubscription(now: Date) async {
        guard let sub = settings.subscription else { return }
        let age = sub.lastUpdated.map { now.timeIntervalSince($0) } ?? .infinity
        guard age > Double(settings.subscriptionUpdateHours) * 3600 else { return }
        _ = await refreshSubscription(manual: false)
    }

    // MARK: - 控制请求

    func handle(_ req: IPCRequest) async -> IPCResponse {
        switch req {
        case .status:
            return IPCResponse(status: snapshotStatus())
        case .getSettings:
            return IPCResponse(settings: settings)
        case .updateSettings(let new):
            await updateSettings(new)
            return IPCResponse(status: snapshotStatus(), settings: settings)
        case .importSubscription(let url):
            return await importSubscription(url)
        case .refreshSubscription:
            return await refreshSubscription(manual: true)
        case .removeSubscription:
            try? FileManager.default.removeItem(atPath: paths.providerFile)
            try? FileManager.default.removeItem(atPath: paths.providerFile + ".bak")
            settings.subscription = nil
            runtime.hasSubscription = false
            saveSettings()
            engine.update(config: fuseConfig(), now: Date())
            applyProtection()
            await reloadCore(reason: "移除订阅")
            log(.info, "订阅已移除，进入直连阻断模式")
            return IPCResponse(status: snapshotStatus())
        case .tripFuse:
            engine.handle(.manualTrip, now: Date())
            applyProtection()
            return IPCResponse(status: snapshotStatus())
        case .restoreNetwork(let force):
            engine.handle(.manualRestore(force: force), now: Date())
            if force { log(.warning, "用户强制恢复网络（跳过线路验证）") }
            applyProtection()
            return IPCResponse(status: snapshotStatus())
        case .captiveLogin(let minutes):
            captiveUntil = Date().addingTimeInterval(TimeInterval(min(max(minutes, 1), 10) * 60))
            log(.info, "Wi-Fi 登录模式：\(min(max(minutes, 1), 10)) 分钟内直连，AI 仍被阻断")
            engine.update(config: fuseConfig(), now: Date())
            applyProtection()
            await reloadCore(reason: "Wi-Fi 登录")
            return IPCResponse(status: snapshotStatus())
        case .endCaptiveLogin:
            guard captiveUntil != nil else { return IPCResponse(status: snapshotStatus()) }
            captiveUntil = Date()
            await tick()
            return IPCResponse(status: snapshotStatus())
        case .controllerInfo:
            return IPCResponse(controller: ControllerInfo(baseURL: api.base.absoluteString, secret: runtime.secret,
                                                          mixedPort: settings.mixedPort))
        case .events(let after):
            return IPCResponse(events: events.filter { $0.id > after })
        case .flushConnections:
            await api.flushConnections()
            return IPCResponse()
        case .restartCore:
            guard settings.enabled else { return .failure("守护已关闭") }
            guard !restarting else { return .failure("内核正在重启") }
            autoRestartCount = 0
            await restartCore(reason: "用户手动重启")
            return apiUp ? IPCResponse(status: snapshotStatus()) : .failure("内核没有启动成功，查看「事件」页的原因")
        }
    }

    private func updateSettings(_ incoming: GuardSettings) async {
        var new = incoming.sanitized()
        new.subscription = settings.subscription
        let old = settings
        settings = new
        saveSettings()
        engine.update(config: fuseConfig(), now: Date())
        if old.enabled != new.enabled || old.disableSystemIPv6 != new.disableSystemIPv6 || old.lockSystemDNS != new.lockSystemDNS {
            syncSystemNetwork()
        }
        if old.enabled != new.enabled {
            if new.enabled {
                log(.info, "守护已开启")
                engine = FuseEngine(config: fuseConfig(), now: Date(), startTripped: true)
                applyProtection()
                await startCore()
            } else {
                log(.warning, "守护已关闭：防火墙、TUN、DNS 锁定全部撤销，AI 不再受保护")
                wantCore = false
                core.stop()
                apiUp = false
                engine.handle(.reset, now: Date())
                applyProtection()
            }
            return
        }
        applyProtection()
        if old.routing != new.routing { log(.info, new.routing == .smart ? "已切换到智能分流" : "已切换到全局代理") }
        // 分流方式只影响大陆闸门，不需要重载配置
        let configChanged = old.mode != new.mode || old.directOnlyMainland != new.directOnlyMainland
            || old.disabledAICategories != new.disabledAICategories || old.customAIDomains != new.customAIDomains
            || old.customDirectDomains != new.customDirectDomains || old.mixedPort != new.mixedPort
            || old.forbiddenRegions != new.forbiddenRegions
        if configChanged { await reloadCore(reason: "设置变更") }
        await applyGates()
    }

    // MARK: - 状态与持久化

    private func fuseConfig() -> FuseConfig {
        FuseConfig(settings: settings, effectiveMode: effectiveMode)
    }

    private func snapshotStatus() -> GuardStatus {
        let snap = engine.snapshot
        var s = GuardStatus()
        if !settings.enabled { s.phase = .disabled }
        else if snap.tripped { s.phase = .tripped }
        else if !apiUp { s.phase = wantCore ? .starting : .error }
        else { s.phase = .protected }
        s.effectiveMode = effectiveMode
        s.routing = settings.routing
        s.fuse = snap
        s.fuseLatched = engine.isLatched
        s.coreRunning = apiUp
        s.coreVersion = coreVersion
        s.coreRestarts = core.restarts
        s.tunUp = tunUp
        s.tunInterface = tunInterface
        s.pfPolicy = pf.current.name
        s.ipv6Blocked = ipv6Blocked
        s.ipv6DisabledServices = ipv6Switch.disabledCount
        s.dnsLockedServices = dnsLock.lockedCount
        s.exit = exitStatus
        s.heartbeatAlive = heartbeatAlive
        s.latency = Array(latency.suffix(60))
        s.primaryInterface = primaryInterface
        s.conflicts = conflicts
        s.subscription = settings.subscription
        s.captiveUntil = captiveUntil
        s.lastError = lastError
        s.nodeCount = nodeCount
        s.updatedAt = Date()
        return s
    }

    private func saveSettings() {
        guard let data = try? JSONEncoder.iso.encode(settings) else { return }
        let tmp = paths.settingsFile + ".tmp"
        FileManager.default.createFile(atPath: tmp, contents: data, attributes: [.posixPermissions: 0o600])
        rename(tmp, paths.settingsFile)
    }

    private func log(_ level: EventLevel, _ message: String) {
        Log.write("[\(level.rawValue)] \(message)")
        events.append(GuardEvent(id: nextEventID, at: Date(), level: level, message: message))
        nextEventID += 1
        if events.count > 300 { events.removeFirst(events.count - 300) }
        eventsDirty = true
        if level == .critical { persistEvents(force: true) }
    }

    private func persistEvents(force: Bool = false) {
        guard eventsDirty || force, let data = try? JSONEncoder.iso.encode(events) else { return }
        eventsDirty = false
        FileManager.default.createFile(atPath: paths.eventsFile, contents: data, attributes: [.posixPermissions: 0o600])
    }
}

extension JSONEncoder {
    static var iso: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }
}

extension JSONDecoder {
    static var iso: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}
