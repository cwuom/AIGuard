import AIGuardCore
import AppKit
import Foundation
import Observation
import ServiceManagement

/// 界面状态中心：轮询守护进程，转发用户操作。所有阻塞 IO 都在后台线程
@Observable
@MainActor
final class GuardStore {
    var status: GuardStatus?
    var settings: GuardSettings?
    var events: [GuardEvent] = []
    /// 清空事件时加一，丢弃清空前已发出、清空后才返回的增量结果
    private var eventsEpoch = 0
    /// 守护进程的事件代号：变了说明它重启或清空过，本地列表和游标作废
    private var eventsGeneration: String?
    var daemonReachable = false
    /// 连得上但状态格式对不上：已安装的是旧版守护进程
    var daemonOutdated = false
    /// 已安装的守护进程比界面新：不能提示「升级」，那会用旧版覆盖新版并丢掉新设置
    var daemonNewer = false
    var daemonVersion: String?
    var lastIPCError: String?
    var busy: Set<String> = []
    var notice: Notice?
    var controller: ControllerInfo?
    var proxies: [String: MihomoAPI.ProxyItem] = [:]
    var traffic = MihomoAPI.Traffic(up: 0, down: 0)
    var trafficHistory: [TrafficPoint] = []
    var testingGroup: String?
    var connections: MihomoAPI.ConnectionsSnapshot?
    /// 验证失败后弹出「是否重启内核」
    var askRestartCore = false
    /// 界面 App 的登录项状态（守护进程是 LaunchDaemon，开机即运行，与此无关）
    var launchAtLogin: SMAppService.Status = SMAppService.mainApp.status

    struct Notice: Equatable {
        var text: String
        var isError: Bool
    }

    struct TrafficPoint: Identifiable, Equatable {
        var id: Date { at }
        var at: Date
        var up: Double
        var down: Double
    }

    private var pollTask: Task<Void, Never>?
    private var trafficTask: Task<Void, Never>?
    private var api: MihomoAPI?
    var windowVisible = true

    var daemonInstalled: Bool { FileManager.default.fileExists(atPath: AIGuardPaths.launchDaemonPlist) }
    var daemonVersionMismatch: Bool { status.map { $0.version != AIGuardVersion } ?? false }

    func start() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.refresh()
                // 窗口隐藏时降频，菜单栏图标 3 秒刷新一次就够了
                try? await Task.sleep(for: .seconds(self.windowVisible ? 1 : 3))
            }
        }
    }

    private nonisolated func call(_ req: IPCRequest, timeout: TimeInterval = 15) async -> Result<IPCResponse, Error> {
        await Task.detached(priority: .userInitiated) {
            Result { try UnixSocketIO.request(req, timeout: timeout) }
        }.value
    }

    func refresh() async {
        switch await call(.status, timeout: 5) {
        case .success(let r):
            // 界面和守护进程版本不一致时一律要求升级，避免新界面操作旧守护进程
            if let v = r.status?.version, v != AIGuardVersion {
                daemonReachable = false
                daemonVersion = v
                daemonNewer = compareVersions(v, AIGuardVersion) == .orderedDescending
                daemonOutdated = !daemonNewer
                lastIPCError = "守护进程版本 \(v)"
                return
            }
            daemonReachable = true
            daemonOutdated = false
            daemonNewer = false
            daemonVersion = r.status?.version
            lastIPCError = nil
            if let s = r.status { status = s }
            if settings == nil, case .success(let sr) = await call(.getSettings) { settings = sr.settings }
            if controller == nil, case .success(let cr) = await call(.controllerInfo), let c = cr.controller {
                controller = c
                api = MihomoAPI(base: URL(string: c.baseURL)!, secret: c.secret)
            }
            let after = events.last?.id ?? 0
            let epoch = eventsEpoch
            if case .success(let er) = await call(.events(after: after)), epoch == eventsEpoch {
                if let gen = er.eventsGeneration, gen != eventsGeneration {
                    // 代号变了：旧游标可能跳过新一代的低编号事件，清空后下一轮从头拉
                    let first = eventsGeneration == nil
                    eventsGeneration = gen
                    if !first {
                        events = []
                        return
                    }
                }
                mergeEvents(er.events ?? [], after: after)
            }
        case .failure(let e):
            daemonReachable = false
            daemonOutdated = e is DecodingError
            lastIPCError = e.localizedDescription
            controller = nil
            api = nil
        }
    }

    private func perform(_ key: String, _ req: IPCRequest, success: String? = nil, timeout: TimeInterval = 30) async -> Bool {
        busy.insert(key)
        defer { busy.remove(key) }
        switch await call(req, timeout: timeout) {
        case .success(let r) where r.ok:
            if let s = r.status { status = s }
            if let s = r.settings { settings = s }
            if let success { notice = Notice(text: success, isError: false) }
            return true
        case .success(let r):
            notice = Notice(text: r.error ?? "操作失败", isError: true)
        case .failure(let e):
            notice = Notice(text: "无法连接守护进程：\(e.localizedDescription)", isError: true)
        }
        return false
    }

    func updateSettings(_ mutate: (inout GuardSettings) -> Void) {
        guard var s = settings else { return }
        mutate(&s)
        settings = s
        Task { _ = await perform("settings", .updateSettings(s)) }
    }

    func importSubscription(_ url: String) async -> Bool {
        await perform("subscription", .importSubscription(url: url), success: "订阅已导入", timeout: 90)
    }

    func refreshSubscription() async {
        _ = await perform("subscription", .refreshSubscription, success: "订阅已更新", timeout: 90)
    }

    func removeSubscription() async {
        _ = await perform("subscription", .removeSubscription, success: "订阅已移除")
        settings?.subscription = nil
    }

    func tripFuse() async { _ = await perform("fuse", .tripFuse, success: "已手动熔断") }
    func restore(force: Bool) async {
        _ = await perform("fuse", .restoreNetwork(force: force), success: force ? "已强制恢复网络" : "已解锁，验证通过后自动恢复")
    }
    /// 解锁并验证：最多等 12 秒，仍未恢复就询问是否重启内核
    func verify() async {
        busy.insert("verify")
        defer { busy.remove("verify") }
        guard await perform("fuse", .restoreNetwork(force: false)) else { return }
        let deadline = ContinuousClock.now + .seconds(12)
        while ContinuousClock.now < deadline {
            try? await Task.sleep(for: .seconds(1))
            if case .success(let r) = await call(.status, timeout: 3), let s = r.status { status = s }
            if status?.fuse.tripped == false {
                // 熔断解除不等于全部正常：防火墙层异常时守护进程报 error，不能说「验证通过」
                if status?.phase == .protected {
                    notice = Notice(text: "验证通过，网络已恢复", isError: false)
                } else {
                    notice = Notice(text: "熔断已解除，但防护仍有异常：\(status?.lastError ?? "请查看「事件」页")", isError: true)
                }
                return
            }
        }
        askRestartCore = true
    }

    func restartCore() async {
        askRestartCore = false
        guard !busy.contains("restart") else { return }
        busy.insert("restart")
        defer { busy.remove("restart") }
        _ = await perform("fuse", .restartCore, success: "内核已重启，正在重新验证线路", timeout: 90)
        settings = nil
        await refresh()
    }

    /// refresh 可能被并发调用（轮询 + 手动刷新），只追加比本地最新编号更大的事件，避免重复
    private func mergeEvents(_ new: [GuardEvent], after: Int) {
        guard !new.isEmpty else { return }
        if let first = new.first, first.id <= after, events.last?.id == after {
            // 守护进程返回的是完整列表（游标失效），整表替换
            events = new
        } else {
            let last = events.last?.id ?? 0
            events.append(contentsOf: new.filter { $0.id > last })
        }
        if events.count > 400 { events.removeFirst(events.count - 400) }
    }

    func clearEvents() async {
        busy.insert("events")
        defer { busy.remove("events") }
        switch await call(.clearEvents) {
        case .success(let r) where r.ok:
            eventsEpoch += 1
            eventsGeneration = r.eventsGeneration ?? eventsGeneration
            events = []
            notice = Notice(text: "事件记录已清空", isError: false)
        case .success(let r):
            notice = Notice(text: r.error ?? "清空失败", isError: true)
        case .failure(let e):
            notice = Notice(text: "无法连接守护进程：\(e.localizedDescription)", isError: true)
        }
    }

    func captiveLogin() async { _ = await perform("captive", .captiveLogin(minutes: 5), success: "5 分钟内直连，请在浏览器完成 Wi-Fi 登录") }
    func endCaptive() async { _ = await perform("captive", .endCaptiveLogin) }

    // MARK: - 节点（直接走 mihomo API）

    func loadProxies() async {
        guard let api else { return }
        let p = await api.proxies()
        if !p.isEmpty { proxies = p }
    }

    func select(group: String, node: String) async {
        guard let api else { return }
        if await api.select(group: group, proxy: node) {
            await api.flushConnections()
            await loadProxies()
            notice = Notice(text: "\(group) → \(node)", isError: false)
        } else {
            notice = Notice(text: "切换失败", isError: true)
        }
    }

    /// 全量测速：内核并发测组内每个节点（含「自动选择」当前线路），结果写进各节点的历史
    func testGroup(_ group: String) async {
        guard let api else { return }
        testingGroup = group
        defer { testingGroup = nil }
        let total = proxies[group]?.all.count ?? 0
        guard let result = await api.groupDelay(group, url: "http://cp.cloudflare.com/generate_204", timeoutMs: 5000) else {
            notice = Notice(text: "测速请求失败，内核没有响应，请稍后重试", isError: true)
            return
        }
        await loadProxies()
        if total > 0 {
            let ok = result.values.filter { $0 > 0 }.count
            notice = Notice(text: "测速完成：\(ok)/\(total) 个可用", isError: ok == 0)
        }
    }

    // MARK: - 连接

    func loadConnections() async {
        guard let api else { return }
        if let c = await api.connections() { connections = c }
    }

    func closeConnection(_ id: String) async {
        guard let api else { return }
        await api.closeConnection(id)
        await loadConnections()
    }

    func closeAllConnections() async {
        guard let api else { return }
        await api.flushConnections()
        await loadConnections()
        notice = Notice(text: "已断开全部连接", isError: false)
    }

    func startTraffic() {
        guard trafficTask == nil, let api else { return }
        trafficTask = Task { [weak self] in
            do {
                for try await t in api.trafficStream() {
                    guard let self else { return }
                    self.traffic = t
                    self.trafficHistory.append(TrafficPoint(at: Date(), up: Double(t.up), down: Double(t.down)))
                    if self.trafficHistory.count > 60 { self.trafficHistory.removeFirst(self.trafficHistory.count - 60) }
                }
            } catch {}
            self?.trafficTask = nil
        }
    }

    func stopTraffic() {
        trafficTask?.cancel()
        trafficTask = nil
    }

    // MARK: - 安装

    /// 通过系统授权弹窗运行安装脚本，密码由用户自己在系统对话框里输入
    func installDaemon() async {
        guard let script = Bundle.main.path(forResource: "install", ofType: "sh") else {
            notice = Notice(text: "App 包内缺少安装脚本，请用 scripts/build-app.sh 构建", isError: true)
            return
        }
        busy.insert("install")
        defer { busy.remove("install") }
        let uid = getuid()
        let cmd = "/bin/zsh \(shellQuote(script)) --uid \(uid)"
        let source = "do shell script \(appleScriptQuote(cmd)) with administrator privileges"
        let result: String? = await Task.detached {
            var err: NSDictionary?
            let out = NSAppleScript(source: source)?.executeAndReturnError(&err)
            if let err { return (err[NSAppleScript.errorMessage] as? String) ?? "安装失败" }
            _ = out
            return nil
        }.value
        if let result {
            notice = Notice(text: result, isError: true)
        } else {
            notice = Notice(text: "守护进程已安装", isError: false)
            settings = nil
            await refresh()
        }
    }

    private nonisolated func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    private nonisolated func appleScriptQuote(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    // MARK: - 登录时启动

    private static let launchAtLoginDefaultKey = "launchAtLoginDefaultApplied"

    /// 首次从「应用程序」运行时默认开启一次；之后完全尊重用户在 App 或系统设置里的选择
    func applyLaunchAtLoginDefault() {
        let defaults = UserDefaults.standard
        guard LaunchAtLoginPolicy.shouldApplyDefault(alreadyApplied: defaults.bool(forKey: Self.launchAtLoginDefaultKey),
                                                     bundlePath: Bundle.main.bundlePath) else {
            refreshLaunchAtLogin()
            return
        }
        defaults.set(true, forKey: Self.launchAtLoginDefaultKey)
        if SMAppService.mainApp.status != .enabled { try? SMAppService.mainApp.register() }
        refreshLaunchAtLogin()
    }

    func refreshLaunchAtLogin() {
        launchAtLogin = SMAppService.mainApp.status
    }

    func setLaunchAtLogin(_ on: Bool) {
        do {
            if on {
                guard LaunchAtLoginPolicy.isInstalledLocation(Bundle.main.bundlePath) else {
                    notice = Notice(text: "请先把 AIGuard 拖进「应用程序」再开启，否则登录时会找不到它", isError: true)
                    return
                }
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            notice = Notice(text: "\(on ? "开启" : "关闭")登录时启动失败：\(error.localizedDescription)", isError: true)
        }
        // 用户手动操作过，默认值不再生效
        UserDefaults.standard.set(true, forKey: Self.launchAtLoginDefaultKey)
        refreshLaunchAtLogin()
        if launchAtLogin == .requiresApproval {
            notice = Notice(text: "还需要在「系统设置 › 通用 › 登录项」里允许 AI 出差管家", isError: false)
        }
    }

    func copyTerminalProxy() {
        let port = controller?.mixedPort ?? settings?.mixedPort ?? 7890
        let text = "export https_proxy=http://127.0.0.1:\(port) http_proxy=http://127.0.0.1:\(port) all_proxy=socks5://127.0.0.1:\(port)"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        notice = Notice(text: "已复制终端代理命令（TUN 已接管，一般不需要）", isError: false)
    }
}
