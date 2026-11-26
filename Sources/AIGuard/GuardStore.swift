import AIGuardCore
import AppKit
import Foundation
import Observation

/// 界面状态中心：轮询守护进程，转发用户操作。所有阻塞 IO 都在后台线程
@Observable
@MainActor
final class GuardStore {
    var status: GuardStatus?
    var settings: GuardSettings?
    var events: [GuardEvent] = []
    var daemonReachable = false
    /// 连得上但状态格式对不上：已安装的是旧版守护进程
    var daemonOutdated = false
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
                daemonOutdated = true
                lastIPCError = "守护进程版本 \(v)"
                return
            }
            daemonReachable = true
            daemonOutdated = false
            lastIPCError = nil
            if let s = r.status { status = s }
            if settings == nil, case .success(let sr) = await call(.getSettings) { settings = sr.settings }
            if controller == nil, case .success(let cr) = await call(.controllerInfo), let c = cr.controller {
                controller = c
                api = MihomoAPI(base: URL(string: c.baseURL)!, secret: c.secret)
            }
            let after = events.last?.id ?? 0
            if case .success(let er) = await call(.events(after: after)), let new = er.events, !new.isEmpty {
                events.append(contentsOf: new)
                if events.count > 400 { events.removeFirst(events.count - 400) }
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
                notice = Notice(text: "验证通过，网络已恢复", isError: false)
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

    func testGroup(_ group: String) async {
        guard let api else { return }
        testingGroup = group
        defer { testingGroup = nil }
        _ = await api.groupDelay(group, url: "http://cp.cloudflare.com/generate_204", timeoutMs: 4000)
        await loadProxies()
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

    func copyTerminalProxy() {
        let port = controller?.mixedPort ?? settings?.mixedPort ?? 7890
        let text = "export https_proxy=http://127.0.0.1:\(port) http_proxy=http://127.0.0.1:\(port) all_proxy=socks5://127.0.0.1:\(port)"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        notice = Notice(text: "已复制终端代理命令（TUN 已接管，一般不需要）", isError: false)
    }
}
