import AIGuardCore
import Darwin
import Foundation

enum Log {
    private static let queue = DispatchQueue(label: "aiguard.log")
    nonisolated(unsafe) private static var handle: FileHandle?
    // 只在 queue 内使用
    nonisolated(unsafe) private static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    static func open(dir: String) {
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let path = dir + "/daemon.log"
        rotate(path, maxBytes: 5 * 1024 * 1024)
        FileManager.default.createFile(atPath: path, contents: nil)
        queue.sync {
            handle = FileHandle(forWritingAtPath: path)
            handle?.seekToEndOfFile()
        }
    }

    static func rotate(_ path: String, maxBytes: Int) {
        guard let size = (try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? Int, size > maxBytes else { return }
        try? FileManager.default.removeItem(atPath: path + ".1")
        try? FileManager.default.moveItem(atPath: path, toPath: path + ".1")
    }

    static func write(_ message: String) {
        let now = Date()
        queue.async {
            let line = "\(formatter.string(from: now)) \(message)\n"
            if let handle { handle.write(Data(line.utf8)) } else { FileHandle.standardError.write(Data(line.utf8)) }
        }
    }
}

struct CommandResult {
    var status: Int32
    var stdout: String
    var stderr: String
}

enum Shell {
    /// 同步执行并带超时；超时后杀进程，避免 pfctl/mihomo -t 卡死守护进程
    @discardableResult
    static func run(_ path: String, _ args: [String], timeout: TimeInterval = 10) -> CommandResult {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return CommandResult(status: -1, stdout: "", stderr: "\(error)") }
        let group = DispatchGroup()
        let outBox = DataBox(), errBox = DataBox()
        group.enter()
        DispatchQueue.global().async { outBox.data = out.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        group.enter()
        DispatchQueue.global().async { errBox.data = err.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        let deadline = DispatchTime.now() + timeout
        if group.wait(timeout: deadline) == .timedOut {
            p.terminate()
            kill(p.processIdentifier, SIGKILL)
            _ = group.wait(timeout: .now() + 2)
            return CommandResult(status: -2, stdout: "", stderr: "timeout")
        }
        p.waitUntilExit()
        return CommandResult(status: p.terminationStatus, stdout: String(decoding: outBox.data, as: UTF8.self),
                             stderr: String(decoding: errBox.data, as: UTF8.self))
    }
}

/// 两个读管道的线程各写各的盒子，读取发生在 group.wait 之后，不存在并发访问
private final class DataBox: @unchecked Sendable {
    var data = Data()
}

func cString(_ buf: [CChar]) -> String {
    String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
}

enum Secrets {
    static func random(_ bytes: Int = 24) -> String {
        var buf = [UInt8](repeating: 0, count: bytes)
        arc4random_buf(&buf, bytes)
        return buf.map { String(format: "%02x", $0) }.joined()
    }
}

/// pf 防火墙：规则放在 com.apple/* 下的子锚点里，不改 /etc/pf.conf
final class PFController: @unchecked Sendable {
    private let rulesPath: String
    private var token: String?
    private var _current: PFPolicy = .none
    private let dryRun: Bool
    /// 电源回调可能在 actor 忙时直接调用，所有状态都在锁内
    private let lock = NSRecursiveLock()
    private var forced = false
    /// 守护进程退出时置位：之后任何回调都不能再装规则，否则退出后会残留断网
    private var stopped = false

    var current: PFPolicy {
        lock.lock()
        defer { lock.unlock() }
        return _current
    }

    /// 睡眠回调专用：不经过 Guardian 立即断网，直到状态机接手前任何 apply 都保持断网
    func forceLockdown() {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return }
        forced = true
        apply(.lockdown)
    }

    func releaseForcedLockdown() {
        lock.lock()
        forced = false
        lock.unlock()
    }

    init(supportDir: String, dryRun: Bool = false) {
        rulesPath = supportDir + "/pf.rules"
        self.dryRun = dryRun
    }

    private func ensureEnabled() {
        guard token == nil else { return }
        let r = Shell.run("/sbin/pfctl", ["-E"])
        let text = r.stdout + r.stderr
        if let line = text.split(separator: "\n").first(where: { $0.contains("Token") }),
           let t = line.split(separator: ":").last?.trimmingCharacters(in: .whitespaces) {
            token = t
        } else {
            Log.write("pfctl -E 未返回 token: \(text.prefix(200))")
        }
    }

    @discardableResult
    func apply(_ requested: PFPolicy, force: Bool = false) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return true }
        let policy = forced ? .lockdown : requested
        if policy == _current && !force { return true }
        let enteringLockdown = Self.isRestrictive(policy) && !Self.isRestrictive(_current)
        if dryRun {
            // 开发模式只记录策略并写出规则文件，便于检查
            try? PFRulesBuilder.rules(for: policy).write(toFile: rulesPath, atomically: true, encoding: .utf8)
            _current = policy
            return true
        }
        if policy == .none {
            Shell.run("/sbin/pfctl", ["-a", PFRulesBuilder.anchor, "-F", "rules"])
            _current = .none
            return true
        }
        ensureEnabled()
        let text = PFRulesBuilder.rules(for: policy)
        do {
            try text.write(toFile: rulesPath, atomically: true, encoding: .utf8)
        } catch {
            Log.write("写入 pf 规则失败: \(error)")
            return false
        }
        let r = Shell.run("/sbin/pfctl", ["-a", PFRulesBuilder.anchor, "-f", rulesPath])
        guard r.status == 0 else {
            let err = r.stderr.split(separator: "\n").filter { !$0.contains("Use of -f option") && !$0.contains("present in the main")
                && !$0.contains("/etc/pf.conf") }.prefix(2).joined(separator: " ")
            // 同一个错误只写一次日志
            if err != lastError { Log.write("加载 pf 规则失败(\(r.status)): \(err)") }
            lastError = err
            // 白名单依赖大陆 IP 表文件；加载不了就退回不依赖文件的全部断网，绝不停留在旧的宽松规则上
            if case .whitelist = policy {
                _ = apply(.lockdown, force: true)
                lastError = err
            }
            return false
        }
        lastError = nil
        _current = policy
        // 其他锚点建立的旧 state 会让已有连接跳过我们的规则，进入断网时全部清掉
        if enteringLockdown { Shell.run("/sbin/pfctl", ["-F", "states"]) }
        return true
    }

    static func isRestrictive(_ p: PFPolicy) -> Bool {
        switch p {
        case .lockdown, .whitelist: return true
        default: return false
        }
    }

    /// 最近一次加载失败时 pfctl 的输出，供事件日志展示
    private(set) var lastError: String?

    /// 系统重载 pf.conf 或其他软件 pfctl -F 都可能清掉锚点，定期核对。
    /// 返回无法自动修复的问题（主规则不再引用 com.apple/*，锚点形同虚设）
    func verify() -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard _current != .none, !dryRun else { return nil }
        let r = Shell.run("/sbin/pfctl", ["-a", PFRulesBuilder.anchor, "-sr"])
        let info = Shell.run("/sbin/pfctl", ["-s", "info"])
        let disabled = info.stdout.contains("Status: Disabled")
        if r.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || disabled {
            Log.write("pf 锚点规则丢失或 pf 被关闭，重新加载")
            if disabled { token = nil }
            apply(_current, force: true)
        }
        let main = Shell.run("/sbin/pfctl", ["-sr"])
        if main.status == 0, !main.stdout.contains("anchor \"com.apple/*\"") {
            return "pf 主规则没有引用 com.apple/* 锚点（/etc/pf.conf 被改动？），防火墙层失效，仅剩内核闸门"
        }
        return nil
    }

    /// 1.1 版熔断时加载的美国 IP 封禁锚点，升级后清掉
    func removeLegacyAnchors() {
        guard !dryRun else { return }
        Shell.run("/sbin/pfctl", ["-a", PFRulesBuilder.legacyUSAnchor, "-F", "all"])
    }

    /// 升级交接：装上全部断网后锁定，进程退出也不撤（不释放 pf 引用），由新版守护进程接管替换
    func holdLockdownOnExit() {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return }
        forced = true
        apply(.lockdown)
        stopped = true
    }

    func teardown() {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return }
        stopped = true
        forced = false
        if dryRun { _current = .none; return }
        Shell.run("/sbin/pfctl", ["-a", PFRulesBuilder.anchor, "-F", "all"])
        if let token { Shell.run("/sbin/pfctl", ["-X", token]) }
        token = nil
        _current = .none
    }
}

enum RouteInspector {
    /// 通过路由套接字查询到某个地址的出口网卡，避免每轮探测都启动 route 子进程
    static func interface(for ipv4: String) -> String? {
        let fd = socket(PF_ROUTE, SOCK_RAW, AF_INET)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var tv = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var dst = sockaddr_in()
        dst.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        dst.sin_family = sa_family_t(AF_INET)
        guard inet_pton(AF_INET, ipv4, &dst.sin_addr) == 1 else { return nil }

        let hdrSize = MemoryLayout<rt_msghdr>.size
        let total = hdrSize + MemoryLayout<sockaddr_in>.size
        var buf = [UInt8](repeating: 0, count: 1024)
        let seq = Int32.random(in: 1...Int32.max)
        buf.withUnsafeMutableBytes { raw in
            let hdr = raw.baseAddress!.assumingMemoryBound(to: rt_msghdr.self)
            hdr.pointee.rtm_msglen = UInt16(total)
            hdr.pointee.rtm_version = UInt8(RTM_VERSION)
            hdr.pointee.rtm_type = UInt8(RTM_GET)
            hdr.pointee.rtm_addrs = RTA_DST
            hdr.pointee.rtm_pid = getpid()
            hdr.pointee.rtm_seq = seq
            withUnsafeBytes(of: &dst) { src in
                raw.baseAddress!.advanced(by: hdrSize).copyMemory(from: src.baseAddress!, byteCount: src.count)
            }
        }
        guard Darwin.write(fd, buf, total) == total else { return nil }
        let me = getpid()
        for _ in 0..<8 {
            let n = Darwin.read(fd, &buf, buf.count)
            guard n >= hdrSize else { return nil }
            let (pid, s, index, errno_) = buf.withUnsafeBytes { raw -> (pid_t, Int32, UInt16, Int32) in
                let h = raw.baseAddress!.assumingMemoryBound(to: rt_msghdr.self).pointee
                return (h.rtm_pid, h.rtm_seq, h.rtm_index, h.rtm_errno)
            }
            guard pid == me, s == seq else { continue }
            guard errno_ == 0 else { return nil }
            var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
            guard if_indextoname(UInt32(index), &name) != nil else { return nil }
            return cString(name)
        }
        return nil
    }

    /// 找到挂着指定 IPv4 地址的网卡（TUN 网卡地址固定在 198.18.0.1）
    static func interfaces() -> [(name: String, ipv4: String)] {
        var out: [(String, String)] = []
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return [] }
        defer { freeifaddrs(ifap) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            let ifa = cur.pointee
            if let addr = ifa.ifa_addr, addr.pointee.sa_family == sa_family_t(AF_INET) {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                    out.append((String(cString: ifa.ifa_name), cString(host)))
                }
            }
            p = ifa.ifa_next
        }
        return out
    }
}

enum NetworkServices {
    static let tool = "/usr/sbin/networksetup"

    static func list() -> [String] {
        Shell.run(tool, ["-listallnetworkservices"]).stdout
            .split(separator: "\n").dropFirst()
            .map(String.init)
            .filter { !$0.hasPrefix("*") && !$0.isEmpty }
    }
}

/// 「服务名\t原值」备份文件。原则：先落盘再改网卡；只恢复自己改过的服务；恢复失败的条目留着下次再试
struct ServiceBackup {
    let path: String

    func read() -> [String: String] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [:] }
        var out: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let p = line.split(separator: "\t", maxSplits: 1).map(String.init)
            if p.count == 2 { out[p[0]] = p[1] }
        }
        return out
    }

    /// 返回是否已落盘。修改系统设置前必须确认备份写成功，否则崩溃后无法恢复用户原来的网络配置
    @discardableResult
    func write(_ b: [String: String]) -> Bool {
        if b.isEmpty {
            try? FileManager.default.removeItem(atPath: path)
            return !FileManager.default.fileExists(atPath: path)
        }
        let text = b.sorted { $0.key < $1.key }.map { "\($0.key)\t\($0.value)" }.joined(separator: "\n") + "\n"
        let tmp = path + ".tmp"
        guard FileManager.default.createFile(atPath: tmp, contents: Data(text.utf8), attributes: [.posixPermissions: 0o600]),
              rename(tmp, path) == 0 else {
            Log.write("备份写入失败：\(path)（errno \(errno)）")
            unlink(tmp)
            return false
        }
        return true
    }
}

/// 把每个网络服务的系统 DNS 锁到 TUN 网段里的地址，查询全部进内核（再由内核走 DoH）
final class SystemDNSLock: @unchecked Sendable {
    static let tunDNS = "198.18.0.2"
    private let backup: ServiceBackup
    private let lock = NSLock()
    private(set) var lockedCount = 0

    init(supportDir: String) {
        backup = ServiceBackup(path: supportDir + "/dns-backup.tsv")
    }

    private func current(_ svc: String) -> String? {
        let r = Shell.run(NetworkServices.tool, ["-getdnsservers", svc])
        guard r.status == 0 else { return nil }
        let ips = r.stdout.split(whereSeparator: \.isWhitespace).map(String.init).filter { $0.contains(".") || $0.contains(":") }
        // 「There aren't any DNS Servers set」= 用 DHCP 下发的，恢复时写 Empty
        return ips.isEmpty ? "Empty" : ips.joined(separator: " ")
    }

    func lockAll() {
        lock.lock()
        defer { lock.unlock() }
        var saved = backup.read()
        var targets: [String] = []
        for svc in NetworkServices.list() {
            guard let cur = current(svc) else { continue }
            if cur == Self.tunDNS { targets.append(svc); continue }
            // 198.18.x 是 TUN 网段（内核或上次运行留下的），不能当成原始设置
            if saved[svc] == nil, !cur.hasPrefix("198.18.") { saved[svc] = cur }
            if saved[svc] != nil { targets.append(svc) }
        }
        guard backup.write(saved) else {
            // 备份没落盘就不改系统 DNS；DNS 防泄漏仍由防火墙兜底
            lockedCount = 0
            return
        }
        var count = 0
        for svc in targets {
            if Shell.run(NetworkServices.tool, ["-setdnsservers", svc, Self.tunDNS]).status == 0 { count += 1 }
        }
        lockedCount = count
    }

    func restoreAll() {
        lock.lock()
        defer { lock.unlock() }
        var saved = backup.read()
        let services = Set(NetworkServices.list())
        for (svc, original) in saved where services.contains(svc) {
            let args = ["-setdnsservers", svc] + original.split(separator: " ").map(String.init)
            if Shell.run(NetworkServices.tool, args).status == 0 { saved[svc] = nil }
        }
        // 当前不存在的服务（改名/拔掉的网卡）保留记录，下次再恢复
        backup.write(saved)
        lockedCount = 0
    }
}

/// 熔断时关闭 AI 进程和浏览器（只动登记用户自己的进程，系统目录下的进程一律不碰）
enum AppCloser {
    enum Kind: Sendable { case ai, browser }

    /// 浏览器：按 .app 名匹配
    static let browserApps: Set<String> = [
        "Safari", "Safari Technology Preview", "Google Chrome", "Google Chrome Canary", "Google Chrome Beta", "Chromium",
        "Microsoft Edge", "Microsoft Edge Beta", "Microsoft Edge Dev", "Firefox", "Firefox Developer Edition",
        "Firefox Nightly", "Arc", "Brave Browser", "Opera", "Opera GX", "Vivaldi", "Orion", "Zen", "Zen Browser", "Dia",
        "Comet", "ChatGPT Atlas", "Quark", "夸克", "QQBrowser", "QQ浏览器", "SogouExplorer", "360Chrome", "Thorium",
        "Floorp", "LibreWolf", "Waterfox", "Tor Browser", "DuckDuckGo", "Sidekick",
    ]
    static let browserBundleIDs: Set<String> = [
        "com.apple.Safari", "com.google.Chrome", "com.google.Chrome.canary", "com.microsoft.edgemac", "org.mozilla.firefox",
        "company.thebrowser.Browser", "company.thebrowser.dia", "com.brave.Browser", "com.operasoftware.Opera",
        "com.vivaldi.Vivaldi", "com.kagi.kagimacOS", "app.zen-browser.zen", "com.quark.desktop",
        "com.duckduckgo.macos.browser", "ai.perplexity.comet", "com.openai.atlas",
    ]
    nonisolated(unsafe) private static var bundleIDCache: [String: String] = [:]
    private static let cacheLock = NSLock()

    static func bundleID(appPath: String) -> String? {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        if let c = bundleIDCache[appPath] { return c }
        let plist = appPath + "/Contents/Info.plist"
        guard let data = FileManager.default.contents(atPath: plist),
              let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let id = obj["CFBundleIdentifier"] as? String else { return nil }
        bundleIDCache[appPath] = id
        return id
    }

    /// 读进程的命令行参数（KERN_PROCARGS2）。缓冲区里参数后面紧跟环境变量，必须按 argc 截断：
    /// 否则 PATH、ANTHROPIC_API_KEY 这类环境变量会让所有终端 shell 都被误判成 AI 进程
    static func arguments(of pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0, size < 1 << 20 else { return [] }
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0 else { return [] }
        return ProcessMatch.parseArgumentList(Array(buf[0..<size]))
    }

    /// 返回被关闭的进程名（去重）
    /// stillWanted：发延迟 SIGKILL 前再确认一次（熔断已解除就不补刀）
    static func close(_ kinds: Set<Kind>, uids: Set<uid_t>, stillWanted: @escaping @Sendable () -> Bool) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        let count = size / MemoryLayout<kinfo_proc>.stride + 32
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        size = count * MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return [] }
        let n = size / MemoryLayout<kinfo_proc>.stride
        let me = getpid()
        var targets: [(pid: pid_t, name: String, start: timeval)] = []
        for i in 0..<n {
            let p = procs[i]
            let pid = p.kp_proc.p_pid
            guard pid > 1, pid != me, uids.contains(p.kp_eproc.e_ucred.cr_uid) else { continue }
            var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
            guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { continue }
            let path = cString(buf)
            if ProcessMatch.isProtected(path: path) || ProcessMatch.isSelf(path: path) { continue }
            let comm = withUnsafeBytes(of: p.kp_proc.p_comm) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
            var appName: String?
            var appPath: String?
            if let r = path.range(of: ".app/") {
                appPath = String(path[..<r.lowerBound]) + ".app"
                appName = (appPath! as NSString).lastPathComponent.replacingOccurrences(of: ".app", with: "")
            }
            let label = appName ?? comm
            if kinds.contains(.browser), let name = appName, let ap = appPath,
               browserApps.contains(name) || bundleID(appPath: ap).map(browserBundleIDs.contains) == true {
                targets.append((pid, label, p.kp_proc.p_starttime))
                continue
            }
            if kinds.contains(.ai) {
                // 先看路径和进程名；解释器（node/python…）再看它跑的脚本入口
                var hit = ProcessMatch.isAI(path) || ProcessMatch.isAI(comm)
                if !hit, ProcessMatch.isInterpreter((path as NSString).lastPathComponent) || ProcessMatch.isInterpreter(comm),
                   let entry = ProcessMatch.entryPoint(of: arguments(of: pid)) {
                    hit = ProcessMatch.isAI(entry)
                }
                if hit { targets.append((pid, label, p.kp_proc.p_starttime)) }
            }
        }
        for t in targets where sameProcess(t.pid, start: t.start, uids: uids) { kill(t.pid, SIGTERM) }
        // 2 秒后还没退出的强制结束；PID 可能已被复用，必须再核对 uid 和启动时间
        let pending = targets
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
            guard stillWanted() else { return }
            for t in pending where sameProcess(t.pid, start: t.start, uids: uids) { kill(t.pid, SIGKILL) }
        }
        return Array(Set(targets.map(\.name))).sorted()
    }

    /// 进程仍然是扫描时那一个：uid 在登记范围内且启动时间一致
    static func sameProcess(_ pid: pid_t, start: timeval, uids: Set<uid_t>) -> Bool {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0, info.kp_proc.p_pid == pid else { return false }
        let st = info.kp_proc.p_starttime
        return uids.contains(info.kp_eproc.e_ucred.cr_uid) && st.tv_sec == start.tv_sec && st.tv_usec == start.tv_usec
    }
}

/// 系统层面的 IPv6 开关（备份规则同 DNS 锁）
final class SystemIPv6Switch: @unchecked Sendable {
    private let backup: ServiceBackup
    private let lock = NSLock()
    private(set) var disabledCount = 0

    init(supportDir: String) {
        backup = ServiceBackup(path: supportDir + "/ipv6-backup.tsv")
    }

    /// Automatic / LinkLocal / Off / Manual / Unknown
    private func mode(of service: String) -> String {
        let info = Shell.run(NetworkServices.tool, ["-getinfo", service]).stdout
        guard let line = info.split(separator: "\n").first(where: { $0.hasPrefix("IPv6:") }) else { return "Unknown" }
        let v = line.dropFirst(5).trimmingCharacters(in: .whitespaces).lowercased()
        if v.hasPrefix("automatic") { return "Automatic" }
        if v.hasPrefix("off") { return "Off" }
        if v.contains("link") { return "LinkLocal" }
        if v.hasPrefix("manual") { return "Manual" }
        return "Unknown"
    }

    /// 关闭所有启用服务的 IPv6，返回无法处理的服务（手动配置的不动，避免丢失地址）
    @discardableResult
    func disableAll() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        var saved = backup.read()
        var skipped: [String] = []
        var toDisable: [String] = []
        var count = 0
        for svc in NetworkServices.list() {
            let m = mode(of: svc)
            switch m {
            case "Off": count += 1
            case "Automatic", "LinkLocal":
                if saved[svc] == nil { saved[svc] = m }
                toDisable.append(svc)
            default: skipped.append(svc)
            }
        }
        guard backup.write(saved) else {
            // 备份没落盘就不关系统 IPv6，改由防火墙封锁
            disabledCount = count
            return skipped + toDisable
        }
        for svc in toDisable {
            if Shell.run(NetworkServices.tool, ["-setv6off", svc]).status == 0 { count += 1 } else { skipped.append(svc) }
        }
        disabledCount = count
        return skipped
    }

    func restoreAll() {
        lock.lock()
        defer { lock.unlock() }
        var saved = backup.read()
        let services = Set(NetworkServices.list())
        for (svc, m) in saved where services.contains(svc) {
            let flag = m == "LinkLocal" ? "-setv6LinkLocal" : "-setv6automatic"
            if Shell.run(NetworkServices.tool, [flag, svc]).status == 0 { saved[svc] = nil }
        }
        backup.write(saved)
        disabledCount = 0
    }
}

enum IPv6Probe {
    /// 尝试 TCP 直连几个公网 IPv6 地址（Cloudflare/Google DNS 的 443）。
    /// 任一能连上就说明 IPv6 出站没被拦住；没有 IPv6 网络时会立刻失败，同样算安全
    static func canReachInternet(timeout: TimeInterval = 2) -> Bool {
        for addr in ["2606:4700:4700::1111", "2001:4860:4860::8888"] where connect(addr, port: 443, timeout: timeout) {
            return true
        }
        return false
    }

    private static func connect(_ ip: String, port: UInt16, timeout: TimeInterval) -> Bool {
        let fd = socket(AF_INET6, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var sa = sockaddr_in6()
        sa.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        sa.sin6_family = sa_family_t(AF_INET6)
        sa.sin6_port = port.bigEndian
        guard inet_pton(AF_INET6, ip, &sa.sin6_addr) == 1 else { return false }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        let rc = withUnsafePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
        }
        if rc == 0 { return true }
        guard errno == EINPROGRESS else { return false }
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&pfd, 1, Int32(timeout * 1000)) == 1 else { return false }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
        return err == 0
    }
}

enum ProcessScanner {
    /// 已知会抢 TUN/路由的代理软件进程名（p_comm 最长 16 字节，按前缀匹配）
    static let known: [(prefix: String, label: String)] = [
        ("V2rayU", "V2rayU"), ("sing-box", "sing-box"), ("xray", "Xray"), ("v2ray", "V2Ray"),
        ("clash-verge", "Clash Verge"), ("Clash Verge", "Clash Verge"), ("verge-mihomo", "Clash Verge 内核"),
        ("ClashX", "ClashX"), ("clash", "Clash"), ("FlClash", "FlClash"), ("Surge", "Surge"),
        ("Stash", "Stash"), ("Shadowrocket", "Shadowrocket"), ("ShadowsocksX", "ShadowsocksX"),
        ("Quantumult", "Quantumult X"), ("Loon", "Loon"), ("hiddify", "Hiddify"), ("nekoray", "NekoRay"),
        ("Hysteria", "Hysteria"), ("tun2socks", "tun2socks"), ("mihomo", "mihomo（非本软件）"),
    ]

    static func runningConflicts(excluding pids: Set<pid_t>) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        let count = size / MemoryLayout<kinfo_proc>.stride + 16
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        size = count * MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return [] }
        let n = size / MemoryLayout<kinfo_proc>.stride
        var found = Set<String>()
        for i in 0..<n {
            let pid = procs[i].kp_proc.p_pid
            if pids.contains(pid) { continue }
            let name = withUnsafeBytes(of: procs[i].kp_proc.p_comm) { raw in
                String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
            }
            for k in known where name.hasPrefix(k.prefix) { found.insert(k.label) }
        }
        return found.sorted()
    }
}
