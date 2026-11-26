import Foundation

/// 出站模式：代理，或者无代理时的「直连 + 阻断 AI」
public enum ProxyMode: String, Codable, Sendable, CaseIterable {
    case proxy
    case direct
}

/// 代理模式下的分流方式
public enum RoutingMode: String, Codable, Sendable, CaseIterable {
    /// AI 强制走安全线路，大陆域名/IP 直连，其余走代理
    case smart
    /// 除局域网外全部走代理（AI 仍走 AI 线路）
    case global
}

/// 熔断时的处置方式
public enum FuseAction: String, Codable, Sendable, CaseIterable {
    /// pf 防火墙切断全部外网 + 内核闸门全部 REJECT
    case cutAll
    /// 大陆白名单：只放行大陆域名/IP（内核按域名、pf 按 IP 双重把关），AI 与境外全部拒绝。
    /// 原始值沿用 1.0 的 blockAIOnly，旧设置文件能直接读
    case whitelist = "blockAIOnly"
}

public struct SubscriptionUsage: Codable, Sendable, Equatable {
    public var upload: Int64
    public var download: Int64
    public var total: Int64
    public var expire: Date?

    /// 机场给的数值不可信，相加可能溢出 Int64 让界面崩溃，溢出时取上限
    public var used: Int64 {
        let (sum, overflow) = upload.addingReportingOverflow(download)
        return overflow ? .max : sum
    }

    public init(upload: Int64, download: Int64, total: Int64, expire: Date?) {
        self.upload = upload
        self.download = download
        self.total = total
        self.expire = expire
    }

    /// 解析 `subscription-userinfo: upload=1; download=2; total=3; expire=4`
    public static func parse(header: String) -> SubscriptionUsage? {
        var values: [String: Int64] = [:]
        for part in header.split(separator: ";") {
            let kv = part.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard kv.count == 2 else { continue }
            // 机场返回的数值不可信：非有限值或越界的浮点数直接转 Int64 会让进程崩溃
            if let v = Int64(kv[1]) ?? Double(kv[1]).flatMap({ $0.isFinite ? Int64(exactly: $0.rounded()) : nil }), v >= 0 {
                values[kv[0].lowercased()] = v
            }
        }
        guard values["total"] != nil || values["download"] != nil else { return nil }
        let expire = values["expire"].flatMap { $0 > 0 ? Date(timeIntervalSince1970: TimeInterval($0)) : nil }
        return SubscriptionUsage(upload: values["upload"] ?? 0, download: values["download"] ?? 0,
                                 total: values["total"] ?? 0, expire: expire)
    }
}

public struct SubscriptionInfo: Codable, Sendable, Equatable {
    public var url: String
    public var name: String?
    public var lastUpdated: Date?
    public var nodeCount: Int
    public var usage: SubscriptionUsage?
    public var lastError: String?

    public init(url: String, name: String? = nil, lastUpdated: Date? = nil, nodeCount: Int = 0,
                usage: SubscriptionUsage? = nil, lastError: String? = nil) {
        self.url = url
        self.name = name
        self.lastUpdated = lastUpdated
        self.nodeCount = nodeCount
        self.usage = usage
        self.lastError = lastError
    }

    /// 订阅链接本身就是凭据，界面和日志只展示脱敏版本
    public var maskedURL: String {
        guard let comps = URLComponents(string: url), let host = comps.host else { return "••••" }
        let path = comps.path
        let tail = path.count > 4 ? String(path.suffix(4)) : ""
        return "\(comps.scheme ?? "https")://\(host)/••••\(tail)"
    }
}

public struct GuardSettings: Codable, Sendable, Equatable {
    /// 设置文件格式版本；升级时据此迁移旧默认值
    public static let currentSchema = 3

    public var schema = GuardSettings.currentSchema
    public var enabled = true
    public var mode: ProxyMode = .proxy
    public var routing: RoutingMode = .smart

    public var fuseEnabled = true
    public var fuseAction: FuseAction = .whitelist
    public var autoRecover = true
    /// 长连接心跳间隔（秒），每次心跳同时校验出口国家
    public var probeIntervalSeconds = 2
    public var failureThreshold = 2
    public var latencyThresholdMs = 3000
    public var recoverSuccesses = 4
    public var wakeHoldSeconds = 8
    /// 出口禁区：出口国家落在这里即熔断，节点名匹配到的地区也不会被自动选中
    public var forbiddenRegions = ["CN", "HK", "MO"]
    public var autoSwitchUnsafeNode = true
    /// 熔断时关闭 AI 客户端与浏览器
    public var closeAppsOnFuse = true
    /// 睡眠/唤醒/换网/启动这类保护性熔断也关闭应用（默认不关：此时防火墙已全部断网）
    public var closeAppsOnGuardTrips = false

    public var leakGuard = true
    /// 直连模式只放行大陆域名/IP，其余全部拒绝：名单外的 AI 服务也无法直连
    public var directOnlyMainland = true
    /// 守护开启时在系统层面关闭各网络服务的 IPv6，关闭守护时恢复原设置
    public var disableSystemIPv6 = true
    /// 守护开启时把各网络服务的系统 DNS 锁定到 TUN，关闭守护时恢复
    public var lockSystemDNS = true
    public var disabledAICategories: [String] = []
    public var customAIDomains: [String] = []
    public var customDirectDomains: [String] = []
    /// 智能分流下强制走代理的域名，用来纠正大陆名单误收的境外站点
    public var customProxyDomains: [String] = []
    public var subscription: SubscriptionInfo?
    public var subscriptionUpdateHours = 12
    public var mixedPort = 7890

    public init() {}

    enum CodingKeys: String, CodingKey {
        case schema, enabled, mode, routing, fuseEnabled, fuseAction, autoRecover, probeIntervalSeconds, failureThreshold
        case latencyThresholdMs, recoverSuccesses, wakeHoldSeconds, forbiddenRegions, autoSwitchUnsafeNode
        case closeAppsOnFuse, closeAppsOnGuardTrips, leakGuard, directOnlyMainland, disableSystemIPv6
        case lockSystemDNS, disabledAICategories, customAIDomains, customDirectDomains, customProxyDomains
        case subscription
        case subscriptionUpdateHours, mixedPort
    }

    /// 1.0 版的字段，只用于迁移
    enum LegacyKeys: String, CodingKey {
        case forbiddenAIRegions, autoSwitchUnsafeAINode
    }

    // 逐字段 decodeIfPresent：新版本加字段后旧的设置文件仍能读取
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let legacy = try decoder.container(keyedBy: LegacyKeys.self)
        let d = GuardSettings()
        let oldSchema = try c.decodeIfPresent(Int.self, forKey: .schema) ?? 1
        schema = GuardSettings.currentSchema
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? d.enabled
        mode = try c.decodeIfPresent(ProxyMode.self, forKey: .mode) ?? d.mode
        routing = try c.decodeIfPresent(RoutingMode.self, forKey: .routing) ?? d.routing
        fuseEnabled = try c.decodeIfPresent(Bool.self, forKey: .fuseEnabled) ?? d.fuseEnabled
        fuseAction = try c.decodeIfPresent(FuseAction.self, forKey: .fuseAction) ?? d.fuseAction
        autoRecover = try c.decodeIfPresent(Bool.self, forKey: .autoRecover) ?? d.autoRecover
        probeIntervalSeconds = try c.decodeIfPresent(Int.self, forKey: .probeIntervalSeconds) ?? d.probeIntervalSeconds
        failureThreshold = try c.decodeIfPresent(Int.self, forKey: .failureThreshold) ?? d.failureThreshold
        latencyThresholdMs = try c.decodeIfPresent(Int.self, forKey: .latencyThresholdMs) ?? d.latencyThresholdMs
        recoverSuccesses = try c.decodeIfPresent(Int.self, forKey: .recoverSuccesses) ?? d.recoverSuccesses
        wakeHoldSeconds = try c.decodeIfPresent(Int.self, forKey: .wakeHoldSeconds) ?? d.wakeHoldSeconds
        forbiddenRegions = try c.decodeIfPresent([String].self, forKey: .forbiddenRegions)
            ?? legacy.decodeIfPresent([String].self, forKey: .forbiddenAIRegions) ?? d.forbiddenRegions
        autoSwitchUnsafeNode = try c.decodeIfPresent(Bool.self, forKey: .autoSwitchUnsafeNode)
            ?? legacy.decodeIfPresent(Bool.self, forKey: .autoSwitchUnsafeAINode) ?? d.autoSwitchUnsafeNode
        closeAppsOnFuse = try c.decodeIfPresent(Bool.self, forKey: .closeAppsOnFuse) ?? d.closeAppsOnFuse
        closeAppsOnGuardTrips = try c.decodeIfPresent(Bool.self, forKey: .closeAppsOnGuardTrips) ?? d.closeAppsOnGuardTrips
        leakGuard = try c.decodeIfPresent(Bool.self, forKey: .leakGuard) ?? d.leakGuard
        directOnlyMainland = try c.decodeIfPresent(Bool.self, forKey: .directOnlyMainland) ?? d.directOnlyMainland
        disableSystemIPv6 = try c.decodeIfPresent(Bool.self, forKey: .disableSystemIPv6) ?? d.disableSystemIPv6
        lockSystemDNS = try c.decodeIfPresent(Bool.self, forKey: .lockSystemDNS) ?? d.lockSystemDNS
        disabledAICategories = try c.decodeIfPresent([String].self, forKey: .disabledAICategories) ?? d.disabledAICategories
        customAIDomains = try c.decodeIfPresent([String].self, forKey: .customAIDomains) ?? d.customAIDomains
        customDirectDomains = try c.decodeIfPresent([String].self, forKey: .customDirectDomains) ?? d.customDirectDomains
        customProxyDomains = try c.decodeIfPresent([String].self, forKey: .customProxyDomains) ?? d.customProxyDomains
        subscription = try c.decodeIfPresent(SubscriptionInfo.self, forKey: .subscription)
        subscriptionUpdateHours = try c.decodeIfPresent(Int.self, forKey: .subscriptionUpdateHours) ?? d.subscriptionUpdateHours
        mixedPort = try c.decodeIfPresent(Int.self, forKey: .mixedPort) ?? d.mixedPort
        if oldSchema < 2 {
            // 1.0 默认把美国放进了禁区、探测 5 秒/3 次；按用户要求改为美国只在熔断时封禁、2 秒心跳
            forbiddenRegions.removeAll { $0.uppercased() == "US" }
            probeIntervalSeconds = d.probeIntervalSeconds
            failureThreshold = d.failureThreshold
        }
        if oldSchema < 3 {
            // 1.1 → 1.2：用户要求熔断时只开大陆白名单，替代全部断网 + 美国 IP 封禁
            fuseAction = .whitelist
        }
    }

    /// 把越界的数值收回安全范围，防止界面或手改文件导致探测风暴或永不熔断
    public func sanitized() -> GuardSettings {
        var s = self
        s.probeIntervalSeconds = min(max(s.probeIntervalSeconds, 1), 10)
        s.failureThreshold = min(max(s.failureThreshold, 1), 20)
        s.latencyThresholdMs = min(max(s.latencyThresholdMs, 300), 10_000)
        s.recoverSuccesses = min(max(s.recoverSuccesses, 1), 30)
        s.wakeHoldSeconds = min(max(s.wakeHoldSeconds, 0), 120)
        s.subscriptionUpdateHours = min(max(s.subscriptionUpdateHours, 1), 168)
        if !(1024...65535).contains(s.mixedPort) { s.mixedPort = 7890 }
        s.forbiddenRegions = Self.normalizeRegions(s.forbiddenRegions)
        // 大陆出口永远视为违规，用户无法把它从禁区里删掉
        if !s.forbiddenRegions.contains("CN") { s.forbiddenRegions.insert("CN", at: 0) }
        s.customAIDomains = DomainSanitizer.clean(s.customAIDomains)
        s.customDirectDomains = DomainSanitizer.clean(s.customDirectDomains)
        s.customProxyDomains = DomainSanitizer.clean(s.customProxyDomains)
        return s
    }

    static func normalizeRegions(_ list: [String]) -> [String] {
        var seen = Set<String>()
        return list.map { $0.trimmingCharacters(in: .whitespaces).uppercased() }
            .filter { $0.count == 2 && $0.allSatisfy(\.isLetter) && seen.insert($0).inserted }
    }
}

public enum DomainSanitizer {
    /// 只保留合法域名字符，去掉协议、路径、前导点，防止注入到 YAML 规则里
    public static func clean(_ list: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for raw in list {
            var s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
            if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
            while s.hasPrefix(".") || s.hasPrefix("*") || s.hasPrefix("+") { s.removeFirst() }
            guard !s.isEmpty, s.count <= 253, s.contains("."),
                  s.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") }),
                  !s.hasSuffix("."), !s.contains("..")
            else { continue }
            if seen.insert(s).inserted { out.append(s) }
        }
        return out
    }
}
