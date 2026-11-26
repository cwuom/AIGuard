import Foundation

public enum FuseReason: Codable, Sendable, Equatable {
    case starting
    case sleeping
    case waking
    case networkChanged
    case coreDown
    case tunLost
    /// 能直连公网 IPv6：防火墙的 IPv6 封锁失效
    case ipv6Leak
    case proxyUnstable(failures: Int)
    case unsafeExit(country: String)
    case manual

    /// 守护类原因：状态恢复正常后总是自动解除，不受「自动恢复」开关影响
    public var isTransientGuard: Bool {
        switch self {
        case .starting, .sleeping, .waking, .networkChanged, .coreDown, .tunLost, .ipv6Leak: return true
        case .proxyUnstable, .unsafeExit, .manual: return false
        }
    }

    /// 睡眠/唤醒/换网/启动：防火墙已全部断网的预防性熔断
    public var isPrecautionary: Bool {
        switch self {
        case .starting, .sleeping, .waking, .networkChanged: return true
        default: return false
        }
    }

    public var title: String {
        switch self {
        case .starting: return "启动保护：等待内核与线路就绪"
        case .sleeping: return "睡眠保护：合盖前已预先断网"
        case .waking: return "唤醒保护：等待网络与代理稳定"
        case .networkChanged: return "网络切换保护：等待新网络稳定"
        case .coreDown: return "代理内核未运行"
        case .tunLost: return "TUN 路由丢失，流量可能绕过代理"
        case .ipv6Leak: return "检测到 IPv6 可以直连公网，防火墙封锁失效"
        case .proxyUnstable(let n): return "代理不稳定：长连接心跳连续 \(n) 次失败"
        case .unsafeExit(let c): return "出口落在 \(RegionNames.name(c))（\(c)）"
        case .manual: return "手动熔断"
        }
    }
}

public struct FuseConfig: Sendable, Equatable {
    public var enabled: Bool
    public var action: FuseAction
    public var autoRecover: Bool
    public var failureThreshold: Int
    public var latencyThresholdMs: Int
    public var recoverSuccesses: Int
    public var wakeHold: TimeInterval
    public var forbidden: Set<String>
    public var mode: ProxyMode

    public init(settings s: GuardSettings, effectiveMode: ProxyMode) {
        enabled = s.fuseEnabled
        action = s.fuseAction
        autoRecover = s.autoRecover
        failureThreshold = s.failureThreshold
        latencyThresholdMs = s.latencyThresholdMs
        recoverSuccesses = s.recoverSuccesses
        wakeHold = TimeInterval(s.wakeHoldSeconds)
        forbidden = Set(s.sanitized().forbiddenRegions)
        mode = effectiveMode
    }
}

public enum FuseSignal: Sendable, Equatable {
    case health(coreUp: Bool, tunUp: Bool)
    /// 长连接心跳：往返毫秒数（nil 表示失败）
    case probe(ms: Int?)
    /// 出口地区检测：nil 表示没测出来（不算违规也不算通过）
    case geo(country: String?)
    /// IPv6 泄漏检测结果
    case ipv6(leaking: Bool)
    case sleep
    case wake
    case networkChanged
    case manualTrip
    case manualRestore(force: Bool)
    case reset
}

public struct FuseSnapshot: Codable, Sendable, Equatable {
    public var tripped: Bool
    public var hard: Bool
    public var reason: FuseReason?
    public var since: Date?
    public var holdUntil: Date?
    public var recoverProgress: Int
    public var recoverNeeded: Int
    public var geoVerified: Bool
    public var consecutiveFailures: Int

    public static let armed = FuseSnapshot(tripped: false, hard: false, reason: nil, since: nil, holdUntil: nil,
                                           recoverProgress: 0, recoverNeeded: 0, geoVerified: false, consecutiveFailures: 0)
}

/// 纯逻辑熔断状态机：输入探测信号，输出是否熔断、是否硬切断。所有副作用由守护进程执行
public struct FuseEngine: Sendable {
    public private(set) var config: FuseConfig
    public private(set) var snapshot = FuseSnapshot.armed
    private var coreUp = false
    private var tunUp = false
    private var successes = 0
    private var geoOKSinceTrip = false
    /// 非守护类原因且关闭了自动恢复（或手动熔断）时上锁，只能由用户解除
    private var manualLatch = false
    /// 收到睡眠通知后、收到唤醒前为 true；期间绝不恢复
    private var asleepSince: Date?
    private var ipv6Leaking = false

    public init(config: FuseConfig, now: Date, startTripped: Bool = true) {
        self.config = config
        if config.enabled && startTripped {
            trip(.starting, now: now, hold: 0)
        }
    }

    public mutating func update(config new: FuseConfig, now: Date) {
        let modeChanged = new.mode != config.mode
        config = new
        if !new.enabled {
            snapshot = .armed
            return
        }
        // 切换出站模式后需要重新验证线路，按启动保护处理
        if modeChanged { trip(.starting, now: now, hold: 0) }
        if snapshot.tripped { snapshot.hard = new.action == .cutAll }
        refreshNeeded()
    }

    /// 内核重启：按启动保护重新验证，但保留手动锁、睡眠状态和未到期的保持期
    public mutating func coreRestarted(now: Date) {
        guard config.enabled else { return }
        coreUp = false
        tunUp = false
        trip(.starting, now: now, hold: 0)
    }

    /// 返回 true 表示熔断状态发生了变化
    @discardableResult
    public mutating func handle(_ signal: FuseSignal, now: Date) -> Bool {
        let before = snapshot
        guard config.enabled else {
            if case .health(let c, let t) = signal { coreUp = c; tunUp = t }
            snapshot = .armed
            return before != snapshot
        }
        switch signal {
        case .reset:
            recover()
        case .health(let c, let t):
            coreUp = c
            tunUp = t
            if !c { trip(.coreDown, now: now, hold: 0) } else if !t { trip(.tunLost, now: now, hold: 0) }
            tryRecover(now: now)
        case .sleep:
            asleepSince = now
            trip(.sleeping, now: now, hold: 0)
        case .wake:
            asleepSince = nil
            trip(.waking, now: now, hold: config.wakeHold)
        case .networkChanged:
            trip(.networkChanged, now: now, hold: max(3, config.wakeHold / 2))
        case .manualTrip:
            trip(.manual, now: now, hold: 0, force: true)
        case .manualRestore(let force):
            if force {
                recover()
            } else if snapshot.tripped {
                // 普通的手动恢复只解锁，仍然要通过健康检查和出口验证才放行
                manualLatch = false
                tryRecover(now: now)
            }
        case .probe(let ms):
            handleProbe(ok: probeOK(ms), now: now)
        case .geo(let country):
            handleGeo(country: country, now: now)
        case .ipv6(let leaking):
            ipv6Leaking = leaking
            if leaking { trip(.ipv6Leak, now: now, hold: 0) } else { tryRecover(now: now) }
        }
        return before != snapshot
    }

    // MARK: - 内部

    private func probeOK(_ ms: Int?) -> Bool {
        guard config.mode == .proxy else { return true }
        guard let ms else { return false }
        return ms <= config.latencyThresholdMs
    }

    private mutating func handleProbe(ok: Bool, now: Date) {
        if config.mode == .direct {
            snapshot.consecutiveFailures = 0
            tryRecover(now: now)
            return
        }
        if ok {
            snapshot.consecutiveFailures = 0
            if snapshot.tripped { successes += 1 }
        } else {
            snapshot.consecutiveFailures += 1
            successes = 0
            if snapshot.consecutiveFailures >= config.failureThreshold {
                trip(.proxyUnstable(failures: snapshot.consecutiveFailures), now: now, hold: 0)
            }
        }
        snapshot.recoverProgress = min(successes, snapshot.recoverNeeded)
        tryRecover(now: now)
    }

    private mutating func handleGeo(country: String?, now: Date) {
        guard config.mode == .proxy else { return }
        if let country, config.forbidden.contains(country) {
            trip(.unsafeExit(country: country), now: now, hold: 0, force: true)
            return
        }
        // 只有出口明确测到且安全才算验证通过，测不出来不能放行
        if country != nil {
            geoOKSinceTrip = true
            snapshot.geoVerified = true
        }
        tryRecover(now: now)
    }

    private mutating func trip(_ reason: FuseReason, now: Date, hold: TimeInterval, force: Bool = false) {
        // 白名单模式下所有原因都只开大陆白名单（pf 按 IP 把关，内核/TUN 故障时同样安全）
        let hard = config.action == .cutAll
        // 已熔断时轻微原因不覆盖严重原因的「显示」，但硬切断、保持期和重新验证照样生效
        let keepReason = snapshot.tripped && !force && snapshot.reason.map { priority(reason) < priority($0) } == true
        let wasTripped = snapshot.tripped
        snapshot.tripped = true
        if !keepReason { snapshot.reason = reason }
        // 硬切断一旦生效，直到恢复前都不降级为软熔断
        snapshot.hard = wasTripped ? (snapshot.hard || hard) : hard
        if !wasTripped { snapshot.since = now }
        if reason == .manual || (!reason.isTransientGuard && !config.autoRecover) { manualLatch = true }
        let until = now.addingTimeInterval(hold)
        snapshot.holdUntil = max(snapshot.holdUntil ?? until, until)
        successes = 0
        geoOKSinceTrip = false
        snapshot.geoVerified = false
        snapshot.recoverProgress = 0
        refreshNeeded()
    }

    private func priority(_ r: FuseReason) -> Int {
        switch r {
        case .manual: return 5
        case .unsafeExit: return 4
        case .coreDown, .tunLost, .ipv6Leak: return 3
        case .proxyUnstable: return 2
        case .sleeping, .waking, .networkChanged: return 1
        case .starting: return 0
        }
    }

    private mutating func refreshNeeded() {
        snapshot.recoverNeeded = config.mode == .proxy ? config.recoverSuccesses : 0
    }

    private mutating func tryRecover(now: Date) {
        guard snapshot.tripped, snapshot.reason != nil else { return }
        if manualLatch { return }
        if let asleep = asleepSince {
            // 唤醒通知丢失的兜底：睡眠期间计时器不会运行，20 秒后还能收到信号说明已经醒了
            guard now.timeIntervalSince(asleep) > 20 else { return }
            asleepSince = nil
            trip(.waking, now: now, hold: config.wakeHold)
            return
        }
        if let hold = snapshot.holdUntil, now < hold { return }
        guard coreUp, tunUp, !ipv6Leaking else { return }
        if config.mode == .proxy {
            guard successes >= config.recoverSuccesses, geoOKSinceTrip else { return }
        }
        recover()
    }

    private mutating func recover() {
        asleepSince = nil
        snapshot = .armed
        successes = 0
        geoOKSinceTrip = false
        manualLatch = false
    }

    public var isLatched: Bool { manualLatch }
}

public enum RegionNames {
    static let table: [String: String] = [
        "CN": "中国大陆", "HK": "香港", "MO": "澳门", "TW": "台湾", "JP": "日本", "KR": "韩国", "SG": "新加坡",
        "US": "美国", "GB": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰", "CA": "加拿大", "AU": "澳大利亚",
        "RU": "俄罗斯", "IN": "印度", "MY": "马来西亚", "TH": "泰国", "VN": "越南", "PH": "菲律宾", "ID": "印度尼西亚",
        "TR": "土耳其", "AE": "阿联酋", "IR": "伊朗", "KP": "朝鲜", "CH": "瑞士", "SE": "瑞典", "IT": "意大利", "ES": "西班牙",
    ]
    public static func name(_ code: String) -> String { table[code.uppercased()] ?? code }

    /// 节点名里常见的地区写法（中文、英文、代码、城市/机场代码、旗帜）
    static let nodeWords: [String: String] = [
        "CN": "中国|大陆|china|(?<![a-z])cn(?![a-z0-9])|上海|北京|广州|深圳|杭州|🇨🇳",
        "HK": "港|hong ?kong|(?<![a-z])hk(?![a-z])|hkg|🇭🇰",
        "MO": "澳门|澳門|macau|macao|(?<![a-z])mo(?![a-z0-9])|🇲🇴",
        "US": "美国|美國|united ?states|america|(?<![a-z])usa?(?![a-z])|洛杉矶|圣何塞|硅谷|西雅图|纽约|芝加哥|达拉斯|凤凰城|波特兰|弗吉尼亚|迈阿密|亚特兰大|(?<![a-z])(lax|sjc|sea|nyc|jfk|ord|dfw|iad|mia|atl|pdx)(?![a-z])|🇺🇸",
        "TW": "台湾|台灣|taiwan|(?<![a-z])tw(?![a-z])|🇹🇼",
        "JP": "日本|japan|(?<![a-z])jp(?![a-z])|东京|大阪|🇯🇵",
        "SG": "新加坡|狮城|singapore|(?<![a-z])sg(?![a-z])|🇸🇬",
        "KR": "韩国|韓國|korea|(?<![a-z])kr(?![a-z])|首尔|🇰🇷",
        "RU": "俄罗斯|russia|(?<![a-z])ru(?![a-z])|🇷🇺",
        "GB": "英国|united ?kingdom|(?<![a-z])(uk|gb)(?![a-z])|伦敦|🇬🇧",
        "DE": "德国|germany|(?<![a-z])de(?![a-z])|法兰克福|🇩🇪",
    ]

    public static func nodePattern(_ code: String) -> String {
        let c = code.uppercased()
        if let p = nodeWords[c] { return p }
        // 未收录的地区：中文名 + 国家代码 + 旗帜
        var parts = ["(?<![a-z])\(c.lowercased())(?![a-z])", flag(c)]
        if let n = table[c] { parts.insert(n, at: 0) }
        return parts.joined(separator: "|")
    }

    public static func flag(_ code: String) -> String {
        let base: UInt32 = 127397
        return code.uppercased().unicodeScalars.compactMap { UnicodeScalar(base + $0.value) }
            .map { String($0) }.joined()
    }
}
