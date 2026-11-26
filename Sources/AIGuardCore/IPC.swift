import Darwin
import Foundation

public enum AIGuardPaths {
    public static let daemonLabel = "com.aiguard.daemon"
    /// 环境变量 AIGUARD_SOCKET 仅用于连开发模式守护进程
    public static let socket = ProcessInfo.processInfo.environment["AIGUARD_SOCKET"] ?? "/var/run/com.aiguard.daemon.sock"
    public static let helperDir = "/Library/PrivilegedHelperTools/com.aiguard.daemon"
    public static let supportDir = "/Library/Application Support/AIGuard"
    public static let logDir = "/Library/Logs/AIGuard"
    public static let launchDaemonPlist = "/Library/LaunchDaemons/com.aiguard.daemon.plist"
}

public let AIGuardVersion = "1.2.0"

public enum GuardPhase: String, Codable, Sendable {
    case disabled
    case starting
    case protected
    /// 熔断（硬切断或仅阻断 AI）
    case tripped
    case error
}

public struct ExitStatus: Codable, Sendable, Equatable {
    public var trace: ExitTrace?
    public var checkedAt: Date?
    public var error: String?
    public init(trace: ExitTrace? = nil, checkedAt: Date? = nil, error: String? = nil) {
        self.trace = trace
        self.checkedAt = checkedAt
        self.error = error
    }
}

public struct LatencySample: Codable, Sendable, Equatable {
    public var at: Date
    /// 长连接心跳往返毫秒数，nil 表示失败
    public var ms: Int?
    public init(at: Date, ms: Int?) {
        self.at = at
        self.ms = ms
    }
}

public struct GuardStatus: Codable, Sendable, Equatable {
    public var version: String = AIGuardVersion
    public var phase: GuardPhase = .starting
    public var effectiveMode: ProxyMode = .direct
    public var routing: RoutingMode = .smart
    public var fuse: FuseSnapshot = .armed
    public var fuseLatched = false
    public var coreRunning = false
    public var coreVersion: String?
    public var coreRestarts = 0
    public var tunUp = false
    public var tunInterface: String?
    public var pfPolicy = "none"
    /// nil 表示还没检测过
    public var ipv6Blocked: Bool?
    /// 系统层面已关闭 IPv6 的网络服务数
    public var ipv6DisabledServices = 0
    /// 系统 DNS 已锁定到 TUN 的网络服务数
    public var dnsLockedServices = 0
    public var exit = ExitStatus()
    /// 长连接心跳是否在线
    public var heartbeatAlive = false
    public var latency: [LatencySample] = []
    public var primaryInterface: String?
    public var conflicts: [String] = []
    public var subscription: SubscriptionInfo?
    public var captiveUntil: Date?
    public var lastError: String?
    public var nodeCount: Int?
    public var updatedAt = Date()

    public init() {}
}

public enum EventLevel: String, Codable, Sendable {
    case info, warning, critical
}

public struct GuardEvent: Codable, Sendable, Equatable, Identifiable {
    public var id: Int
    public var at: Date
    public var level: EventLevel
    public var message: String
    public init(id: Int, at: Date, level: EventLevel, message: String) {
        self.id = id
        self.at = at
        self.level = level
        self.message = message
    }
}

public struct ControllerInfo: Codable, Sendable, Equatable {
    public var baseURL: String
    public var secret: String
    public var mixedPort: Int
    public init(baseURL: String, secret: String, mixedPort: Int) {
        self.baseURL = baseURL
        self.secret = secret
        self.mixedPort = mixedPort
    }
}

public enum IPCRequest: Codable, Sendable {
    case status
    case getSettings
    case updateSettings(GuardSettings)
    case importSubscription(url: String)
    case refreshSubscription
    case removeSubscription
    case tripFuse
    case restoreNetwork(force: Bool)
    case captiveLogin(minutes: Int)
    case endCaptiveLogin
    case controllerInfo
    case events(after: Int)
    case flushConnections
    case restartCore
}

public struct IPCResponse: Codable, Sendable {
    public var ok: Bool
    public var error: String?
    public var status: GuardStatus?
    public var settings: GuardSettings?
    public var controller: ControllerInfo?
    public var events: [GuardEvent]?

    public init(ok: Bool = true, error: String? = nil, status: GuardStatus? = nil, settings: GuardSettings? = nil,
                controller: ControllerInfo? = nil, events: [GuardEvent]? = nil) {
        self.ok = ok
        self.error = error
        self.status = status
        self.settings = settings
        self.controller = controller
        self.events = events
    }

    public static func failure(_ message: String) -> IPCResponse { IPCResponse(ok: false, error: message) }
}

public enum IPCCodec {
    public static let maxMessageBytes = 4 * 1024 * 1024

    public static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .secondsSince1970
        return e
    }

    public static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .secondsSince1970
        return d
    }
}

/// 一问一答的 Unix 域套接字通信：一行 JSON 请求，一行 JSON 响应
public enum UnixSocketIO {
    public static func connect(path: String, timeout: TimeInterval) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        var tv = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - floor(timeout)) * 1_000_000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            close(fd)
            throw POSIXError(.ENAMETOOLONG)
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            buf.copyBytes(from: bytes)
            buf[bytes.count] = 0
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else {
            let err = errno
            close(fd)
            throw POSIXError(.init(rawValue: err) ?? .ECONNREFUSED)
        }
        return fd
    }

    public static func writeAll(fd: Int32, data: Data) throws {
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw POSIXError(.init(rawValue: errno) ?? .EIO)
                }
                offset += n
            }
        }
    }

    /// 读到换行或 EOF 为止
    public static func readLine(fd: Int32) throws -> Data {
        var out = Data()
        var buf = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let n = Darwin.read(fd, &buf, buf.count)
            if n < 0 {
                if errno == EINTR { continue }
                throw POSIXError(.init(rawValue: errno) ?? .EIO)
            }
            if n == 0 { break }
            if let nl = buf[0..<n].firstIndex(of: 0x0A) {
                out.append(contentsOf: buf[0..<nl])
                break
            }
            out.append(contentsOf: buf[0..<n])
            if out.count > IPCCodec.maxMessageBytes { throw POSIXError(.EMSGSIZE) }
        }
        return out
    }

    /// 客户端调用（阻塞），供界面在后台线程使用
    public static func request(_ req: IPCRequest, path: String = AIGuardPaths.socket, timeout: TimeInterval = 15) throws -> IPCResponse {
        let fd = try connect(path: path, timeout: timeout)
        defer { close(fd) }
        var payload = try IPCCodec.encoder().encode(req)
        payload.append(0x0A)
        try writeAll(fd: fd, data: payload)
        let line = try readLine(fd: fd)
        return try IPCCodec.decoder().decode(IPCResponse.self, from: line)
    }
}
