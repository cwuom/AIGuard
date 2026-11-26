import Foundation

/// mihomo RESTful API 客户端（只连 127.0.0.1）
public final class MihomoAPI: Sendable {
    public let base: URL
    public let secret: String
    private let session: URLSession
    /// 最近一次重载失败时内核返回的信息，方便写日志
    public let lastReloadError = LockedValue<String?>(nil)

    public convenience init(port: Int, secret: String) {
        self.init(base: URL(string: "http://127.0.0.1:\(port)")!, secret: secret)
    }

    public init(base: URL, secret: String) {
        self.base = base
        self.secret = secret
        let cfg = URLSessionConfiguration.ephemeral
        cfg.connectionProxyDictionary = [:]
        cfg.timeoutIntervalForRequest = 8
        cfg.httpMaximumConnectionsPerHost = 8
        session = URLSession(configuration: cfg)
    }

    private func request(_ path: String, method: String = "GET", query: [URLQueryItem] = [], body: Any? = nil,
                         timeout: TimeInterval = 5) async throws -> (Data, Int) {
        var req = makeRequest(path, query: query, timeout: timeout)
        req.httpMethod = method
        if let body {
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, resp) = try await session.data(for: req)
        return (data, (resp as? HTTPURLResponse)?.statusCode ?? 0)
    }

    private func makeRequest(_ path: String, query: [URLQueryItem] = [], timeout: TimeInterval) -> URLRequest {
        var comps = URLComponents(url: base, resolvingAgainstBaseURL: false)!
        // 策略组名包含中文和空格，必须逐段编码
        comps.percentEncodedPath = path
        if !query.isEmpty { comps.queryItems = query }
        var req = URLRequest(url: comps.url!, timeoutInterval: timeout)
        req.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        return req
    }

    public static func seg(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? s
    }

    public func version() async -> String? {
        guard let (data, code) = try? await request("/version", timeout: 2), code == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return obj["version"] as? String
    }

    /// 经指定策略组测一次延迟（不经过规则和闸门），失败返回 nil
    public func delay(_ proxy: String, url: String, timeoutMs: Int) async -> Int? {
        let q = [URLQueryItem(name: "url", value: url), URLQueryItem(name: "timeout", value: String(timeoutMs))]
        guard let (data, code) = try? await request("/proxies/\(Self.seg(proxy))/delay", query: q,
                                                     timeout: TimeInterval(timeoutMs) / 1000 + 2),
              code == 200, let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let d = obj["delay"] as? Int, d > 0 else { return nil }
        return d
    }

    @discardableResult
    public func select(group: String, proxy: String) async -> Bool {
        guard let (_, code) = try? await request("/proxies/\(Self.seg(group))", method: "PUT", body: ["name": proxy])
        else { return false }
        return code == 204 || code == 200
    }

    public struct GroupInfo: Sendable {
        public var now: String?
        public var all: [String]
    }

    public func group(_ name: String) async -> GroupInfo? {
        guard let (data, code) = try? await request("/proxies/\(Self.seg(name))"), code == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return GroupInfo(now: obj["now"] as? String, all: obj["all"] as? [String] ?? [])
    }

    /// 内核对这个节点的最新健康判断（nil 表示查询失败）
    public func isAlive(_ name: String) async -> Bool? {
        guard let (data, code) = try? await request("/proxies/\(Self.seg(name))"), code == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return obj["alive"] as? Bool
    }

    public func reloadConfig(path: String) async -> Bool {
        guard let (data, code) = try? await request("/configs", method: "PUT", query: [URLQueryItem(name: "force", value: "true")],
                                                     body: ["path": path], timeout: 20) else { return false }
        if code != 204 && code != 200 { lastReloadError.set(String(decoding: data.prefix(300), as: UTF8.self)) }
        return code == 204 || code == 200
    }

    public func reloadProvider(_ name: String) async -> Bool {
        guard let (_, code) = try? await request("/providers/proxies/\(Self.seg(name))", method: "PUT", timeout: 20) else { return false }
        return code == 204 || code == 200
    }

    public func providerCount(_ name: String) async -> Int? {
        guard let (data, code) = try? await request("/providers/proxies/\(Self.seg(name))"), code == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let proxies = obj["proxies"] as? [Any] else { return nil }
        return proxies.count
    }

    public struct ProxyItem: Sendable, Identifiable, Equatable {
        public var id: String { name }
        public var name: String
        public var type: String
        public var now: String?
        public var all: [String]
        public var lastDelay: Int?
        public var alive: Bool
    }

    /// 全部节点与策略组（界面列表用）
    public func proxies() async -> [String: ProxyItem] {
        guard let (data, code) = try? await request("/proxies"), code == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let map = obj["proxies"] as? [String: [String: Any]] else { return [:] }
        var out: [String: ProxyItem] = [:]
        for (name, p) in map {
            let history = p["history"] as? [[String: Any]] ?? []
            let last = (history.last?["delay"] as? Int).flatMap { $0 > 0 ? $0 : nil }
            out[name] = ProxyItem(name: name, type: p["type"] as? String ?? "", now: p["now"] as? String,
                                  all: p["all"] as? [String] ?? [], lastDelay: last, alive: p["alive"] as? Bool ?? true)
        }
        return out
    }

    /// 并发测速整个策略组，返回 节点名 → 延迟
    public func groupDelay(_ name: String, url: String, timeoutMs: Int) async -> [String: Int] {
        let q = [URLQueryItem(name: "url", value: url), URLQueryItem(name: "timeout", value: String(timeoutMs))]
        guard let (data, code) = try? await request("/group/\(Self.seg(name))/delay", query: q,
                                                     timeout: TimeInterval(timeoutMs) / 1000 + 10),
              code == 200, let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Int] else { return [:] }
        return obj
    }

    public struct Traffic: Sendable, Equatable {
        public var up: Int64
        public var down: Int64
        public init(up: Int64, down: Int64) {
            self.up = up
            self.down = down
        }
    }

    /// /traffic 是每秒一行 JSON 的长连接
    public func trafficStream() -> AsyncThrowingStream<Traffic, Error> {
        let req = makeRequest("/traffic", timeout: 3600)
        let session = self.session
        return AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let (bytes, _) = try await session.bytes(for: req)
                    for try await line in bytes.lines {
                        guard let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else { continue }
                        continuation.yield(Traffic(up: (obj["up"] as? NSNumber)?.int64Value ?? 0,
                                                   down: (obj["down"] as? NSNumber)?.int64Value ?? 0))
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    public struct Connection: Sendable, Identifiable, Equatable {
        public var id: String
        public var host: String
        public var destination: String
        public var network: String
        public var chain: String
        public var rule: String
        public var upload: Int64
        public var download: Int64
        public var start: Date?
    }

    public struct ConnectionsSnapshot: Sendable, Equatable {
        public var connections: [Connection]
        public var uploadTotal: Int64
        public var downloadTotal: Int64
    }

    nonisolated(unsafe) private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
    private static let isoLock = NSLock()

    /// 当前全部连接（界面的连接列表用）
    public func connections() async -> ConnectionsSnapshot? {
        guard let (data, code) = try? await request("/connections"), code == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let list = (obj["connections"] as? [[String: Any]] ?? []).map { c -> Connection in
            let m = c["metadata"] as? [String: Any] ?? [:]
            let host = (m["host"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? (m["sniffHost"] as? String) ?? ""
            let dst = "\(m["destinationIP"] as? String ?? ""):\(m["destinationPort"] as? String ?? "")"
            let chains = (c["chains"] as? [String] ?? []).filter { !$0.hasPrefix(GroupName.internalPrefix) }
            let rule = [c["rule"] as? String, c["rulePayload"] as? String].compactMap { $0 }.filter { !$0.isEmpty }
                .joined(separator: " · ")
            let start = (c["start"] as? String).flatMap { s -> Date? in
                Self.isoLock.lock()
                defer { Self.isoLock.unlock() }
                return Self.isoFormatter.date(from: s)
            }
            return Connection(id: c["id"] as? String ?? UUID().uuidString, host: host, destination: dst,
                              network: (m["network"] as? String ?? "").uppercased(),
                              chain: chains.reversed().joined(separator: " → "), rule: rule,
                              upload: (c["upload"] as? NSNumber)?.int64Value ?? 0,
                              download: (c["download"] as? NSNumber)?.int64Value ?? 0, start: start)
        }
        return ConnectionsSnapshot(connections: list,
                                   uploadTotal: (obj["uploadTotal"] as? NSNumber)?.int64Value ?? 0,
                                   downloadTotal: (obj["downloadTotal"] as? NSNumber)?.int64Value ?? 0)
    }

    public func closeConnection(_ id: String) async {
        _ = try? await request("/connections/\(Self.seg(id))", method: "DELETE")
    }

    public func connectionCount() async -> Int? {
        guard let (data, code) = try? await request("/connections"), code == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return (obj["connections"] as? [Any])?.count ?? 0
    }

    /// 用内核自己的 DNS（不经过闸门、不走系统解析）查 A 记录
    public func resolveA(_ name: String) async -> [String] {
        let q = [URLQueryItem(name: "name", value: name), URLQueryItem(name: "type", value: "A")]
        guard let (data, code) = try? await request("/dns/query", query: q, timeout: 5), code == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let answers = obj["Answer"] as? [[String: Any]] else { return [] }
        return answers.compactMap { ($0["type"] as? Int) == 1 ? $0["data"] as? String : nil }
    }

    public func flushConnections() async {
        _ = try? await request("/connections", method: "DELETE")
    }
}

/// 经本机带认证的 HTTP 代理入站发请求（用于出口检测和订阅下载）
public final class ProxiedFetcher: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let user: String
    private let password: String
    private var sessions: [Int: URLSession] = [:]
    private let lock = NSLock()

    public init(user: String, password: String) {
        self.user = user
        self.password = password
    }

    private func session(port: Int?) -> URLSession {
        lock.lock()
        defer { lock.unlock() }
        let key = port ?? 0
        if let s = sessions[key] { return s }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.httpShouldSetCookies = false
        if let port {
            cfg.connectionProxyDictionary = [
                "HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": port,
                "HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort": port,
            ]
        } else {
            cfg.connectionProxyDictionary = [:]
        }
        let s = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
        sessions[key] = s
        return s
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.isProxy(), challenge.previousFailureCount == 0 {
            completionHandler(.useCredential, URLCredential(user: user, password: password, persistence: .forSession))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }

    /// 丢弃某个端口的会话：节点切换后旧的长连接还连着旧节点，必须重建
    public func reset(port: Int?) {
        lock.lock()
        let s = sessions.removeValue(forKey: port ?? 0)
        lock.unlock()
        s?.invalidateAndCancel()
    }

    /// 经内核直连入站向阿里 DNS（JSON API）查 A 记录：不依赖代理、不经过闸门，熔断时也能用
    public func resolveDirect(_ name: String, viaPort port: Int) async -> [String] {
        var c = URLComponents(string: "https://223.5.5.5/resolve")!
        c.queryItems = [URLQueryItem(name: "name", value: name), URLQueryItem(name: "type", value: "1")]
        guard let url = c.url, let (data, resp) = try? await fetch(url, viaPort: port, timeout: 5), resp.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let answers = obj["Answer"] as? [[String: Any]] else { return [] }
        return answers.compactMap { ($0["type"] as? Int) == 1 ? $0["data"] as? String : nil }
    }

    /// 备用出口查询（心跳里 Cloudflare 失败时用，超时受心跳剩余预算限制）
    public func ipinfo(viaPort port: Int, timeout: TimeInterval) async -> ExitTrace? {
        guard timeout > 0.2,
              let (data, resp) = try? await fetch(URL(string: "https://ipinfo.io/json")!, viaPort: port, timeout: timeout),
              resp.statusCode == 200 else { return nil }
        return ExitTrace.parseJSON(data)
    }

    public func fetch(_ url: URL, viaPort port: Int?, timeout: TimeInterval, headers: [String: String] = [:]) async throws
        -> (Data, HTTPURLResponse) {
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        let (data, resp) = try await session(port: port).data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return (data, http)
    }

    /// 心跳：经长连接请求一次 Cloudflare trace。会话按端口缓存，TLS 连接保持复用，
    /// 所以每次心跳只是在同一条长连接上发一个小请求
    public func heartbeat(viaPort port: Int, timeout: TimeInterval) async -> ExitTrace? {
        guard let (data, resp) = try? await fetch(URL(string: "https://www.cloudflare.com/cdn-cgi/trace")!, viaPort: port,
                                                  timeout: timeout),
              resp.statusCode == 200 else { return nil }
        return ExitTrace.parseCloudflare(String(decoding: data, as: UTF8.self))
    }

    /// 先查 Cloudflare trace，失败再查 ipinfo，两个都失败返回 nil
    public func exitTrace(viaPort port: Int) async -> ExitTrace? {
        if let (data, resp) = try? await fetch(URL(string: "https://www.cloudflare.com/cdn-cgi/trace")!, viaPort: port, timeout: 6),
           resp.statusCode == 200, let t = ExitTrace.parseCloudflare(String(decoding: data, as: UTF8.self)) {
            return t
        }
        // 备用源也必须走 HTTPS，明文结果可被链路上篡改从而骗过出口验证
        if let (data, resp) = try? await fetch(URL(string: "https://ipinfo.io/json")!, viaPort: port, timeout: 6),
           resp.statusCode == 200, let t = ExitTrace.parseJSON(data) {
            return t
        }
        return nil
    }
}


public final class LockedValue<T: Sendable>: @unchecked Sendable {
    private var value: T
    private let lock = NSLock()
    public init(_ v: T) { value = v }
    public func get() -> T { lock.lock(); defer { lock.unlock() }; return value }
    public func set(_ v: T) { lock.lock(); value = v; lock.unlock() }
}
