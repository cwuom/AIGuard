import Foundation

public enum SubscriptionFormat: String, Codable, Sendable {
    case clashYAML
    case uriList
}

public struct ParsedSubscription: Sendable, Equatable {
    public var format: SubscriptionFormat
    public var nodeCount: Int
    /// 写给 mihomo 文件型 proxy-provider 的内容
    public var providerContent: String
}

public enum SubscriptionError: Error, LocalizedError, Equatable {
    case invalidURL
    case empty
    case unrecognized
    case noNodes
    case http(Int)

    public var errorDescription: String? {
        switch self {
        case .invalidURL: return "订阅链接无效，只支持 http/https"
        case .empty: return "订阅返回了空内容"
        case .unrecognized: return "无法识别订阅格式（需要 Clash YAML 或节点链接列表）"
        case .noNodes: return "订阅里没有可用节点"
        case .http(let code): return "订阅服务器返回 HTTP \(code)"
        }
    }
}

public enum SubscriptionParser {
    static let schemes = ["ss://", "ssr://", "vmess://", "vless://", "trojan://", "hysteria://", "hysteria2://",
                          "hy2://", "tuic://", "anytls://", "wireguard://", "wg://", "socks5://", "socks://",
                          "snell://"]

    public static func validateURL(_ s: String) -> URL? {
        guard let url = URL(string: s.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
              url.host?.isEmpty == false else { return nil }
        return url
    }

    public static func parse(_ data: Data) throws -> ParsedSubscription {
        guard var text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
            throw SubscriptionError.unrecognized
        }
        text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { throw SubscriptionError.empty }

        if let yaml = parseClashYAML(text) { return yaml }
        if let list = parseURIList(text) { return list }
        if let decoded = decodeBase64(text), let list = parseURIList(decoded) { return list }
        throw SubscriptionError.unrecognized
    }

    /// 只抽取 proxies 段，丢弃机场自带的规则和策略组（分流由本软件负责）
    static func parseClashYAML(_ text: String) -> ParsedSubscription? {
        let lines = text.components(separatedBy: .newlines)
        guard let start = lines.firstIndex(where: { $0.hasPrefix("proxies:") }) else { return nil }
        var section = [lines[start]]
        var count = 0
        for line in lines[(start + 1)...] {
            if let first = line.first, !first.isWhitespace, first != "-", first != "#" { break }
            section.append(line)
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("- {") || t.hasPrefix("-{") || t.hasPrefix("- name:") { count += 1 }
        }
        // 行内写法 proxies: [ ... ] 极少见，交给内核解析
        if count == 0, lines[start].contains("[") { count = lines[start].components(separatedBy: "name:").count - 1 }
        guard count > 0 else { return nil }
        return ParsedSubscription(format: .clashYAML, nodeCount: count, providerContent: section.joined(separator: "\n") + "\n")
    }

    static func parseURIList(_ text: String) -> ParsedSubscription? {
        let nodes = text.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { line in
                let lower = line.lowercased()
                return schemes.contains { lower.hasPrefix($0) } && line.count > 12
            }
        guard !nodes.isEmpty else { return nil }
        return ParsedSubscription(format: .uriList, nodeCount: nodes.count, providerContent: nodes.joined(separator: "\n") + "\n")
    }

    static func decodeBase64(_ text: String) -> String? {
        var s = text.components(separatedBy: .whitespacesAndNewlines).joined()
        s = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        guard let data = Data(base64Encoded: s) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// 从 provider 内容里取出全部节点服务器地址（域名或 IP），用于熔断期间给内核留的窄例外
    public static func serverHosts(providerContent text: String) -> [String] {
        var hosts = Set<String>()
        func add(_ raw: Substring) {
            let h = raw.trimmingCharacters(in: CharacterSet(charactersIn: "\"' []"))
            if !h.isEmpty, h.count <= 253, h.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-") }) {
                hosts.insert(h.lowercased())
            }
        }
        for line in text.components(separatedBy: .newlines) {
            let t = line.trimmingCharacters(in: .whitespaces)
            // YAML：server: x 或行内 {server: x, ...}
            if let r = t.range(of: #"(?<![a-z-])server:\s*([^,}\s]+)"#, options: .regularExpression) {
                add(t[r].split(separator: ":", maxSplits: 1)[1])
                continue
            }
            let lower = t.lowercased()
            if lower.hasPrefix("vmess://"), let json = decodeBase64(String(t.dropFirst(8))),
               let obj = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any],
               let add_ = obj["add"] as? String {
                add(Substring(add_))
                continue
            }
            // scheme://user@host:port 形式
            guard schemes.contains(where: { lower.hasPrefix($0) }),
                  let at = t.range(of: "@", options: .backwards) ?? t.range(of: "://") else { continue }
            let rest = t[at.upperBound...]
            let hostPart = rest.prefix { $0 != ":" && $0 != "/" && $0 != "?" && $0 != "#" }
            add(hostPart)
        }
        return hosts.sorted()
    }

    /// `profile-title` 可能是 `base64:xxxx`；否则退回 Content-Disposition 里的文件名
    public static func profileName(headers: [String: String]) -> String? {
        let lower = Dictionary(headers.map { ($0.key.lowercased(), $0.value) }, uniquingKeysWith: { a, _ in a })
        if let title = lower["profile-title"], !title.isEmpty {
            if title.hasPrefix("base64:"), let d = Data(base64Encoded: String(title.dropFirst(7))),
               let s = String(data: d, encoding: .utf8) { return s }
            return title
        }
        guard let cd = lower["content-disposition"] else { return nil }
        if let r = cd.range(of: "filename*=UTF-8''") {
            let v = cd[r.upperBound...].split(separator: ";").first.map(String.init) ?? ""
            return v.removingPercentEncoding
        }
        if let r = cd.range(of: "filename=") {
            return cd[r.upperBound...].split(separator: ";").first.map {
                $0.trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
            }
        }
        return nil
    }
}

/// Cloudflare `/cdn-cgi/trace` 返回 `ip=...\nloc=US\n...`
public struct ExitTrace: Codable, Sendable, Equatable {
    public var ip: String
    public var country: String

    public init(ip: String, country: String) {
        self.ip = ip
        self.country = country
    }

    public static func parseCloudflare(_ text: String) -> ExitTrace? {
        var ip: String?
        var loc: String?
        for line in text.split(whereSeparator: \.isNewline) {
            let kv = line.split(separator: "=", maxSplits: 1)
            guard kv.count == 2 else { continue }
            if kv[0] == "ip" { ip = String(kv[1]) }
            if kv[0] == "loc" { loc = String(kv[1]).uppercased() }
        }
        guard let ip, let loc, loc.count == 2 else { return nil }
        return ExitTrace(ip: ip, country: loc)
    }

    /// 备用出口查询（ipinfo.io `{"ip":..,"country":"US"}`，也兼容 ip-api 的 countryCode/query）
    public static func parseJSON(_ data: Data) -> ExitTrace? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let c = (obj["country"] ?? obj["countryCode"] ?? obj["country_code"]) as? String
        let ip = (obj["ip"] ?? obj["query"]) as? String
        guard let c, c.count == 2, c.allSatisfy(\.isLetter), let ip else { return nil }
        return ExitTrace(ip: ip, country: c.uppercased())
    }
}
