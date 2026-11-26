import Foundation

public enum PFPolicy: Equatable, Sendable {
    /// 不加载任何规则
    case none
    /// 平时：只允许经 TUN 出站，普通用户进程绕过 TUN 直连外网（泄漏）一律丢弃
    case leakGuard(tun: String)
    /// 熔断：切断全部外网，只留回环、局域网、DHCP，以及 root 进程（内核需要连节点做探测）
    case lockdown
    /// 关闭防泄漏层时仍然保留：IPv6 封锁 + DNS 防泄漏
    case basic(tun: String)
    /// 熔断（大陆白名单）：任何进程只能连大陆 IP；内核（root）额外可连节点/订阅服务器用于恢复；
    /// allowTUN 为 true 时放行进入 TUN 的流量，由内核按域名只放大陆直连（闸门确认后才放）
    case whitelist(tun: String, allowTUN: Bool, cnTable: String, allow: [String])

    public var name: String {
        switch self {
        case .none: return "none"
        case .leakGuard: return "leakGuard"
        case .lockdown: return "lockdown"
        case .basic: return "basic"
        case .whitelist: return "whitelist"
        }
    }
}

public enum PFRulesBuilder {
    public static let anchor = "com.apple/250.AIGuard"
    /// 1.1 的美国 IP 封禁锚点，已废弃；启动和卸载时清理残留
    public static let legacyUSAnchor = "com.apple/240.AIGuardUS"
    public static let cnTable = "aiguard_cn"
    static let lan = "{ 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 255.255.255.255 }"
    /// 普通登录用户的 uid 区间（501 起），不含 nobody 等系统账户
    static let humanUsers = "user 500 >< 65534"

    /// DNS 防泄漏：除 root（内核自己的上游解析）外，53/853 端口只能经 TUN 发出，
    /// 发往路由器/酒店 DNS 的明文查询一律拒绝
    static let dnsGuard = [
        "pass out quick proto { tcp udp } from any to any port { 53 853 } user 0 no state",
        "block return out quick proto { tcp udp } from any to any port { 53 853 }",
    ]
    static let ipv6Guard = [
        "pass out quick inet6 from any to { fe80::/10 ff00::/8 } no state",
        "block return out quick inet6 all",
    ]

    /// 全部规则用 no state：切换策略时不会有旧状态让已建立的连接继续漏出去
    public static func rules(for policy: PFPolicy) -> String {
        var r = ["# AIGuard 自动生成，请勿手动修改"]
        switch policy {
        case .none:
            return ""
        case .leakGuard(let tun), .basic(let tun):
            guard isValidInterface(tun) else { return rules(for: .lockdown) }
            r += ["pass quick on lo0 all no state", "pass out quick on \(tun) all no state"]
            r += dnsGuard
            r += ipv6Guard
            if case .leakGuard = policy {
                r += [
                    "pass out quick inet from any to \(lan) no state",
                    "pass out quick inet proto udp from any port 68 to any port 67 no state",
                    "block drop out quick proto { tcp udp } all \(humanUsers)",
                ]
            }
        case .whitelist(let tun, let allowTUN, let cnFile, let allow):
            guard isValidInterface(tun), isSafePath(cnFile) else { return rules(for: .lockdown) }
            let ips = allow.filter(isIPv4)
            r += ["table <\(cnTable)> persist file \"\(cnFile)\""]
            if !ips.isEmpty { r += ["table <\(allowTable)> { \(ips.joined(separator: " ")) }"] }
            r += ["pass quick on lo0 all no state"]
            // 白名单下内核自己的 DNS 只能发往大陆 DNS（223.5.5.5 等）和局域网（酒店 DHCP DNS）
            r += [
                "pass out quick proto { tcp udp } from any to <\(cnTable)> port { 53 853 } user 0 no state",
                "pass out quick proto { tcp udp } from any to \(lan) port { 53 853 } user 0 no state",
                "block return out quick proto { tcp udp } from any to any port { 53 853 }",
            ]
            r += ipv6Guard
            r += [
                "pass out quick inet from any to \(lan) no state",
                "pass out quick inet proto udp from any port 68 to any port 67 no state",
            ]
            if allowTUN { r += ["pass out quick on \(tun) all no state"] }
            r += ["pass out quick inet from any to <\(cnTable)> no state"]
            if !ips.isEmpty { r += ["pass out quick proto { tcp udp } from any to <\(allowTable)> user 0 no state"] }
            r += ["block return out quick all"]
        case .lockdown:
            r += ["pass quick on lo0 all no state"]
            r += dnsGuard
            r += ipv6Guard
            r += [
                "pass out quick inet from any to \(lan) no state",
                "pass out quick inet proto udp from any port 68 to any port 67 no state",
                "pass out quick proto { tcp udp } all user 0 no state",
                "block drop out quick all",
            ]
        }
        return r.joined(separator: "\n") + "\n"
    }

    public static let allowTable = "aiguard_allow"

    /// 表文件路径会拼进规则，只接受普通绝对路径
    static func isSafePath(_ p: String) -> Bool {
        p.hasPrefix("/") && !p.contains("\"") && !p.contains("\n") && !p.contains("..")
    }

    public static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { p in
            !p.isEmpty && p.count <= 3 && p.allSatisfy(\.isNumber) && Int(p).map { $0 <= 255 } == true
        }
    }

    /// 接口名会拼进 pf 规则，只接受 utunN 这种形式
    public static func isValidInterface(_ name: String) -> Bool {
        guard name.hasPrefix("utun") else { return false }
        let n = name.dropFirst(4)
        return !n.isEmpty && n.count <= 4 && n.allSatisfy(\.isNumber)
    }
}
