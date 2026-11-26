import Foundation

/// mihomo 里的策略组名称。闸门组只给守护进程用，界面不展示
public enum GroupName {
    public static let proxy = "节点选择"
    public static let auto = "自动选择"
    public static let gateAI = "AIGUARD-GATE-AI"
    public static let gateMain = "AIGUARD-GATE-MAIN"
    public static let gateDirect = "AIGUARD-GATE-DIRECT"
    /// 大陆流量闸门：智能分流=DIRECT，全局=节点选择，软熔断=DIRECT，硬熔断=REJECT
    public static let gateCN = "AIGUARD-GATE-CN"
    public static let internalPrefix = "AIGUARD-"
    public static let providerName = "sub"
}

/// 守护进程运行期参数（端口、密钥等），与用户设置分开
public struct CoreRuntime: Sendable, Equatable {
    public var controllerPort: Int
    public var secret: String
    public var listenerUser: String
    public var listenerPassword: String
    /// 带认证的探测入站，直通「节点选择」，不经过规则和闸门（心跳长连接、出口检测、订阅下载用）
    public var probePort: Int
    public var directProbePort: Int
    public var tunDevice: String
    public var tunEnabled: Bool
    public var hasSubscription: Bool

    public init(controllerPort: Int = 19097, secret: String, listenerUser: String = "aiguard", listenerPassword: String,
                probePort: Int = 17892, directProbePort: Int = 17893,
                tunDevice: String = "utun199", tunEnabled: Bool = true, hasSubscription: Bool) {
        self.controllerPort = controllerPort
        self.secret = secret
        self.listenerUser = listenerUser
        self.listenerPassword = listenerPassword
        self.probePort = probePort
        self.directProbePort = directProbePort
        self.tunDevice = tunDevice
        self.tunEnabled = tunEnabled
        self.hasSubscription = hasSubscription
    }
}

public enum MihomoConfigBuilder {
    /// 订阅里的流量/到期提示「节点」
    static let infoNodeWords = "剩余|流量|到期|过期|有效期|expire|官网|网址|重置|套餐|订阅|traffic|频道|群组|telegram|客服|公告"

    /// 按出口禁区生成节点排除正则：禁区里的地区不会被自动选中，避免反复熔断
    public static func excludeFilter(regions: [String], extra: [String] = []) -> String {
        var parts = regions.map { RegionNames.nodePattern($0) }
        parts += extra
        parts.append(infoNodeWords)
        return "(?i)(" + parts.joined(separator: "|") + ")"
    }

    /// 单线路的节点排除：出口禁区 + 回国/直连 + AI 服务不支持的俄罗斯
    public static func nodeExcludeFilter(_ s: GuardSettings) -> String {
        excludeFilter(regions: s.sanitized().forbiddenRegions, extra: ["回国|直连|俄罗斯|russia"])
    }

    static let privateCIDRs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                               "100.64.0.0/10", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"]
    static let testURL = "http://cp.cloudflare.com/generate_204"
    // DNS 服务器全部用 IP，不依赖系统解析；连接方式写死在 # 后缀里，不经过分流规则和闸门，
    // 熔断时（闸门 REJECT）内核自己的解析仍然可用，订阅下载和节点探测不会被卡住
    static let domesticDoH = ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"]
    static let foreignDoH = ["https://1.1.1.1/dns-query#\(GroupName.proxy)", "https://8.8.8.8/dns-query#\(GroupName.proxy)"]

    public static func effectiveMode(_ settings: GuardSettings, _ rt: CoreRuntime) -> ProxyMode {
        rt.hasSubscription ? settings.mode : .direct
    }

    /// captive=true 表示 Wi-Fi 登录模式：直连且不限大陆，方便打开认证页（AI 仍拒绝）。
    /// captiveInterface 是当前物理网卡，登录模式下用它的 DHCP DNS 解析认证页
    public static func build(settings raw: GuardSettings, runtime rt: CoreRuntime, captive: Bool = false,
                             captiveInterface: String? = nil) -> String {
        let s = raw.sanitized()
        let mode = captive ? .direct : effectiveMode(s, rt)
        var y = YAMLWriter()

        y.line("mixed-port: \(s.mixedPort)")
        y.line("allow-lan: false")
        y.line("mode: rule")
        y.line("log-level: warning")
        y.line("ipv6: false")
        y.line("unified-delay: true")
        y.line("tcp-concurrent: true")
        y.line("find-process-mode: off")
        y.line("geo-auto-update: false")
        y.line("external-controller: \(q("127.0.0.1:\(rt.controllerPort)"))")
        y.line("secret: \(q(rt.secret))")
        y.line("skip-auth-prefixes: []")
        y.line("profile:")
        y.line("  store-selected: true")
        y.line("  store-fake-ip: true")

        // TUN：接管全部流量，并由内核把系统 DNS 指向 TUN（macOS 无法劫持发往局域网的 DNS）
        y.line("tun:")
        y.line("  enable: \(rt.tunEnabled)")
        y.line("  stack: mixed")
        y.line("  device: \(q(rt.tunDevice))")
        y.line("  auto-route: true")
        y.line("  auto-detect-interface: true")
        y.line("  dns-mode: hijack")
        y.line("  dns-hijack: [\(q("any:53")), \(q("tcp://any:53"))]")

        y.line("sniffer:")
        y.line("  enable: true")
        y.line("  force-dns-mapping: true")
        y.line("  parse-pure-ip: true")
        y.line("  override-destination: true")
        y.line("  sniff:")
        y.line("    HTTP: {ports: [80, 8080-8880]}")
        y.line("    TLS: {ports: [443, 8443]}")
        y.line("    QUIC: {ports: [443, 8443]}")
        y.line("  skip-domain: [\(q("+.push.apple.com")), \(q("Mijia Cloud"))]")

        y.line("dns:")
        y.line("  enable: true")
        y.line("  listen: \(q("127.0.0.1:1053"))")
        y.line("  ipv6: false")
        y.line("  cache-algorithm: arc")
        y.line("  enhanced-mode: fake-ip")
        y.line("  fake-ip-range: 198.18.0.1/16")
        y.line("  fake-ip-filter-mode: blacklist")
        // NTP 域名不能放进过滤表：拿到真实 IP 后域名规则就匹配不到了
        let fakeIPFilter = ["rule-set:cn-site", "*.lan", "*.local", "*.localdomain", "*.home.arpa", "+.msftconnecttest.com",
                            "+.msftncsi.com", "localhost.ptlogin2.qq.com", "+.stun.*.*", "+.stun.*.*.*"]
        y.list("  fake-ip-filter", fakeIPFilter)
        y.list("  default-nameserver", ["223.5.5.5", "119.29.29.29"])
        y.list("  proxy-server-nameserver", domesticDoH)
        y.list("  direct-nameserver", domesticDoH)
        if mode == .proxy && rt.hasSubscription {
            // 境外域名经代理走 DoH，ISP 看不到查询；大陆域名用国内 DoH
            y.list("  nameserver", foreignDoH)
            y.line("  nameserver-policy:")
            y.line("    \(q("rule-set:cn-site")): [\(domesticDoH.map(q).joined(separator: ", "))]")
        } else if captive, let iface = captiveInterface, iface.range(of: "^en[0-9]{1,3}$", options: .regularExpression) != nil {
            // 酒店认证页通常只能用 DHCP 下发的 DNS 解析
            y.list("  nameserver", ["dhcp://\(iface)"] + domesticDoH)
        } else {
            y.list("  nameserver", domesticDoH)
        }

        if rt.hasSubscription {
            y.line("proxy-providers:")
            y.line("  \(GroupName.providerName):")
            y.line("    type: file")
            y.line("    path: \(q("./providers/sub.yaml"))")
            y.line("    health-check: {enable: false}")
        }

        y.line("rule-providers:")
        for r in BundledRuleSets.all {
            y.line("  \(r.provider): {type: file, behavior: \(r.behavior), format: mrs, path: \(q("./rules/\(r.file)"))}")
        }

        y.line("proxy-groups:")
        if rt.hasSubscription {
            let exclude = nodeExcludeFilter(s)
            group(&y, name: GroupName.proxy, type: "select", proxies: [GroupName.auto], use: true, exclude: exclude)
            // fallback 只在当前节点失效时才换线，出口 IP 最稳定，AI 账号不容易触发风控
            group(&y, name: GroupName.auto, type: "fallback", proxies: [], use: true, exclude: exclude,
                  extra: ["url: \(q(testURL))", "interval: 60", "lazy: false", "expected-status: 204"])
            group(&y, name: GroupName.gateAI, type: "select", proxies: [GroupName.proxy, "REJECT"])
            // 主闸门不含 DIRECT：任何熔断都不会让境外流量（包括名单外的 AI）直连
            group(&y, name: GroupName.gateMain, type: "select", proxies: [GroupName.proxy, "REJECT"])
            group(&y, name: GroupName.gateCN, type: "select", proxies: ["DIRECT", GroupName.proxy, "REJECT"])
        } else {
            group(&y, name: GroupName.gateAI, type: "select", proxies: ["REJECT"])
            group(&y, name: GroupName.gateMain, type: "select", proxies: ["REJECT"])
            group(&y, name: GroupName.gateCN, type: "select", proxies: ["DIRECT", "REJECT"])
        }
        group(&y, name: GroupName.gateDirect, type: "select", proxies: ["DIRECT", "REJECT"])

        // 探测/订阅专用入站：绕过闸门直连指定策略组，带认证防止其他程序借道
        y.line("listeners:")
        func listener(_ name: String, _ port: Int, _ proxy: String) {
            y.line("  - name: \(q(name))")
            y.line("    type: http")
            y.line("    listen: \(q("127.0.0.1"))")
            y.line("    port: \(port)")
            y.line("    proxy: \(q(proxy))")
            y.line("    users: [{username: \(q(rt.listenerUser)), password: \(q(rt.listenerPassword))}]")
        }
        if rt.hasSubscription {
            listener("aiguard-probe", rt.probePort, GroupName.proxy)
        }
        listener("aiguard-direct", rt.directProbePort, "DIRECT")

        y.list("rules", rules(settings: s, mode: mode, captive: captive))
        return y.text
    }

    public static func rules(settings s: GuardSettings, mode: ProxyMode, captive: Bool = false) -> [String] {
        var r: [String] = []
        for cidr in privateCIDRs { r.append("IP-CIDR,\(cidr),DIRECT,no-resolve") }
        r.append("DOMAIN-SUFFIX,local,DIRECT")
        r.append("DOMAIN-SUFFIX,lan,DIRECT")

        let aiTarget = mode == .proxy ? GroupName.gateAI : "REJECT"
        if mode == .proxy {
            // 境外 QUIC 经代理不稳定，拒绝后浏览器会立即回落 TCP
            r.append("AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((RULE-SET,cn-site)))),REJECT")
        }
        for line in AIRuleCatalog.ruleLines(disabled: s.disabledAICategories, custom: s.customAIDomains) {
            r.append(line.hasPrefix("IP-CIDR") ? "\(line),\(aiTarget),no-resolve" : "\(line),\(aiTarget)")
        }
        for d in s.customDirectDomains { r.append("DOMAIN-SUFFIX,\(d),\(GroupName.gateDirect)") }

        switch mode {
        case .direct where s.directOnlyMainland && !captive:
            // 只放行大陆：名单之外的 AI 服务也到不了
            r.append("RULE-SET,cn-site,\(GroupName.gateDirect)")
            r.append("RULE-SET,cn-ip,\(GroupName.gateDirect)")
            r.append("MATCH,REJECT")
        case .direct:
            r.append("MATCH,\(GroupName.gateDirect)")
        case .proxy:
            // 智能/全局的区别由大陆闸门决定，切换分流方式不需要重载配置
            r.append("RULE-SET,cn-site,\(GroupName.gateCN)")
            r.append("RULE-SET,cn-ip,\(GroupName.gateCN)")
            r.append("MATCH,\(GroupName.gateMain)")
        }
        return r
    }

    private static func group(_ y: inout YAMLWriter, name: String, type: String, proxies: [String], use: Bool = false,
                              exclude: String? = nil, extra: [String] = []) {
        y.line("  - name: \(q(name))")
        y.line("    type: \(type)")
        if !proxies.isEmpty { y.line("    proxies: [\(proxies.map(q).joined(separator: ", "))]") }
        if use { y.line("    use: [\(q(GroupName.providerName))]") }
        if let exclude { y.line("    exclude-filter: \(q(exclude))") }
        for e in extra { y.line("    \(e)") }
    }
}

/// YAML 双引号标量与 JSON 字符串兼容，统一用它转义，避免节点名/正则破坏结构
public func q(_ s: String) -> String {
    var out = "\""
    for u in s.unicodeScalars {
        switch u {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if u.value < 0x20 { out += String(format: "\\u%04X", u.value) } else { out.unicodeScalars.append(u) }
        }
    }
    return out + "\""
}

struct YAMLWriter {
    private(set) var text = ""
    mutating func line(_ s: String) { text += s + "\n" }
    mutating func list(_ key: String, _ items: [String]) {
        let indent = String(key.prefix { $0 == " " })
        if items.isEmpty { line("\(key): []"); return }
        line("\(key):")
        for i in items { line("\(indent)  - \(q(i))") }
    }
}
