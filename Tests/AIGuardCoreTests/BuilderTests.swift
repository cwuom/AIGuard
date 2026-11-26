import Foundation
import Testing
@testable import AIGuardCore

private let runtime = CoreRuntime(secret: "s3cret", listenerPassword: "pw\"x", hasSubscription: true)

private func repoRoot() -> URL {
    URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
}

private func run(_ path: String, _ args: [String]) throws -> (Int32, String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = pipe
    try p.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: data, as: UTF8.self))
}

struct ConfigBuilderTests {
    @Test func aiRulesComeBeforeMainlandDirectRules() {
        let rules = MihomoConfigBuilder.rules(settings: GuardSettings(), mode: .proxy)
        let firstAI = rules.firstIndex { $0 == "DOMAIN-SUFFIX,claude.ai,\(GroupName.gateAI)" }
        let cn = rules.firstIndex { $0.hasPrefix("RULE-SET,cn-site") }
        #expect(firstAI != nil && cn != nil && firstAI! < cn!)
        #expect(rules.last == "MATCH,\(GroupName.gateMain)")
        #expect(rules.contains("IP-CIDR,160.79.104.0/21,\(GroupName.gateAI),no-resolve"))
        #expect(rules.contains("IP-CIDR6,2607:6bc0::/32,\(GroupName.gateAI),no-resolve"))
        // AI 规则绝不能指向 DIRECT
        #expect(!rules.contains { $0.contains("anthropic") && $0.hasSuffix(",DIRECT") })
    }

    @Test func directModeRejectsAIAndNeverProxies() {
        let rules = MihomoConfigBuilder.rules(settings: GuardSettings(), mode: .direct)
        #expect(rules.contains("DOMAIN-SUFFIX,openai.com,REJECT"))
        #expect(rules.contains("DOMAIN-KEYWORD,claude,REJECT"))
        #expect(rules.last == "MATCH,REJECT")
        #expect(!rules.contains { $0.contains(GroupName.gateMain) || $0.contains(GroupName.gateAI) })
    }

    @Test func mainlandRulesGoThroughCNGateInBothRoutings() {
        for routing in RoutingMode.allCases {
            var s = GuardSettings()
            s.routing = routing
            let rules = MihomoConfigBuilder.rules(settings: s, mode: .proxy)
            #expect(rules.contains("RULE-SET,cn-site,\(GroupName.gateCN)"))
            #expect(rules.contains("RULE-SET,cn-ip,\(GroupName.gateCN)"))
            #expect(!rules.contains { $0.hasSuffix(",DIRECT") && !$0.hasPrefix("IP-CIDR") && !$0.hasPrefix("DOMAIN-SUFFIX,l") })
        }
        // 主闸门永远不含 DIRECT
        let yaml = MihomoConfigBuilder.build(settings: GuardSettings(), runtime: runtime)
        #expect(yaml.contains("name: \"\(GroupName.gateMain)\"\n    type: select\n    proxies: [\"\(GroupName.proxy)\", \"REJECT\"]"))
    }

    @Test func strictDirectOnlyAllowsMainland() {
        let strict = MihomoConfigBuilder.rules(settings: GuardSettings(), mode: .direct)
        #expect(strict.suffix(3) == ["RULE-SET,cn-site,\(GroupName.gateDirect)", "RULE-SET,cn-ip,\(GroupName.gateDirect)", "MATCH,REJECT"])
        // Wi-Fi 登录模式不限大陆，但 AI 仍然拒绝
        let captive = MihomoConfigBuilder.rules(settings: GuardSettings(), mode: .direct, captive: true)
        #expect(captive.last == "MATCH,\(GroupName.gateDirect)")
        #expect(captive.contains("DOMAIN-SUFFIX,claude.ai,REJECT"))
        var loose = GuardSettings()
        loose.directOnlyMainland = false
        #expect(MihomoConfigBuilder.rules(settings: loose, mode: .direct).last == "MATCH,\(GroupName.gateDirect)")
    }

    @Test func disabledCategoryAndCustomDomains() {
        var s = GuardSettings()
        s.disabledAICategories = ["google-strict"]
        s.customAIDomains = ["https://Example-AI.dev/path", "bad domain", "*.foo.ai"]
        s.customDirectDomains = ["corp.internal.cn"]
        let rules = MihomoConfigBuilder.rules(settings: s.sanitized(), mode: .proxy)
        #expect(!rules.contains("DOMAIN-SUFFIX,google.com,\(GroupName.gateAI)"))
        #expect(rules.contains("DOMAIN-SUFFIX,gemini.google.com,\(GroupName.gateAI)"))
        #expect(rules.contains("DOMAIN-SUFFIX,example-ai.dev,\(GroupName.gateAI)"))
        #expect(rules.contains("DOMAIN-SUFFIX,foo.ai,\(GroupName.gateAI)"))
        #expect(!rules.contains { $0.contains("bad domain") })
        #expect(rules.contains("DOMAIN-SUFFIX,corp.internal.cn,\(GroupName.gateDirect)"))
    }

    @Test func noSubscriptionFallsBackToDirect() {
        let rt = CoreRuntime(secret: "s", listenerPassword: "p", hasSubscription: false)
        let yaml = MihomoConfigBuilder.build(settings: GuardSettings(), runtime: rt)
        #expect(!yaml.contains(GroupName.proxy))
        #expect(!yaml.contains("proxy-providers"))
        #expect(yaml.contains("MATCH,REJECT"))
    }

    @Test func quotingEscapesSpecialCharacters() {
        #expect(q("a\"b\\c\nd") == #""a\"b\\c\nd""#)
        let yaml = MihomoConfigBuilder.build(settings: GuardSettings(), runtime: runtime)
        #expect(yaml.contains(#"password: "pw\"x""#))
    }

    @Test func catalogHasNoDuplicateOrMalformedEntries() {
        for c in AIRuleCatalog.all {
            // .google 是 Google 自有顶级域，作为后缀是有意为之
            for d in c.suffixes + c.domains where d != "google" {
                #expect(DomainSanitizer.clean([d]) == [d.lowercased()], "非法域名: \(d) in \(c.id)")
            }
        }
        let lines = AIRuleCatalog.ruleLines(disabled: [], custom: [])
        #expect(Set(lines).count == lines.count)
        #expect(lines.count > 300)
        // 用户提供的清单必须全部覆盖
        for d in ["anthropic.com", "claude.ai", "claude.com", "clau.de", "claudemcpclient.com", "claudemcpcontent.com",
                  "claudeusercontent.com", "sentry.io", "statsigapi.net", "intercom.io", "intercomcdn.com"] {
            #expect(lines.contains("DOMAIN-SUFFIX,\(d)"), "缺少 \(d)")
        }
        for d in ["servd-anthropic-website.b-cdn.net", "anthropic.com.cdn.cloudflare.net", "anthropic.auth0.com",
                  "anthropic-com.ghost.io", "browser-intake-us5-datadoghq.com", "cdn.usefathom.com"] {
            #expect(lines.contains("DOMAIN,\(d)"), "缺少 \(d)")
        }
        #expect(lines.contains("DOMAIN-KEYWORD,datadog") && lines.contains("DOMAIN-KEYWORD,sift"))
        #expect(lines.contains("RULE-SET,ai-anthropic") && lines.contains("RULE-SET,ai-ntp"))
        #expect(lines.contains("AND,((NETWORK,UDP),(DST-PORT,123))"))
    }

    /// 关掉第三方类后，Claude 类里的遥测关键字和官方规则集仍然生效
    @Test func claudeStrictSurvivesThirdPartyToggle() {
        let lines = AIRuleCatalog.ruleLines(disabled: ["third-party"], custom: [])
        for k in ["sentry", "datadog", "sift"] { #expect(lines.contains("DOMAIN-KEYWORD,\(k)")) }
        #expect(lines.contains("RULE-SET,ai-anthropic"))
        let rules = MihomoConfigBuilder.rules(settings: GuardSettings(), mode: .proxy)
        #expect(rules.contains("AND,((NETWORK,UDP),(DST-PORT,123)),\(GroupName.gateAI)"))
        #expect(rules.contains("RULE-SET,ai-ntp,\(GroupName.gateAI)"))
        let yaml = MihomoConfigBuilder.build(settings: GuardSettings(), runtime: runtime)
        #expect(!yaml.contains("ntp.org\""), "NTP 不能出现在 fake-ip 过滤表里")
    }

    private func matcher(_ pattern: String) throws -> (String) -> Bool {
        let re = try NSRegularExpression(pattern: pattern.replacingOccurrences(of: "(?i)", with: ""), options: [.caseInsensitive])
        return { s in re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil }
    }

    /// 用 ICU 正则近似验证（mihomo 用 regexp2，语法兼容这里用到的环视）
    @Test func nodeFilterFollowsForbiddenRegions() throws {
        let excluded = try matcher(MihomoConfigBuilder.nodeExcludeFilter(GuardSettings()))
        for name in ["🇭🇰 香港 01", "HK01 IEPL", "Hong Kong 02", "广港专线", "澳门 01", "MO-01", "中国 回国",
                     "CN 直连", "剩余流量：100G", "套餐到期：2027-01-01", "HKG-BGP", "俄罗斯 01"] {
            #expect(excluded(name), "应排除: \(name)")
        }
        // 美国不在默认禁区
        for name in ["日本 东京 01", "🇸🇬 Singapore", "Mongolia", "台湾 01", "韩国 首尔", "Germany Frankfurt",
                     "Australia Sydney", "Cyprus 01", "🇺🇸 美国 CN2 GIA", "US-LAX-Hysteria", "USA 02"] {
            #expect(!excluded(name), "不应排除: \(name)")
        }
        // 用户把美国加入禁区后，美国节点按名字排除
        var s = GuardSettings()
        s.forbiddenRegions = ["CN", "HK", "MO", "US"]
        let strict = try matcher(MihomoConfigBuilder.nodeExcludeFilter(s))
        #expect(strict("🇺🇸 美国 CN2 GIA") && strict("US-LAX-Hysteria") && strict("洛杉矶 01"))
    }

    @Test func defaultForbiddenRegionsExcludeUS() {
        let s = GuardSettings().sanitized()
        #expect(s.forbiddenRegions == ["CN", "HK", "MO"])
    }

    /// 回归：熔断（闸门 REJECT）时内核自己的 DNS 不能经过规则，否则订阅下载和节点解析全部失败
    @Test func dnsNeverDependsOnGates() {
        let yaml = MihomoConfigBuilder.build(settings: GuardSettings(), runtime: runtime)
        #expect(!yaml.contains("respect-rules"))
        #expect(yaml.contains("https://1.1.1.1/dns-query#\(GroupName.proxy)"))
        #expect(yaml.contains("https://223.5.5.5/dns-query"))
        #expect(!yaml.contains("dns.alidns.com"), "DNS 服务器必须是 IP，不依赖系统解析")
        // 单线路：只有一个探测入站，没有 AI 线路
        #expect(!yaml.contains("AI 线路"))
        #expect(yaml.contains("name: \"aiguard-probe\""))
    }

    @Test func captiveUsesDHCPDNSOnlyForPhysicalInterface() {
        let ok = MihomoConfigBuilder.build(settings: GuardSettings(), runtime: runtime, captive: true, captiveInterface: "en0")
        #expect(ok.contains("dhcp://en0"))
        let bad = MihomoConfigBuilder.build(settings: GuardSettings(), runtime: runtime, captive: true, captiveInterface: "en0\"; x")
        #expect(!bad.contains("dhcp://"))
    }

    /// 生成的配置交给真实内核校验（需要先运行 scripts/fetch-core.sh）
    @Test func generatedConfigsPassMihomoValidation() throws {
        let root = repoRoot()
        let mihomo = root.appendingPathComponent("Vendor/mihomo").path
        guard FileManager.default.isExecutableFile(atPath: mihomo) else { return }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("aiguard-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("providers"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("rules"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        for f in BundledRuleSets.files {
            try FileManager.default.copyItem(at: root.appendingPathComponent("Vendor/rules/\(f)"),
                                             to: dir.appendingPathComponent("rules/\(f)"))
        }
        try "proxies:\n  - {name: \"US 01\", type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}\n"
            .write(to: dir.appendingPathComponent("providers/sub.yaml"), atomically: true, encoding: .utf8)

        for (mode, routing, sub) in [(ProxyMode.proxy, RoutingMode.smart, true), (.proxy, .global, true),
                                     (.direct, .smart, true), (.direct, .smart, false)] {
            var s = GuardSettings()
            s.mode = mode
            s.routing = routing
            var rt = runtime
            rt.hasSubscription = sub
            rt.tunEnabled = false
            let file = dir.appendingPathComponent("config-\(mode)-\(routing)-\(sub).yaml")
            try MihomoConfigBuilder.build(settings: s, runtime: rt).write(to: file, atomically: true, encoding: .utf8)
            let (code, out) = try run(mihomo, ["-t", "-d", dir.path, "-f", file.path])
            #expect(code == 0, "mihomo 拒绝了配置 \(mode)/\(routing)/\(sub): \(out.suffix(600))")
        }
    }
}

struct PFRulesTests {
    @Test func invalidTunNameFallsBackToLockdown() {
        #expect(PFRulesBuilder.rules(for: .leakGuard(tun: "en0; pass all")) == PFRulesBuilder.rules(for: .lockdown))
        #expect(PFRulesBuilder.isValidInterface("utun199"))
        #expect(!PFRulesBuilder.isValidInterface("utun"))
    }

    @Test func everyPolicyBlocksIPv6() {
        for policy in [PFPolicy.leakGuard(tun: "utun199"), .lockdown, .basic(tun: "utun199")] {
            let r = PFRulesBuilder.rules(for: policy)
            // DNS 防泄漏：非 root 的 53/853 只能经 TUN
            let dnsBlock = r.range(of: "block return out quick proto { tcp udp } from any to any port { 53 853 }")
            #expect(dnsBlock != nil)
            if let tunPass = r.range(of: "pass out quick on utun199"), let dnsBlock {
                #expect(tunPass.lowerBound < dnsBlock.lowerBound, "TUN 放行必须在 DNS 封锁之前")
            }
            if let lanPass = r.range(of: "pass out quick inet from any to"), let dnsBlock {
                #expect(dnsBlock.lowerBound < lanPass.lowerBound, "DNS 封锁必须在局域网放行之前，否则路由器 DNS 会泄漏")
            }
            #expect(r.contains("block drop out quick inet6 all") || r.contains("block return out quick inet6 all"))
        }
    }

    /// 大陆白名单熔断规则：用真实的大陆 IP 表让 pfctl 解析（不需要 root）
    @Test func whitelistRulesParseAndOrder() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let table = root.appendingPathComponent("Vendor/rules/cn4.txt").path
        guard FileManager.default.fileExists(atPath: table) else { return }
        for allowTUN in [false, true] {
            let rules = PFRulesBuilder.rules(for: .whitelist(tun: "utun199", allowTUN: allowTUN, cnTable: table,
                                                             allow: ["104.21.1.1", "bad; pass all", "300.1.1.1"]))
            #expect(rules.contains("pass out quick on utun199") == allowTUN, "闸门确认前不能放行 TUN")
            #expect(rules.contains("{ 104.21.1.1 }") && !rules.contains("bad") && !rules.contains("300.1.1.1"))
            #expect(rules.contains("to <aiguard_allow> user 0"), "节点例外只给 root 内核")
            #expect(rules.contains("to <aiguard_cn> port { 53 853 } user 0"), "白名单下内核 DNS 只能发往大陆 DNS")
            #expect(!rules.contains("from any to any port { 53 853 } user 0"), "白名单下不能放行内核发往任意地址的 DNS")
            #expect(rules.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("block return out quick all"))
            let dns = try #require(rules.range(of: "port { 53 853 }\nblock") ?? rules.range(of: "block return out quick proto { tcp udp } from any to any port { 53 853 }"))
            let cn = try #require(rules.range(of: "pass out quick inet from any to <aiguard_cn> no state"))
            #expect(dns.lowerBound < cn.lowerBound, "DNS 防泄漏必须在大陆放行之前，否则 114/223 这类国内明文 DNS 会漏")
            let file = FileManager.default.temporaryDirectory.appendingPathComponent("aiguard-wl-\(UUID().uuidString)")
            try rules.write(to: file, atomically: true, encoding: .utf8)
            defer { try? FileManager.default.removeItem(at: file) }
            let (code, out) = try run("/sbin/pfctl", ["-nf", file.path])
            #expect(code == 0, "pfctl 解析失败: \(out)")
        }
        // 路径或网卡名非法时退回全部断网
        let bad = PFRulesBuilder.rules(for: .whitelist(tun: "utun199", allowTUN: true, cnTable: "/tmp/x\" pass all", allow: []))
        #expect(bad == PFRulesBuilder.rules(for: .lockdown))
    }

    @Test func lockdownEndsWithBlockAll() {
        let r = PFRulesBuilder.rules(for: .lockdown)
        #expect(r.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("block drop out quick all"))
        #expect(!r.contains("keep state"))
    }

    /// pfctl -n 只做语法解析，不需要 root
    @Test func rulesParseWithPfctl() throws {
        for policy in [PFPolicy.leakGuard(tun: "utun199"), .lockdown, .basic(tun: "utun199"),
                       .whitelist(tun: "utun199", allowTUN: true, cnTable: "/dev/null", allow: ["1.2.3.4"])] {
            let file = FileManager.default.temporaryDirectory.appendingPathComponent("aiguard-pf-\(UUID().uuidString)")
            try PFRulesBuilder.rules(for: policy).write(to: file, atomically: true, encoding: .utf8)
            defer { try? FileManager.default.removeItem(at: file) }
            let (code, out) = try run("/sbin/pfctl", ["-nf", file.path])
            #expect(code == 0, "pfctl 解析失败: \(out)")
        }
    }
}
