import Foundation
import Testing
@testable import AIGuardCore

struct SubscriptionTests {
    @Test func clashYAMLKeepsOnlyProxies() throws {
        let yaml = """
        port: 7890
        proxies:
          - {name: "🇺🇸 US 01", type: ss, server: a.example.com, port: 443, cipher: aes-128-gcm, password: x}
          - name: "JP 02"
            type: trojan
            server: b.example.com
            port: 443
            password: y
        proxy-groups:
          - {name: G, type: select, proxies: ["JP 02"]}
        rules:
          - MATCH,DIRECT
        """
        let p = try SubscriptionParser.parse(Data(yaml.utf8))
        #expect(p.format == .clashYAML)
        #expect(p.nodeCount == 2)
        #expect(!p.providerContent.contains("rules:"))
        #expect(!p.providerContent.contains("proxy-groups"))
    }

    @Test func base64URIList() throws {
        let list = "ss://YWVzLTEyOC1nY206eA@1.2.3.4:8388#US\ntrojan://pw@host.example:443?sni=x#JP\n"
        let b64 = Data(list.utf8).base64EncodedString()
        let p = try SubscriptionParser.parse(Data(b64.utf8))
        #expect(p.format == .uriList && p.nodeCount == 2)
    }

    @Test func rejectsHTMLAndEmpty() {
        #expect(throws: SubscriptionError.unrecognized) {
            try SubscriptionParser.parse(Data("<html><body>login</body></html>".utf8))
        }
        #expect(throws: SubscriptionError.empty) { try SubscriptionParser.parse(Data("  \n".utf8)) }
    }

    /// 美国封禁的窄例外：必须能从各种订阅格式里取到节点服务器地址
    @Test func serverHostsFromAllFormats() {
        let yaml = """
        proxies:
          - {name: "JP 01", type: ss, server: jp1.example.com, port: 443, cipher: aes-128-gcm, password: x}
          - name: "SG 02"
            type: trojan
            server: 203.0.113.7
            port: 443
            password: y
        """
        #expect(SubscriptionParser.serverHosts(providerContent: yaml) == ["203.0.113.7", "jp1.example.com"])
        let vmessJSON = #"{"v":"2","ps":"US","add":"us.example.net","port":"443","id":"x"}"#
        let uris = """
        trojan://pw@tr.example.org:443?sni=x#JP
        vless://uuid@198.51.100.9:8443?type=ws#SG
        hysteria2://auth@hy.example.com:5000/?insecure=1#HY
        vmess://\(Data(vmessJSON.utf8).base64EncodedString())
        """
        #expect(SubscriptionParser.serverHosts(providerContent: uris)
                == ["198.51.100.9", "hy.example.com", "tr.example.org", "us.example.net"])
        // 恶意内容不能混进 pf 规则
        #expect(SubscriptionParser.serverHosts(providerContent: "  - {server: \"evil;pass all\", port: 1}").isEmpty)
    }

    /// 关 AI 进程只看 argv，不能读到环境变量：否则带 ANTHROPIC_API_KEY 的终端 shell 全会被误杀
    @Test func processArgumentsExcludeEnvironment() {
        func buf(argc: Int32, exec: String, args: [String], env: [String]) -> [UInt8] {
            var b = withUnsafeBytes(of: argc) { Array($0) }
            b += Array(exec.utf8) + [0, 0, 0]
            for a in args + env { b += Array(a.utf8) + [0] }
            return b
        }
        let shell = buf(argc: 1, exec: "/bin/zsh", args: ["-zsh"], env: ["ANTHROPIC_API_KEY=x", "PATH=/Users/me/.claude/bin"])
        #expect(ProcessMatch.parseArguments(shell) == "-zsh")
        #expect(!ProcessMatch.isAI(ProcessMatch.parseArguments(shell)))
        let cli = buf(argc: 3, exec: "/opt/homebrew/bin/node", args: ["node", "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js", "--resume"], env: ["HOME=/Users/me"])
        #expect(ProcessMatch.isAI(ProcessMatch.parseArguments(cli)))
        #expect(ProcessMatch.parseArguments([1, 0]) == "")
    }

    @Test func aiProcessKeywords() {
        for t in ["/Applications/Claude.app/Contents/MacOS/Claude", "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
                  "/Users/me/.vscode/extensions/github.copilot-chat-0.30/dist/copilot", "codex", "gemini",
                  "/Applications/Cherry Studio.app/Contents/MacOS/Cherry Studio", "/usr/local/bin/ollama",
                  "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js"] {
            #expect(ProcessMatch.isAI(t), "应识别为 AI: \(t)")
        }
        // 完整词匹配：decline 不是 cline，traefik 不是 trae
        for t in ["/Applications/WeChat.app/Contents/MacOS/WeChat", "/Applications/iTerm.app/Contents/MacOS/iTerm2", "-zsh",
                  "/usr/local/bin/traefik", "/Users/me/decline-tool/run", "/Applications/Kimiwork.app/x"] {
            #expect(!ProcessMatch.isAI(t), "不应识别为 AI: \(t)")
        }
        // 系统自带进程和 AIGuard 自己撞上关键词也不能杀
        #expect(ProcessMatch.isProtected(path: "/System/Library/CoreServices/CursorUIViewService.app/Contents/MacOS/CursorUIViewService"))
        #expect(!ProcessMatch.isProtected(path: "/usr/bin/python3"))
        #expect(ProcessMatch.isSelf(path: "/Users/me/claude-builds/AIGuard.app/Contents/MacOS/AIGuard"))
    }

    /// 解释器只看实际运行的脚本；普通程序的文件参数（vim ~/.claude/x）不算
    @Test func interpreterEntryPoint() {
        #expect(ProcessMatch.isInterpreter("node") && ProcessMatch.isInterpreter("python3.12") && !ProcessMatch.isInterpreter("vim"))
        #expect(ProcessMatch.entryPoint(of: ["node", "--no-warnings", "/opt/x/@anthropic-ai/claude-code/cli.js", "-p"])
                == "/opt/x/@anthropic-ai/claude-code/cli.js")
        #expect(ProcessMatch.entryPoint(of: ["python3", "-m", "aider", "--model", "x"]) == "aider")
        #expect(ProcessMatch.entryPoint(of: ["node"]) == nil)
        #expect(ProcessMatch.isAI(ProcessMatch.entryPoint(of: ["python3", "-m", "aider"])!))
        #expect(!ProcessMatch.isAI(ProcessMatch.entryPoint(of: ["python3", "/Users/me/scripts/backup.py", "--to", "~/.claude"])!))
    }

    @Test func usageHeader() {
        let u = SubscriptionUsage.parse(header: "upload=1024; download=2048; total=10737418240; expire=1798732800")
        #expect(u?.upload == 1024 && u?.download == 2048 && u?.total == 10_737_418_240)
        #expect(u?.expire == Date(timeIntervalSince1970: 1_798_732_800))
        #expect(SubscriptionUsage.parse(header: "garbage") == nil)
        // 回归：异常数值不能让守护进程崩溃
        let weird = SubscriptionUsage.parse(header: "upload=1e400; download=nan; total=9.9e30; expire=-5")
        #expect(weird == nil)
        let mixed = SubscriptionUsage.parse(header: "upload=inf; download=1.5e3; total=2048")
        #expect(mixed?.download == 1500 && mixed?.upload == 0 && mixed?.total == 2048)
    }

    @Test func profileNameFromHeaders() {
        let b64 = Data("出差机场".utf8).base64EncodedString()
        #expect(SubscriptionParser.profileName(headers: ["Profile-Title": "base64:\(b64)"]) == "出差机场")
        #expect(SubscriptionParser.profileName(headers: ["Content-Disposition": "attachment; filename*=UTF-8''%E6%9C%BA%E5%9C%BA"]) == "机场")
    }

    @Test func urlValidationAndMasking() {
        #expect(SubscriptionParser.validateURL("ftp://x.com/a") == nil)
        #expect(SubscriptionParser.validateURL(" https://sub.example.com/abc123 ") != nil)
        let info = SubscriptionInfo(url: "https://sub.example.com/abcdef123456")
        #expect(info.maskedURL == "https://sub.example.com/••••3456")
    }
}

struct TraceAndSettingsTests {
    @Test func cloudflareTrace() {
        let t = ExitTrace.parseCloudflare("fl=1\nh=www.cloudflare.com\nip=203.0.113.9\nts=1\nloc=jp\ncolo=NRT\n")
        #expect(t == ExitTrace(ip: "203.0.113.9", country: "JP"))
        #expect(ExitTrace.parseCloudflare("ip=1.1.1.1\n") == nil)
        #expect(ExitTrace.parseJSON(Data(#"{"countryCode":"us","query":"1.2.3.4"}"#.utf8)) == ExitTrace(ip: "1.2.3.4", country: "US"))
        #expect(ExitTrace.parseJSON(Data(#"{"ip":"5.6.7.8","country":"SG"}"#.utf8)) == ExitTrace(ip: "5.6.7.8", country: "SG"))
        #expect(ExitTrace.parseJSON(Data(#"{"ip":"5.6.7.8","country":"S1"}"#.utf8)) == nil)
    }

    @Test func oldSettingsFileDecodesWithDefaults() throws {
        let s = try JSONDecoder().decode(GuardSettings.self, from: Data(#"{"mode":"direct","probeIntervalSeconds":1}"#.utf8))
        #expect(s.mode == .direct && s.fuseEnabled && s.routing == .smart)
        #expect(s.customProxyDomains.isEmpty)
        #expect(s.sanitized().probeIntervalSeconds == 2)
    }

    @Test func mainlandAlwaysForbidden() {
        var s = GuardSettings()
        s.forbiddenRegions = ["hk", "x1", "HK"]
        #expect(s.sanitized().forbiddenRegions == ["CN", "HK"])
    }

    /// 1.0 的设置文件：两个禁区列表 + 美国 + 5 秒探测，迁移后去掉美国、改用 2 秒心跳
    @Test func migratesV1Settings() throws {
        let v1 = #"{"forbiddenAIRegions":["CN","HK","MO","US"],"forbiddenMainRegions":["CN","US"],"probeIntervalSeconds":5,"failureThreshold":3,"autoSwitchUnsafeAINode":false}"#
        let s = try JSONDecoder().decode(GuardSettings.self, from: Data(v1.utf8))
        #expect(s.forbiddenRegions == ["CN", "HK", "MO"])
        #expect(s.probeIntervalSeconds == 2 && s.failureThreshold == 2)
        #expect(s.autoSwitchUnsafeNode == false)
        #expect(s.fuseAction == .whitelist, "1.2 起熔断默认改为大陆白名单")
        #expect(s.schema == GuardSettings.currentSchema)
        // 新格式写回后再读，不再迁移（用户后来自己加的美国保留）
        var v2 = s
        v2.forbiddenRegions.append("US")
        v2.probeIntervalSeconds = 5
        let again = try JSONDecoder().decode(GuardSettings.self, from: JSONEncoder().encode(v2))
        #expect(again.forbiddenRegions.contains("US") && again.probeIntervalSeconds == 5)
    }

    @Test func ipcRoundTrip() throws {
        let req = IPCRequest.importSubscription(url: "https://a.b/c")
        let data = try IPCCodec.encoder().encode(req)
        guard case .importSubscription(let url) = try IPCCodec.decoder().decode(IPCRequest.self, from: data) else {
            Issue.record("解码失败")
            return
        }
        #expect(url == "https://a.b/c")
        #expect(RegionNames.flag("us") == "🇺🇸")
        guard case .clearEvents = try IPCCodec.decoder().decode(IPCRequest.self, from: IPCCodec.encoder().encode(IPCRequest.clearEvents))
        else {
            Issue.record("clearEvents 解码失败")
            return
        }
        // 旧守护进程的响应没有事件代号，新界面必须照常解码
        let old = try IPCCodec.decoder().decode(IPCResponse.self, from: Data(#"{"ok":true,"events":[]}"#.utf8))
        #expect(old.eventsGeneration == nil && old.events == [])
    }

    @Test func launchAtLoginDefaultsOnOnceAndOnlyWhenInstalled() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        #expect(LaunchAtLoginPolicy.shouldApplyDefault(alreadyApplied: false, bundlePath: "/Applications/AIGuard.app"))
        #expect(LaunchAtLoginPolicy.shouldApplyDefault(alreadyApplied: false, bundlePath: home + "/Applications/AIGuard.app"))
        // 用户关过（或已经默认开过一次）就不再强开
        #expect(!LaunchAtLoginPolicy.shouldApplyDefault(alreadyApplied: true, bundlePath: "/Applications/AIGuard.app"))
        // 从 DMG、构建目录运行时登记的路径会失效
        #expect(!LaunchAtLoginPolicy.shouldApplyDefault(alreadyApplied: false, bundlePath: "/Volumes/AI 出差管家/AIGuard.app"))
        #expect(!LaunchAtLoginPolicy.shouldApplyDefault(alreadyApplied: false, bundlePath: "/Users/x/Desktop/AIGuard/build/AIGuard.app"))
        #expect(!LaunchAtLoginPolicy.isInstalledLocation("/Applications/../Volumes/x/AIGuard.app"))
        #expect(!LaunchAtLoginPolicy.isInstalledLocation("/Applications/AIGuard"))
    }

    @Test func versionOrdering() {
        #expect(compareVersions("1.2.1", "1.2.0") == .orderedDescending)
        #expect(compareVersions("1.10.0", "1.9.9") == .orderedDescending)
        #expect(compareVersions("1.2", "1.2.0") == .orderedSame)
        #expect(compareVersions("1.2.0", "1.2.1") == .orderedAscending)
    }

    @Test func usageSumNeverOverflows() {
        let u = SubscriptionUsage(upload: .max - 1, download: 10, total: 100, expire: nil)
        #expect(u.used == .max)
        #expect(SubscriptionUsage(upload: 3, download: 4, total: 10, expire: nil).used == 7)
    }

    /// 回归：订阅节点在 proxy-provider 里，/proxies 不返回，测速结果必须从 /providers/proxies 合并
    @Test func providerNodesMergedIntoProxies() {
        let top = #"{"proxies":{"自动选择":{"type":"Fallback","now":"JP 01","all":["JP 01","US 01"],"history":[{"delay":51}]},"DIRECT":{"type":"Direct","history":[]}}}"#
        let providers = #"{"providers":{"sub":{"proxies":[{"name":"JP 01","type":"Shadowsocks","history":[{"delay":0},{"delay":88}]},{"name":"US 01","type":"Shadowsocks","history":[{"delay":0}]},{"name":"HK 01","type":"Shadowsocks","history":[]}]},"default":{"proxies":[{"name":"DIRECT","type":"Direct","history":[{"delay":9}]}]}}}"#
        let map = MihomoAPI.parseProxies(Data(top.utf8), providers: Data(providers.utf8))
        #expect(map["JP 01"]?.lastDelay == 88 && map["JP 01"]?.tested == true)
        // 测过但失败：显示超时而不是未测速
        #expect(map["US 01"]?.lastDelay == nil && map["US 01"]?.tested == true)
        #expect(map["HK 01"]?.tested == false)
        #expect(map["自动选择"]?.lastDelay == 51 && map["自动选择"]?.all == ["JP 01", "US 01"])
        // 顶层同名项以 /proxies 为准
        #expect(map["DIRECT"]?.tested == false)
        // 没有 providers 数据时只用 /proxies；有但结构不对时整体作废，不发布半份快照
        #expect(MihomoAPI.parseProxies(Data(top.utf8), providers: nil).count == 2)
        #expect(MihomoAPI.parseProxies(Data(top.utf8), providers: Data(#"{"error":"x"}"#.utf8)).isEmpty)
        #expect(MihomoAPI.parseProxies(Data(top.utf8), providers: Data("not json".utf8)).isEmpty)
    }

    @Test func connectionRouteKind() {
        func conn(_ leaf: String) -> MihomoAPI.Connection {
            MihomoAPI.Connection(id: "1", host: "", destination: "1.1.1.1:443", network: "TCP", chain: leaf, rule: "",
                                 upload: 0, download: 0, start: nil, leaf: leaf)
        }
        #expect(conn("DIRECT").route == .direct)
        #expect(conn("REJECT").route == .reject)
        #expect(conn("REJECT-DROP").route == .reject)
        #expect(conn("🇸🇬新加坡 03").route == .proxy)
        // 节点名以内置出站名开头也按代理算
        #expect(conn("DIRECT-HK 备用").route == .proxy)
        #expect(conn("REJECT 线路").route == .proxy)
        #expect(conn("").route == .proxy)
    }
}
