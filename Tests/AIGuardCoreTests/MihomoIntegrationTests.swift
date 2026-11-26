import Foundation
import Testing
@testable import AIGuardCore

/// 用真实 mihomo（非 root、不开 TUN）验证：节点过滤、闸门、带认证的探测入站、延迟 API。
/// 需要联网，设置 AIGUARD_INTEGRATION=1 才运行
@Suite(.enabled(if: ProcessInfo.processInfo.environment["AIGUARD_INTEGRATION"] == "1"), .serialized)
struct MihomoIntegrationTests {
    @Test(.timeLimit(.minutes(2))) func gatesListenersAndFilters() async throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let mihomo = root.appendingPathComponent("Vendor/mihomo").path
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("aiguard-it-\(UUID().uuidString)")
        let fm = FileManager.default
        try fm.createDirectory(at: dir.appendingPathComponent("providers"), withIntermediateDirectories: true)
        try fm.createDirectory(at: dir.appendingPathComponent("rules"), withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }
        for f in BundledRuleSets.files {
            try fm.copyItem(at: root.appendingPathComponent("Vendor/rules/\(f)"), to: dir.appendingPathComponent("rules/\(f)"))
        }

        let base = Int.random(in: 30000...40000)
        var rt = CoreRuntime(controllerPort: base, secret: "it-secret", listenerPassword: "it-pass",
                             probePort: base + 1, directProbePort: base + 3,
                             tunEnabled: false, hasSubscription: true)
        rt.listenerUser = "aiguard"
        // 节点指回本机的 DIRECT 入站，这样不需要真实机场也能走通「入站 → 策略组 → 节点 → 出网」
        let node = "type: http, server: 127.0.0.1, port: \(base + 3), username: aiguard, password: it-pass"
        try """
        proxies:
          - {name: "🇯🇵 JP 01", \(node)}
          - {name: "🇺🇸 US 01", \(node)}
          - {name: "🇭🇰 香港 01", \(node)}
          - {name: "剩余流量：100G", \(node)}
        """.write(to: dir.appendingPathComponent("providers/sub.yaml"), atomically: true, encoding: .utf8)
        var s = GuardSettings()
        s.mixedPort = base + 4
        let cfg = dir.appendingPathComponent("config.yaml")
        try MihomoConfigBuilder.build(settings: s, runtime: rt).write(to: cfg, atomically: true, encoding: .utf8)

        let p = Process()
        p.executableURL = URL(fileURLWithPath: mihomo)
        p.arguments = ["-d", dir.path, "-f", cfg.path]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        defer { p.terminate() }

        let api = MihomoAPI(port: base, secret: "it-secret")
        var up = false
        for _ in 0..<50 where !up {
            up = await api.version() != nil
            if !up { try await Task.sleep(for: .milliseconds(100)) }
        }
        #expect(up, "内核未启动")

        // 单线路：排除港澳与信息节点，美国保留（不在默认禁区）
        let main = try #require(await api.group(GroupName.proxy))
        #expect(main.all.contains("🇯🇵 JP 01"))
        #expect(main.all.contains("🇺🇸 US 01"))
        #expect(!main.all.contains("🇭🇰 香港 01"))
        #expect(!main.all.contains { $0.contains("剩余") })

        // 延迟探测经策略组直出，不受闸门影响
        #expect(await api.select(group: GroupName.gateMain, proxy: "REJECT"))
        let d = await api.delay(GroupName.proxy, url: "http://cp.cloudflare.com/generate_204", timeoutMs: 5000)
        #expect(d != nil, "延迟探测失败")

        // 全量测速：订阅节点在 provider 里，测完必须能从 proxies() 读到它们各自的结果
        let tested = try #require(await api.groupDelay(GroupName.proxy, url: "http://cp.cloudflare.com/generate_204", timeoutMs: 5000))
        #expect(tested["🇯🇵 JP 01"] != nil && tested["🇺🇸 US 01"] != nil)
        #expect(await api.groupDelay("不存在的组", url: "http://cp.cloudflare.com/generate_204", timeoutMs: 1000) == nil)
        let all = await api.proxies()
        #expect(all["🇯🇵 JP 01"]?.tested == true && all["🇯🇵 JP 01"]?.lastDelay != nil, "provider 节点的测速结果没有合并进来")
        #expect(all["🇺🇸 US 01"]?.lastDelay != nil)

        // 闸门 REJECT 时普通入站访问失败；放行后恢复
        let plain = ProxiedFetcher(user: "", password: "")
        let probe = URL(string: "http://cp.cloudflare.com/generate_204")!
        let rejected = try? await plain.fetch(probe, viaPort: base + 4, timeout: 5)
        #expect(rejected == nil || rejected?.1.statusCode != 204)
        #expect(await api.select(group: GroupName.gateMain, proxy: GroupName.proxy))
        await api.flushConnections()
        let passed = try await plain.fetch(probe, viaPort: base + 4, timeout: 8)
        #expect(passed.1.statusCode == 204)

        // 回归：browserleaks.com 被 geosite:cn 误收，必须仍经主闸门走代理，不能命中大陆名单直连
        let leakTask = Task { _ = try? await plain.fetch(URL(string: "https://browserleaks.com/ip")!, viaPort: base + 4, timeout: 8) }
        var leakConn: MihomoAPI.Connection?
        for _ in 0..<60 where leakConn == nil {
            leakConn = await api.connections()?.connections.first { $0.host == "browserleaks.com" }
            if leakConn == nil { try await Task.sleep(for: .milliseconds(50)) }
        }
        leakTask.cancel()
        let lc = try #require(leakConn, "没有捕获到 browserleaks.com 的连接")
        #expect(lc.route == .proxy && !lc.rule.contains("cn-site"), "browserleaks.com 走了 \(lc.chain)（\(lc.rule)）")

        // 探测入站必须认证：错误密码拿不到结果，正确密码能查到出口
        let wrong = ProxiedFetcher(user: "aiguard", password: "nope")
        let denied = try? await wrong.fetch(probe, viaPort: base + 1, timeout: 5)
        #expect(denied?.1.statusCode != 204)
        let good = ProxiedFetcher(user: "aiguard", password: "it-pass")
        let trace = await good.heartbeat(viaPort: base + 1, timeout: 8)
        #expect(trace != nil, "经探测入站的长连接心跳失败")
        // 订阅下载走带上限的流式读取，经认证入站同样可用；超过上限必须报错而不是整包读进内存
        let limited = try await good.fetchLimited(URL(string: "https://www.cloudflare.com/cdn-cgi/trace")!, viaPort: base + 1,
                                                  timeout: 8, maxBytes: 1 << 20)
        #expect(limited.1.statusCode == 200 && !limited.0.isEmpty)
        await #expect(throws: URLError.self) {
            _ = try await good.fetchLimited(URL(string: "https://www.cloudflare.com/cdn-cgi/trace")!, viaPort: base + 1,
                                            timeout: 8, maxBytes: 16)
        }
        #expect(trace?.country.count == 2)
    }
}
