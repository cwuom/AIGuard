import Foundation
import Testing
@testable import AIGuardCore

private func makeEngine(_ mutate: (inout GuardSettings) -> Void = { _ in }, mode: ProxyMode = .proxy,
                        now: Date) -> FuseEngine {
    var s = GuardSettings()
    s.recoverSuccesses = 2
    s.failureThreshold = 3
    s.wakeHoldSeconds = 8
    mutate(&s)
    return FuseEngine(config: FuseConfig(settings: s.sanitized(), effectiveMode: mode), now: now)
}

/// 把引擎推到正常放行状态
private func bringUp(_ e: inout FuseEngine, at t: Date) {
    e.handle(.health(coreUp: true, tunUp: true), now: t)
    e.handle(.geo(country: "SG"), now: t)
    e.handle(.probe(ms: 200), now: t)
    e.handle(.probe(ms: 210), now: t)
}

struct FuseEngineTests {
    let t0 = Date(timeIntervalSince1970: 1_000_000)

    @Test func startsTrippedAndRecoversOnlyAfterProbesAndGeo() {
        var e = makeEngine(now: t0)
        // 默认是大陆白名单（不是全部断网）
        #expect(e.snapshot.tripped && !e.snapshot.hard && e.snapshot.reason == .starting)

        e.handle(.health(coreUp: true, tunUp: true), now: t0)
        e.handle(.probe(ms: 200), now: t0)
        e.handle(.probe(ms: 200), now: t0)
        // 探测够了但出口还没验证，不能放行
        #expect(e.snapshot.tripped)
        e.handle(.geo(country: "SG"), now: t0)
        #expect(!e.snapshot.tripped)
    }

    @Test func consecutiveFailuresTripAndSuccessResetsCounter() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.probe(ms: nil), now: t0)
        e.handle(.probe(ms: nil), now: t0)
        e.handle(.probe(ms: 100), now: t0)
        e.handle(.probe(ms: nil), now: t0)
        #expect(!e.snapshot.tripped)
        e.handle(.probe(ms: nil), now: t0)
        e.handle(.probe(ms: 9_999), now: t0)
        #expect(e.snapshot.tripped)
        #expect(e.snapshot.reason == .proxyUnstable(failures: 3))
    }

    @Test func unsafeAIExitTripsAndNeedsFreshSafeGeo() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.geo(country: "HK"), now: t0)
        #expect(e.snapshot.reason == .unsafeExit(country: "HK"))
        e.handle(.probe(ms: 100), now: t0)
        e.handle(.probe(ms: 100), now: t0)
        e.handle(.probe(ms: 100), now: t0)
        #expect(e.snapshot.tripped)
        // 常规线路落在香港是允许的，只有 AI 线路不允许
        e.handle(.geo(country: "SG"), now: t0)
        #expect(!e.snapshot.tripped)
    }

    @Test func mainlandExitOnMainGroupTrips() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.geo(country: "CN"), now: t0)
        #expect(e.snapshot.reason == .unsafeExit(country: "CN"))
    }

    @Test func geoUnknownDoesNotVerify() {
        var e = makeEngine(now: t0)
        e.handle(.health(coreUp: true, tunUp: true), now: t0)
        e.handle(.geo(country: nil), now: t0)
        e.handle(.probe(ms: 100), now: t0)
        e.handle(.probe(ms: 100), now: t0)
        #expect(e.snapshot.tripped)
    }

    @Test func wakeHoldsAtLeastConfiguredSeconds() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.sleep, now: t0)
        #expect(e.snapshot.tripped && e.snapshot.reason == .sleeping)
        let t1 = t0.addingTimeInterval(3600)
        e.handle(.wake, now: t1)
        e.handle(.health(coreUp: true, tunUp: true), now: t1)
        e.handle(.geo(country: "SG"), now: t1)
        e.handle(.probe(ms: 100), now: t1)
        e.handle(.probe(ms: 100), now: t1)
        #expect(e.snapshot.tripped, "唤醒保持期内不能放行")
        e.handle(.probe(ms: 100), now: t1.addingTimeInterval(9))
        #expect(!e.snapshot.tripped)
    }

    @Test func missedWakeNotificationFallsBackToWaking() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.sleep, now: t0)
        e.handle(.health(coreUp: true, tunUp: true), now: t0.addingTimeInterval(5))
        #expect(e.snapshot.reason == .sleeping)
        e.handle(.health(coreUp: true, tunUp: true), now: t0.addingTimeInterval(600))
        #expect(e.snapshot.reason == .waking)
    }

    @Test func autoRecoverOffLatchesUntilUserRestores() {
        var e = makeEngine({ $0.autoRecover = false }, now: t0)
        bringUp(&e, at: t0)
        for _ in 0..<3 { e.handle(.probe(ms: nil), now: t0) }
        #expect(e.snapshot.tripped)
        // 内核掉线这种守护类原因覆盖后，锁也不能被绕过
        e.handle(.health(coreUp: false, tunUp: false), now: t0)
        e.handle(.health(coreUp: true, tunUp: true), now: t0)
        bringUp(&e, at: t0)
        bringUp(&e, at: t0)
        #expect(e.snapshot.tripped && e.isLatched)
        e.handle(.manualRestore(force: false), now: t0)
        bringUp(&e, at: t0)
        #expect(!e.snapshot.tripped)
    }

    @Test func manualTripStaysUntilRestore() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.manualTrip, now: t0)
        bringUp(&e, at: t0)
        #expect(e.snapshot.reason == .manual)
        e.handle(.manualRestore(force: true), now: t0)
        #expect(!e.snapshot.tripped)
    }

    /// 熔断方式只由设置决定：白名单模式下任何原因都只开白名单（pf 按 IP 把关，内核故障时同样安全）
    @Test func fuseActionDecidesHardness() {
        var w = makeEngine({ $0.fuseAction = .whitelist }, now: t0)
        bringUp(&w, at: t0)
        w.handle(.health(coreUp: true, tunUp: false), now: t0)
        #expect(w.snapshot.tripped && !w.snapshot.hard && w.snapshot.reason == .tunLost)
        var c = makeEngine({ $0.fuseAction = .cutAll }, now: t0)
        bringUp(&c, at: t0)
        for _ in 0..<3 { c.handle(.probe(ms: nil), now: t0) }
        #expect(c.snapshot.tripped && c.snapshot.hard)
        // 熔断中切换熔断方式立即生效
        c.update(config: FuseConfig(settings: { var s = GuardSettings(); s.fuseAction = .whitelist; return s }(),
                                    effectiveMode: .proxy), now: t0)
        #expect(c.snapshot.tripped && !c.snapshot.hard)
    }

    @Test func directModeRecoversWithoutProxyProbes() {
        var e = makeEngine(mode: .direct, now: t0)
        #expect(e.snapshot.tripped)
        e.handle(.health(coreUp: true, tunUp: true), now: t0)
        #expect(!e.snapshot.tripped)
        // 直连模式下出口是大陆是预期的，不熔断
        e.handle(.geo(country: "CN"), now: t0)
        #expect(!e.snapshot.tripped)
        e.handle(.health(coreUp: true, tunUp: false), now: t0)
        #expect(e.snapshot.tripped && e.snapshot.reason == .tunLost)
    }

    @Test func disabledFuseNeverTrips() {
        var e = makeEngine({ $0.fuseEnabled = false }, now: t0)
        #expect(!e.snapshot.tripped)
        e.handle(.health(coreUp: false, tunUp: false), now: t0)
        e.handle(.geo(country: "CN"), now: t0)
        #expect(!e.snapshot.tripped)
    }

    @Test func modeChangeRetriggersStartupGuard() {
        var e = makeEngine(mode: .direct, now: t0)
        e.handle(.health(coreUp: true, tunUp: true), now: t0)
        #expect(!e.snapshot.tripped)
        var s = GuardSettings()
        s.recoverSuccesses = 2
        e.update(config: FuseConfig(settings: s.sanitized(), effectiveMode: .proxy), now: t0)
        #expect(e.snapshot.tripped && e.snapshot.reason == .starting)
    }

    /// 回归：出口违规熔断期间合盖，睡眠期间绝不恢复，唤醒后有保持期且必须重新验证
    @Test func sleepDuringUnsafeExitNeverRecoversWhileAsleep() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.geo(country: "HK"), now: t0)
        #expect(e.snapshot.tripped)
        e.handle(.sleep, now: t0)
        // 睡眠前的几秒里即使探测和出口都恢复也不能放行
        e.handle(.geo(country: "SG"), now: t0.addingTimeInterval(1))
        for _ in 0..<5 { e.handle(.probe(ms: 100), now: t0.addingTimeInterval(2)) }
        #expect(e.snapshot.tripped)
        let t1 = t0.addingTimeInterval(600)
        e.handle(.wake, now: t1)
        e.handle(.health(coreUp: true, tunUp: true), now: t1)
        e.handle(.geo(country: "SG"), now: t1)
        for _ in 0..<3 { e.handle(.probe(ms: 100), now: t1) }
        #expect(e.snapshot.tripped)
        e.handle(.probe(ms: 100), now: t1.addingTimeInterval(9))
        #expect(!e.snapshot.tripped)
    }

    @Test func networkChangeDuringUnsafeExitStillResetsVerification() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.geo(country: "CN"), now: t0)
        e.handle(.geo(country: "SG"), now: t0)
        e.handle(.probe(ms: 100), now: t0)
        e.handle(.networkChanged, now: t0)
        e.handle(.probe(ms: 100), now: t0.addingTimeInterval(10))
        // 换网后旧的出口验证作废
        #expect(e.snapshot.tripped && !e.snapshot.geoVerified)
    }

    /// 回归：美国不在禁区（1.0 误加），美国出口不熔断
    @Test func usExitIsAllowed() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.geo(country: "US"), now: t0)
        #expect(!e.snapshot.tripped)
        e.handle(.geo(country: "HK"), now: t0)
        #expect(e.snapshot.reason == .unsafeExit(country: "HK"))
    }

    @Test func ipv6LeakTripsAndBlocksRecovery() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.ipv6(leaking: true), now: t0)
        #expect(e.snapshot.tripped && e.snapshot.reason == .ipv6Leak)
        bringUp(&e, at: t0)
        bringUp(&e, at: t0)
        #expect(e.snapshot.tripped, "IPv6 仍泄漏时不能恢复")
        e.handle(.ipv6(leaking: false), now: t0)
        bringUp(&e, at: t0)
        #expect(!e.snapshot.tripped)
    }

    /// 回归：重启内核不能解除手动熔断锁、不能丢掉睡眠保护
    @Test func coreRestartKeepsLatchAndSleep() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.manualTrip, now: t0)
        e.coreRestarted(now: t0)
        bringUp(&e, at: t0)
        bringUp(&e, at: t0)
        #expect(e.snapshot.tripped && e.isLatched, "手动熔断后重启内核仍需用户解锁")

        var f = makeEngine(now: t0)
        bringUp(&f, at: t0)
        f.handle(.sleep, now: t0)
        f.coreRestarted(now: t0.addingTimeInterval(1))
        bringUp(&f, at: t0.addingTimeInterval(2))
        bringUp(&f, at: t0.addingTimeInterval(3))
        #expect(f.snapshot.tripped, "睡眠期间重启内核也不能放行")
    }

    @Test func lowerPriorityReasonDoesNotOverride() {
        var e = makeEngine(now: t0)
        bringUp(&e, at: t0)
        e.handle(.geo(country: "CN"), now: t0)
        e.handle(.networkChanged, now: t0)
        #expect(e.snapshot.reason == .unsafeExit(country: "CN"))
    }
}
