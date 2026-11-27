package com.aiguard.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FuseEngineTest {
    private val t0 = 1_000_000L

    private fun engine(mode: ProxyMode = ProxyMode.PROXY, mutate: (GuardSettings) -> GuardSettings = { it }): FuseEngine {
        val s = mutate(GuardSettings(recoverSuccesses = 2, failureThreshold = 3, networkHoldSeconds = 8))
        return FuseEngine(FuseConfig.from(s, mode), t0)
    }

    /** 把引擎推到正常放行状态 */
    private fun FuseEngine.bringUp(t: Long) {
        handle(FuseSignal.Health(coreUp = true, tunUp = true), t)
        handle(FuseSignal.Geo("SG"), t)
        handle(FuseSignal.Probe(200), t)
        handle(FuseSignal.Probe(210), t)
    }

    @Test
    fun startsTrippedAndRecoversOnlyAfterProbesAndGeo() {
        val e = engine()
        // 默认是大陆白名单（不是全部断网）
        assertTrue(e.snapshot.tripped && !e.snapshot.hard)
        assertEquals(FuseReason.Starting, e.snapshot.reason)
        e.handle(FuseSignal.Health(true, true), t0)
        e.handle(FuseSignal.Probe(100), t0)
        e.handle(FuseSignal.Probe(100), t0)
        assertTrue("没有出口验证不能放行", e.snapshot.tripped)
        e.handle(FuseSignal.Geo("JP"), t0)
        assertFalse(e.snapshot.tripped)
    }

    @Test
    fun consecutiveFailuresTripAndSuccessResetsCounter() {
        val e = engine()
        e.bringUp(t0)
        e.handle(FuseSignal.Probe(null), t0)
        e.handle(FuseSignal.Probe(null), t0)
        e.handle(FuseSignal.Probe(100), t0)
        assertFalse(e.snapshot.tripped)
        repeat(3) { e.handle(FuseSignal.Probe(null), t0) }
        assertEquals(FuseReason.ProxyUnstable(3), e.snapshot.reason)
        // 超过延迟阈值也算失败
        val slow = engine()
        slow.bringUp(t0)
        repeat(3) { slow.handle(FuseSignal.Probe(5000), t0) }
        assertTrue(slow.snapshot.tripped)
    }

    @Test
    fun unsafeExitTripsAndNeedsFreshSafeGeo() {
        val e = engine()
        e.bringUp(t0)
        e.handle(FuseSignal.Geo("HK"), t0)
        assertEquals(FuseReason.UnsafeExit("HK"), e.snapshot.reason)
        e.handle(FuseSignal.Probe(100), t0)
        e.handle(FuseSignal.Probe(100), t0)
        assertTrue("没有新的安全出口不能放行", e.snapshot.tripped)
        e.handle(FuseSignal.Geo("SG"), t0)
        assertFalse(e.snapshot.tripped)
    }

    @Test
    fun mainlandIsAlwaysForbiddenAndUSIsAllowed() {
        val e = engine { it.copy(forbiddenRegions = listOf("HK")) }
        e.bringUp(t0)
        e.handle(FuseSignal.Geo("CN"), t0)
        assertTrue(e.snapshot.tripped)
        val us = engine()
        us.bringUp(t0)
        us.handle(FuseSignal.Geo("US"), t0)
        assertFalse(us.snapshot.tripped)
    }

    @Test
    fun geoUnknownDoesNotVerify() {
        val e = engine()
        e.handle(FuseSignal.Health(true, true), t0)
        e.handle(FuseSignal.Probe(100), t0)
        e.handle(FuseSignal.Probe(100), t0)
        e.handle(FuseSignal.Geo(null), t0)
        assertTrue(e.snapshot.tripped)
        assertFalse(e.snapshot.geoVerified)
    }

    @Test
    fun networkChangeHoldsAtLeastConfiguredSeconds() {
        val e = engine()
        e.bringUp(t0)
        e.handle(FuseSignal.NetworkChanged, t0)
        assertEquals(FuseReason.NetworkChanged, e.snapshot.reason)
        e.bringUp(t0 + 7_000)
        assertTrue("保持期内不能恢复", e.snapshot.tripped)
        e.bringUp(t0 + 8_001)
        assertFalse(e.snapshot.tripped)
    }

    @Test
    fun networkChangeDuringUnsafeExitKeepsReasonButResetsVerification() {
        val e = engine()
        e.bringUp(t0)
        e.handle(FuseSignal.Geo("HK"), t0)
        e.handle(FuseSignal.Geo("SG"), t0 + 1)
        e.handle(FuseSignal.Probe(100), t0 + 1)
        e.handle(FuseSignal.NetworkChanged, t0 + 2)
        assertFalse(e.snapshot.geoVerified)
        assertEquals(0, e.snapshot.recoverProgress)
    }

    @Test
    fun autoRecoverOffLatchesUntilUserRestores() {
        val e = engine { it.copy(autoRecover = false) }
        e.bringUp(t0)
        repeat(3) { e.handle(FuseSignal.Probe(null), t0) }
        e.handle(FuseSignal.ManualRestore(force = false), t0 + 1)
        assertTrue("解锁后仍需验证", e.snapshot.tripped)
        assertFalse(e.isLatched)

        val latched = engine { it.copy(autoRecover = false) }
        latched.bringUp(t0)
        repeat(3) { latched.handle(FuseSignal.Probe(null), t0) }
        latched.bringUp(t0 + 1)
        assertTrue("上锁期间验证通过也不放行", latched.snapshot.tripped && latched.isLatched)
        latched.handle(FuseSignal.ManualRestore(force = false), t0 + 2)
        assertFalse("已验证过的线路在解锁后放行", latched.snapshot.tripped)
        e.bringUp(t0 + 3)
        assertFalse(e.snapshot.tripped)
    }

    @Test
    fun guardReasonsRecoverEvenWithAutoRecoverOff() {
        val e = engine { it.copy(autoRecover = false) }
        e.bringUp(t0)
        assertFalse("启动保护属于守护类原因，总是自动解除", e.snapshot.tripped)
    }

    @Test
    fun manualTripStaysUntilRestore() {
        val e = engine()
        e.bringUp(t0)
        e.handle(FuseSignal.ManualTrip, t0)
        e.bringUp(t0 + 1)
        assertEquals(FuseReason.Manual, e.snapshot.reason)
        e.handle(FuseSignal.ManualRestore(force = true), t0 + 2)
        assertFalse(e.snapshot.tripped)
    }

    @Test
    fun fuseActionDecidesHardness() {
        val e = engine { it.copy(fuseAction = FuseAction.CUT_ALL) }
        assertTrue(e.snapshot.hard)
        // 切回白名单时已熔断的状态立即降为白名单
        e.update(FuseConfig.from(GuardSettings(fuseAction = FuseAction.WHITELIST), ProxyMode.PROXY), t0)
        assertFalse(e.snapshot.hard)
    }

    @Test
    fun directModeRecoversWithoutProxyProbes() {
        val e = engine(ProxyMode.DIRECT)
        e.handle(FuseSignal.Health(true, true), t0)
        assertFalse(e.snapshot.tripped)
        assertEquals(0, e.snapshot.recoverNeeded)
    }

    @Test
    fun disabledFuseNeverTrips() {
        val e = engine { it.copy(fuseEnabled = false) }
        assertFalse(e.snapshot.tripped)
        e.handle(FuseSignal.Geo("CN"), t0)
        e.handle(FuseSignal.Health(false, false), t0)
        assertFalse(e.snapshot.tripped)
    }

    @Test
    fun modeChangeRetriggersStartupGuard() {
        val e = engine()
        e.bringUp(t0)
        e.update(FuseConfig.from(GuardSettings(recoverSuccesses = 2), ProxyMode.DIRECT), t0)
        assertEquals(FuseReason.Starting, e.snapshot.reason)
    }

    @Test
    fun ipv6LeakTripsAndBlocksRecovery() {
        val e = engine()
        e.bringUp(t0)
        e.handle(FuseSignal.Ipv6(leaking = true), t0)
        e.bringUp(t0 + 1)
        assertEquals(FuseReason.Ipv6Leak, e.snapshot.reason)
        e.handle(FuseSignal.Ipv6(leaking = false), t0 + 2)
        e.bringUp(t0 + 3)
        assertFalse(e.snapshot.tripped)
    }

    @Test
    fun coreAndTunHealthGateRecovery() {
        val e = engine()
        e.bringUp(t0)
        e.handle(FuseSignal.Health(coreUp = true, tunUp = false), t0)
        assertEquals(FuseReason.TunLost, e.snapshot.reason)
        e.handle(FuseSignal.Health(coreUp = false, tunUp = false), t0)
        assertEquals(FuseReason.CoreDown, e.snapshot.reason)
    }

    @Test
    fun coreRestartKeepsLatch() {
        val e = engine()
        e.bringUp(t0)
        e.handle(FuseSignal.ManualTrip, t0)
        e.coreRestarted(t0 + 1)
        e.bringUp(t0 + 2)
        assertTrue(e.snapshot.tripped && e.isLatched)
    }

    @Test
    fun lowerPriorityReasonDoesNotOverride() {
        val e = engine()
        e.bringUp(t0)
        e.handle(FuseSignal.Geo("HK"), t0)
        e.handle(FuseSignal.NetworkChanged, t0 + 1)
        assertEquals(FuseReason.UnsafeExit("HK"), e.snapshot.reason)
        // 但保持期照样生效
        assertEquals(t0 + 1 + 8_000, e.snapshot.holdUntil)
    }
}
