package core

import (
	"reflect"
	"testing"
)

const t0 int64 = 1_000_000

func ptr[T any](value T) *T { return &value }

func want[T any](t *testing.T, got, expected T) {
	t.Helper()
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("got %#v, want %#v", got, expected)
	}
}

func check(t *testing.T, ok bool, message string) {
	t.Helper()
	if !ok {
		t.Fatal(message)
	}
}

func testEngine(mode ProxyMode, changes ...func(*GuardSettings)) *FuseEngine {
	s := DefaultSettings()
	s.RecoverSuccesses, s.FailureThreshold, s.WakeHoldSeconds = 2, 3, 8
	for _, change := range changes {
		change(&s)
	}
	return NewFuseEngine(NewFuseConfig(s, mode), t0)
}

func bringUp(e *FuseEngine, at int64) {
	e.Handle(Health{true, true}, at)
	e.Handle(Geo{ptr("SG")}, at)
	e.Handle(Probe{ptr(200)}, at)
	e.Handle(Probe{ptr(210)}, at)
}

func TestStartsTrippedAndRecoversOnlyAfterProbesAndGeo(t *testing.T) {
	e := testEngine(ModeProxy)
	s := e.Snapshot()
	check(t, s.Tripped && !s.Hard, "startup should allow only the mainland whitelist")
	want(t, s.Reason, ptr(FuseReason{Type: ReasonStarting}))
	e.Handle(Health{true, true}, t0)
	e.Handle(Probe{ptr(100)}, t0)
	e.Handle(Probe{ptr(100)}, t0)
	check(t, e.Snapshot().Tripped, "recovery requires exit verification")
	e.Handle(Geo{ptr("JP")}, t0)
	want(t, e.Snapshot().Tripped, false)
}

func TestConsecutiveFailuresTripAndSuccessResetsCounter(t *testing.T) {
	e := testEngine(ModeProxy)
	bringUp(e, t0)
	e.Handle(Probe{}, t0)
	e.Handle(Probe{}, t0)
	e.Handle(Probe{ptr(100)}, t0)
	want(t, e.Snapshot().Tripped, false)
	for range 3 {
		e.Handle(Probe{}, t0)
	}
	want(t, e.Snapshot().Reason, ptr(FuseReason{Type: ReasonProxyUnstable, Failures: 3}))

	slow := testEngine(ModeProxy)
	bringUp(slow, t0)
	for range 3 {
		slow.Handle(Probe{ptr(5000)}, t0)
	}
	want(t, slow.Snapshot().Tripped, true)
}

func TestUnsafeExitTripsAndNeedsFreshSafeGeo(t *testing.T) {
	e := testEngine(ModeProxy)
	bringUp(e, t0)
	e.Handle(Geo{ptr("HK")}, t0)
	want(t, e.Snapshot().Reason, ptr(FuseReason{Type: ReasonUnsafeExit, Country: "HK"}))
	e.Handle(Probe{ptr(100)}, t0)
	e.Handle(Probe{ptr(100)}, t0)
	check(t, e.Snapshot().Tripped, "recovery requires a fresh safe exit")
	e.Handle(Geo{ptr("SG")}, t0)
	want(t, e.Snapshot().Tripped, false)
}

func TestMainlandIsAlwaysForbiddenAndUSIsAllowed(t *testing.T) {
	e := testEngine(ModeProxy, func(s *GuardSettings) { s.ForbiddenRegions = []string{"HK"} })
	bringUp(e, t0)
	e.Handle(Geo{ptr("CN")}, t0)
	want(t, e.Snapshot().Tripped, true)

	us := testEngine(ModeProxy)
	bringUp(us, t0)
	us.Handle(Geo{ptr("US")}, t0)
	want(t, us.Snapshot().Tripped, false)
}

func TestGeoUnknownDoesNotVerify(t *testing.T) {
	e := testEngine(ModeProxy)
	e.Handle(Health{true, true}, t0)
	e.Handle(Probe{ptr(100)}, t0)
	e.Handle(Probe{ptr(100)}, t0)
	e.Handle(Geo{}, t0)
	want(t, e.Snapshot().Tripped, true)
	want(t, e.Snapshot().GeoVerified, false)
}

func TestNetworkChangeHoldsAtLeastConfiguredSeconds(t *testing.T) {
	e := testEngine(ModeProxy)
	bringUp(e, t0)
	e.Handle(NetworkChanged{}, t0)
	want(t, e.Snapshot().Reason, ptr(FuseReason{Type: ReasonNetworkChanged}))
	bringUp(e, t0+7000)
	check(t, e.Snapshot().Tripped, "the hold period must elapse before recovery")
	bringUp(e, t0+8001)
	want(t, e.Snapshot().Tripped, false)
}

func TestNetworkChangeDuringUnsafeExitKeepsReasonButResetsVerification(t *testing.T) {
	e := testEngine(ModeProxy)
	bringUp(e, t0)
	e.Handle(Geo{ptr("HK")}, t0)
	e.Handle(Geo{ptr("SG")}, t0+1)
	e.Handle(Probe{ptr(100)}, t0+1)
	e.Handle(NetworkChanged{}, t0+2)
	want(t, e.Snapshot().Reason, ptr(FuseReason{Type: ReasonUnsafeExit, Country: "HK"}))
	want(t, e.Snapshot().GeoVerified, false)
	want(t, e.Snapshot().RecoverProgress, 0)
}

func TestAutoRecoverOffLatchesUntilUserRestores(t *testing.T) {
	off := func(s *GuardSettings) { s.AutoRecover = false }
	e := testEngine(ModeProxy, off)
	bringUp(e, t0)
	for range 3 {
		e.Handle(Probe{}, t0)
	}
	e.Handle(ManualRestore{}, t0+1)
	check(t, e.Snapshot().Tripped, "unlock still requires verification")
	want(t, e.IsLatched(), false)

	latched := testEngine(ModeProxy, off)
	bringUp(latched, t0)
	for range 3 {
		latched.Handle(Probe{}, t0)
	}
	bringUp(latched, t0+1)
	check(t, latched.Snapshot().Tripped && latched.IsLatched(), "verification cannot clear a latch")
	latched.Handle(ManualRestore{}, t0+2)
	want(t, latched.Snapshot().Tripped, false)
	bringUp(e, t0+3)
	want(t, e.Snapshot().Tripped, false)
}

func TestGuardReasonsRecoverEvenWithAutoRecoverOff(t *testing.T) {
	e := testEngine(ModeProxy, func(s *GuardSettings) { s.AutoRecover = false })
	bringUp(e, t0)
	want(t, e.Snapshot().Tripped, false)
}

func TestManualTripStaysUntilRestore(t *testing.T) {
	e := testEngine(ModeProxy)
	bringUp(e, t0)
	e.Handle(ManualTrip{}, t0)
	bringUp(e, t0+1)
	want(t, e.Snapshot().Reason, ptr(FuseReason{Type: ReasonManual}))
	e.Handle(ManualRestore{Force: true}, t0+2)
	want(t, e.Snapshot().Tripped, false)
}

func TestFuseActionDecidesHardness(t *testing.T) {
	e := testEngine(ModeProxy, func(s *GuardSettings) { s.FuseAction = FuseCutAll })
	want(t, e.Snapshot().Hard, true)
	e.Update(NewFuseConfig(DefaultSettings(), ModeProxy), t0)
	want(t, e.Snapshot().Hard, false)
}

func TestDirectModeRecoversWithoutProxyProbes(t *testing.T) {
	e := testEngine(ModeDirect)
	e.Handle(Health{true, true}, t0)
	want(t, e.Snapshot().Tripped, false)
	want(t, e.Snapshot().RecoverNeeded, 0)
}

func TestDisabledFuseNeverTrips(t *testing.T) {
	e := testEngine(ModeProxy, func(s *GuardSettings) { s.FuseEnabled = false })
	want(t, e.Snapshot().Tripped, false)
	e.Handle(Geo{ptr("CN")}, t0)
	e.Handle(Health{false, false}, t0)
	want(t, e.Snapshot().Tripped, false)
}

func TestModeChangeRetriggersStartupGuard(t *testing.T) {
	e := testEngine(ModeProxy)
	bringUp(e, t0)
	settings := DefaultSettings()
	settings.RecoverSuccesses = 2
	e.Update(NewFuseConfig(settings, ModeDirect), t0)
	want(t, e.Snapshot().Reason, ptr(FuseReason{Type: ReasonStarting}))
}

func TestIPv6LeakTripsAndBlocksRecovery(t *testing.T) {
	e := testEngine(ModeProxy)
	bringUp(e, t0)
	e.Handle(IPv6{true}, t0)
	bringUp(e, t0+1)
	want(t, e.Snapshot().Reason, ptr(FuseReason{Type: ReasonIPv6Leak}))
	e.Handle(IPv6{false}, t0+2)
	bringUp(e, t0+3)
	want(t, e.Snapshot().Tripped, false)
}

func TestCoreAndTunHealthGateRecovery(t *testing.T) {
	e := testEngine(ModeProxy)
	bringUp(e, t0)
	e.Handle(Health{true, false}, t0)
	want(t, e.Snapshot().Reason, ptr(FuseReason{Type: ReasonTunLost}))
	e.Handle(Health{false, false}, t0)
	want(t, e.Snapshot().Reason, ptr(FuseReason{Type: ReasonCoreDown}))
}

func TestCoreRestartKeepsLatch(t *testing.T) {
	e := testEngine(ModeProxy)
	bringUp(e, t0)
	e.Handle(ManualTrip{}, t0)
	e.CoreRestarted(t0 + 1)
	bringUp(e, t0+2)
	check(t, e.Snapshot().Tripped && e.IsLatched(), "core restart must keep the manual latch")
}

func TestLowerPriorityReasonDoesNotOverride(t *testing.T) {
	e := testEngine(ModeProxy)
	bringUp(e, t0)
	e.Handle(Geo{ptr("HK")}, t0)
	e.Handle(NetworkChanged{}, t0+1)
	want(t, e.Snapshot().Reason, ptr(FuseReason{Type: ReasonUnsafeExit, Country: "HK"}))
	want(t, e.Snapshot().HoldUntil, ptr(t0+1+8000))
}
