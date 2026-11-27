package core

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	ReasonStarting       = "starting"
	ReasonNetworkChanged = "networkChanged"
	ReasonCoreDown       = "coreDown"
	ReasonTunLost        = "tunLost"
	ReasonIPv6Leak       = "ipv6Leak"
	ReasonProxyUnstable  = "proxyUnstable"
	ReasonUnsafeExit     = "unsafeExit"
	ReasonManual         = "manual"
)

type FuseReason struct {
	Type     string
	Failures int
	Country  string
}

func (r FuseReason) MarshalJSON() ([]byte, error) {
	value := fuseReasonJSON{Type: r.Type}
	switch r.Type {
	case ReasonProxyUnstable:
		value.Failures = &r.Failures
	case ReasonUnsafeExit:
		value.Country = &r.Country
	default:
		if r.Priority() < 0 {
			return nil, fmt.Errorf("unknown fuse reason %q", r.Type)
		}
	}
	return json.Marshal(value)
}

type fuseReasonJSON struct {
	Type     string  `json:"type"`
	Failures *int    `json:"failures,omitempty"`
	Country  *string `json:"country,omitempty"`
}

func (r *FuseReason) UnmarshalJSON(data []byte) error {
	fields, err := wireFields(data)
	if err != nil {
		return err
	}
	var out FuseReason
	if err := decodeRequiredField(fields, "type", &out.Type); err != nil {
		return err
	}
	switch out.Type {
	case ReasonProxyUnstable:
		err = decodeRequiredField(fields, "failures", &out.Failures)
	case ReasonUnsafeExit:
		err = decodeRequiredField(fields, "country", &out.Country)
	default:
		if out.Priority() < 0 {
			return fmt.Errorf("unknown fuse reason %q", out.Type)
		}
	}
	if err != nil {
		return err
	}
	*r = out
	return nil
}

func (r FuseReason) IsTransientGuard() bool {
	return r.IsPrecautionary() || r.Type == ReasonCoreDown || r.Type == ReasonTunLost || r.Type == ReasonIPv6Leak
}

func (r FuseReason) IsPrecautionary() bool {
	return r.Type == ReasonStarting || r.Type == ReasonNetworkChanged
}

func (r FuseReason) Title() string {
	switch r.Type {
	case ReasonStarting:
		return "启动保护：等待内核与线路就绪"
	case ReasonNetworkChanged:
		return "网络切换保护：等待新网络稳定"
	case ReasonCoreDown:
		return "代理内核未运行"
	case ReasonTunLost:
		return "TUN 路由丢失，流量可能绕过代理"
	case ReasonIPv6Leak:
		return "检测到 IPv6 可以直连公网，防火墙封锁失效"
	case ReasonProxyUnstable:
		return fmt.Sprintf("代理不稳定：长连接心跳连续 %d 次失败", r.Failures)
	case ReasonUnsafeExit:
		return fmt.Sprintf("出口落在 %s（%s）", RegionName(r.Country), r.Country)
	case ReasonManual:
		return "手动熔断"
	default:
		return ""
	}
}

func (r FuseReason) Priority() int {
	switch r.Type {
	case ReasonManual:
		return 5
	case ReasonUnsafeExit:
		return 4
	case ReasonCoreDown, ReasonTunLost, ReasonIPv6Leak:
		return 3
	case ReasonProxyUnstable:
		return 2
	case ReasonNetworkChanged:
		return 1
	case ReasonStarting:
		return 0
	default:
		return -1
	}
}

type FuseConfig struct {
	Enabled            bool
	Action             FuseAction
	AutoRecover        bool
	FailureThreshold   int
	LatencyThresholdMs int
	RecoverSuccesses   int
	NetworkHoldMs      int64
	Forbidden          map[string]bool
	Mode               ProxyMode
}

func NewFuseConfig(raw GuardSettings, effectiveMode ProxyMode) FuseConfig {
	s := raw.Sanitized()
	forbidden := make(map[string]bool, len(s.ForbiddenRegions))
	for _, region := range s.ForbiddenRegions {
		forbidden[region] = true
	}
	return FuseConfig{
		Enabled: s.FuseEnabled, Action: s.FuseAction, AutoRecover: s.AutoRecover,
		FailureThreshold: s.FailureThreshold, LatencyThresholdMs: s.LatencyThresholdMs,
		RecoverSuccesses: s.RecoverSuccesses, NetworkHoldMs: int64(s.WakeHoldSeconds) * 1000,
		Forbidden: forbidden, Mode: effectiveMode,
	}
}

type FuseSignal interface{ fuseSignal() }

type (
	Health         struct{ CoreUp, TunUp bool }
	Probe          struct{ MS *int }
	Geo            struct{ Country *string }
	IPv6           struct{ Leaking bool }
	NetworkChanged struct{}
	ManualTrip     struct{}
	ManualRestore  struct{ Force bool }
	Reset          struct{}
)

func (Health) fuseSignal()         {}
func (Probe) fuseSignal()          {}
func (Geo) fuseSignal()            {}
func (IPv6) fuseSignal()           {}
func (NetworkChanged) fuseSignal() {}
func (ManualTrip) fuseSignal()     {}
func (ManualRestore) fuseSignal()  {}
func (Reset) fuseSignal()          {}

// since and holdUntil use the caller's monotonic milliseconds
type FuseSnapshot struct {
	Tripped             bool        `json:"tripped"`
	Hard                bool        `json:"hard"`
	Reason              *FuseReason `json:"reason,omitempty"`
	Since               *int64      `json:"since,omitempty"`
	HoldUntil           *int64      `json:"holdUntil,omitempty"`
	RecoverProgress     int         `json:"recoverProgress"`
	RecoverNeeded       int         `json:"recoverNeeded"`
	GeoVerified         bool        `json:"geoVerified"`
	ConsecutiveFailures int         `json:"consecutiveFailures"`
}

func (s *FuseSnapshot) UnmarshalJSON(data []byte) error {
	type plain FuseSnapshot
	var value plain
	if err := decodeWireObject(data, &value); err != nil {
		return err
	}
	*s = FuseSnapshot(value)
	return nil
}

type FuseEngine struct {
	config         FuseConfig
	snapshot       FuseSnapshot
	coreUp         bool
	tunUp          bool
	successes      int
	geoOKSinceTrip bool
	latched        bool
	ipv6Leaking    bool
}

func NewFuseEngine(config FuseConfig, now int64, startTripped ...bool) *FuseEngine {
	e := &FuseEngine{config: config}
	if config.Enabled && (len(startTripped) == 0 || startTripped[0]) {
		e.trip(FuseReason{Type: ReasonStarting}, now, 0, false)
	}
	return e
}

func (e *FuseEngine) Snapshot() FuseSnapshot {
	s := e.snapshot
	s.Reason = copyOptional(s.Reason)
	s.Since = copyOptional(s.Since)
	s.HoldUntil = copyOptional(s.HoldUntil)
	return s
}

func copyOptional[T any](p *T) *T {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}

func (e *FuseEngine) IsLatched() bool { return e.latched }

func (e *FuseEngine) Update(config FuseConfig, now int64) {
	modeChanged := config.Mode != e.config.Mode
	e.config = config
	if !config.Enabled {
		e.snapshot = FuseSnapshot{}
		return
	}
	if modeChanged {
		e.trip(FuseReason{Type: ReasonStarting}, now, 0, false)
	}
	if e.snapshot.Tripped {
		e.snapshot.Hard = config.Action == FuseCutAll
	}
	e.refreshNeeded()
}

func (e *FuseEngine) CoreRestarted(now int64) {
	if !e.config.Enabled {
		return
	}
	e.coreUp, e.tunUp = false, false
	e.trip(FuseReason{Type: ReasonStarting}, now, 0, false)
}

func (e *FuseEngine) Handle(signal FuseSignal, now int64) bool {
	before := e.snapshot
	if !e.config.Enabled {
		if health, ok := signal.(Health); ok {
			e.coreUp, e.tunUp = health.CoreUp, health.TunUp
		}
		e.snapshot = FuseSnapshot{}
		return before != e.snapshot
	}
	switch s := signal.(type) {
	case Reset:
		e.recover()
	case Health:
		e.coreUp, e.tunUp = s.CoreUp, s.TunUp
		if !s.CoreUp {
			e.trip(FuseReason{Type: ReasonCoreDown}, now, 0, false)
		} else if !s.TunUp {
			e.trip(FuseReason{Type: ReasonTunLost}, now, 0, false)
		}
		e.tryRecover(now)
	case NetworkChanged:
		e.trip(FuseReason{Type: ReasonNetworkChanged}, now, e.config.NetworkHoldMs, false)
	case ManualTrip:
		e.trip(FuseReason{Type: ReasonManual}, now, 0, true)
	case ManualRestore:
		if s.Force {
			e.recover()
		} else if e.snapshot.Tripped {
			e.latched = false
			e.tryRecover(now)
		}
	case Probe:
		ok := e.config.Mode != ModeProxy || (s.MS != nil && *s.MS <= e.config.LatencyThresholdMs)
		e.handleProbe(ok, now)
	case Geo:
		e.handleGeo(s.Country, now)
	case IPv6:
		e.ipv6Leaking = s.Leaking
		if s.Leaking {
			e.trip(FuseReason{Type: ReasonIPv6Leak}, now, 0, false)
		} else {
			e.tryRecover(now)
		}
	}
	// trip retains the existing pointers when their values are unchanged
	return before != e.snapshot
}

func (e *FuseEngine) handleProbe(ok bool, now int64) {
	s := &e.snapshot
	if e.config.Mode == ModeDirect {
		s.ConsecutiveFailures = 0
		e.tryRecover(now)
		return
	}
	if ok {
		s.ConsecutiveFailures = 0
		if s.Tripped {
			e.successes++
		}
	} else {
		s.ConsecutiveFailures++
		e.successes = 0
		if s.ConsecutiveFailures >= e.config.FailureThreshold {
			e.trip(FuseReason{Type: ReasonProxyUnstable, Failures: s.ConsecutiveFailures}, now, 0, false)
		}
	}
	s.RecoverProgress = min(e.successes, s.RecoverNeeded)
	e.tryRecover(now)
}

func (e *FuseEngine) handleGeo(country *string, now int64) {
	if e.config.Mode != ModeProxy {
		return
	}
	if country != nil {
		if e.config.Forbidden[*country] {
			e.trip(FuseReason{Type: ReasonUnsafeExit, Country: *country}, now, 0, true)
			return
		}
		e.geoOKSinceTrip = true
		e.snapshot.GeoVerified = true
	}
	e.tryRecover(now)
}

func (e *FuseEngine) trip(reason FuseReason, now, holdMs int64, force bool) {
	s := &e.snapshot
	if reason.Type == ReasonManual || (!reason.IsTransientGuard() && !e.config.AutoRecover) {
		e.latched = true
	}
	current := s.Reason
	keepReason := s.Tripped && !force && current != nil && reason.Priority() < current.Priority()
	if !keepReason && (current == nil || *current != reason) {
		s.Reason = &reason
	}
	until := now + holdMs
	if s.HoldUntil == nil || *s.HoldUntil < until {
		s.HoldUntil = &until
	}
	if !s.Tripped {
		s.Since = &now
	}
	s.Hard = (s.Tripped && s.Hard) || e.config.Action == FuseCutAll
	s.Tripped = true
	s.GeoVerified = false
	s.RecoverProgress = 0
	e.successes = 0
	e.geoOKSinceTrip = false
	e.refreshNeeded()
}

func (e *FuseEngine) refreshNeeded() {
	e.snapshot.RecoverNeeded = 0
	if e.config.Mode == ModeProxy {
		e.snapshot.RecoverNeeded = e.config.RecoverSuccesses
	}
}

func (e *FuseEngine) tryRecover(now int64) {
	s := e.snapshot
	if !s.Tripped || s.Reason == nil || e.latched || (s.HoldUntil != nil && now < *s.HoldUntil) {
		return
	}
	if !e.coreUp || !e.tunUp || e.ipv6Leaking {
		return
	}
	if e.config.Mode == ModeProxy && (e.successes < e.config.RecoverSuccesses || !e.geoOKSinceTrip) {
		return
	}
	e.recover()
}

func (e *FuseEngine) recover() {
	e.snapshot = FuseSnapshot{}
	e.successes = 0
	e.geoOKSinceTrip = false
	e.latched = false
}

func RegionName(code string) string {
	if name, ok := regionNames[strings.ToUpper(code)]; ok {
		return name
	}
	return code
}

func RegionNodePattern(code string) string {
	c := strings.ToUpper(code)
	if pattern, ok := nodeWords[c]; ok {
		return pattern
	}
	pattern := "(?<![a-z])" + strings.ToLower(c) + "(?![a-z])|" + RegionFlag(c)
	if name, ok := regionNames[c]; ok {
		return name + "|" + pattern
	}
	return pattern
}

func RegionFlag(code string) string {
	var out strings.Builder
	for _, unit := range utf16Units(strings.ToUpper(code)) {
		out.WriteRune(0x1f1e6 + (rune(unit) - 'A'))
	}
	return out.String()
}

var regionNames = map[string]string{
	"CN": "中国大陆", "HK": "香港", "MO": "澳门", "TW": "台湾", "JP": "日本", "KR": "韩国",
	"SG": "新加坡", "US": "美国", "GB": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰",
	"CA": "加拿大", "AU": "澳大利亚", "RU": "俄罗斯", "IN": "印度", "MY": "马来西亚", "TH": "泰国",
	"VN": "越南", "PH": "菲律宾", "ID": "印度尼西亚", "TR": "土耳其", "AE": "阿联酋", "IR": "伊朗",
	"KP": "朝鲜", "CH": "瑞士", "SE": "瑞典", "IT": "意大利", "ES": "西班牙",
}

var nodeWords = map[string]string{
	"CN": "中国|大陆|china|(?<![a-z])cn(?![a-z0-9])|上海|北京|广州|深圳|杭州|🇨🇳",
	"HK": "港|hong ?kong|(?<![a-z])hk(?![a-z])|hkg|🇭🇰",
	"MO": "澳门|澳門|macau|macao|(?<![a-z])mo(?![a-z0-9])|🇲🇴",
	"US": "美国|美國|united ?states|america|(?<![a-z])usa?(?![a-z])|洛杉矶|圣何塞|硅谷|西雅图|纽约|芝加哥|达拉斯|凤凰城|波特兰|弗吉尼亚|迈阿密|亚特兰大|(?<![a-z])(lax|sjc|sea|nyc|jfk|ord|dfw|iad|mia|atl|pdx)(?![a-z])|🇺🇸",
	"TW": "台湾|台灣|taiwan|(?<![a-z])tw(?![a-z])|🇹🇼",
	"JP": "日本|japan|(?<![a-z])jp(?![a-z])|东京|大阪|🇯🇵",
	"SG": "新加坡|狮城|singapore|(?<![a-z])sg(?![a-z])|🇸🇬",
	"KR": "韩国|韓國|korea|(?<![a-z])kr(?![a-z])|首尔|🇰🇷",
	"RU": "俄罗斯|russia|(?<![a-z])ru(?![a-z])|🇷🇺",
	"GB": "英国|united ?kingdom|(?<![a-z])(uk|gb)(?![a-z])|伦敦|🇬🇧",
	"DE": "德国|germany|(?<![a-z])de(?![a-z])|法兰克福|🇩🇪",
}
