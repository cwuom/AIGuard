package core

import (
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type ProxyMode string

const (
	ModeProxy  ProxyMode = "proxy"
	ModeDirect ProxyMode = "direct"
)

type RoutingMode string

const (
	RoutingSmart  RoutingMode = "smart"
	RoutingGlobal RoutingMode = "global"
)

type FuseAction string

const (
	FuseCutAll    FuseAction = "cutAll"
	FuseWhitelist FuseAction = "whitelist"
)

type SubscriptionUsage struct {
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Total    int64  `json:"total"`
	Expire   *int64 `json:"expire,omitempty"` // epoch seconds
}

func (u *SubscriptionUsage) UnmarshalJSON(data []byte) error {
	type plain SubscriptionUsage
	var value plain
	if err := decodeWireObject(data, &value, "upload", "download", "total"); err != nil {
		return err
	}
	*u = SubscriptionUsage(value)
	return nil
}

func (u SubscriptionUsage) Used() int64 {
	sum := u.Upload + u.Download
	if ((u.Upload ^ sum) & (u.Download ^ sum)) < 0 {
		return math.MaxInt64
	}
	return sum
}

func ParseSubscriptionUsage(header string) *SubscriptionUsage {
	values := make(map[string]int64)
	for part := range strings.SplitSeq(header, ";") {
		key, raw, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		raw = strings.TrimSpace(raw)
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			f, err := strconv.ParseFloat(raw, 64)
			if err != nil || !(f >= 0 && f < 9.2e18) {
				continue
			}
			v = int64(math.Round(f))
		}
		if v >= 0 {
			values[strings.ToLower(strings.TrimSpace(key))] = v
		}
	}
	if _, total := values["total"]; !total {
		if _, download := values["download"]; !download {
			return nil
		}
	}
	u := SubscriptionUsage{Upload: values["upload"], Download: values["download"], Total: values["total"]}
	if expire := values["expire"]; expire > 0 {
		u.Expire = &expire
	}
	return &u
}

type SubscriptionInfo struct {
	URL         string             `json:"url"`
	Name        *string            `json:"name,omitempty"`
	LastUpdated *int64             `json:"lastUpdated,omitempty"` // epoch milliseconds
	NodeCount   int                `json:"nodeCount"`
	Usage       *SubscriptionUsage `json:"usage,omitempty"`
	LastError   *string            `json:"lastError,omitempty"`
}

func (s *SubscriptionInfo) UnmarshalJSON(data []byte) error {
	type plain SubscriptionInfo
	var value plain
	if err := decodeWireObject(data, &value, "url"); err != nil {
		return err
	}
	*s = SubscriptionInfo(value)
	return nil
}

func (s SubscriptionInfo) MaskedURL() string {
	u, host := parseSubscriptionURL(s.URL)
	if u == nil || host == "" {
		return "••••"
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	} else {
		scheme, _, _ = strings.Cut(s.URL, ":")
	}
	var tail string
	_, rawPath := rawURLParts(s.URL)
	if path := utf16Units(rawPath); len(path) > 4 {
		tail = decodeUTF16(path[len(path)-4:])
	}
	return scheme + "://" + host + "/••••" + tail
}

func (s SubscriptionInfo) Host() string {
	_, host := parseSubscriptionURL(s.URL)
	return strings.ToLower(host)
}

const CurrentSchema = 1

type GuardSettings struct {
	Schema                  int               `json:"schema"`
	Enabled                 bool              `json:"enabled"`
	Mode                    ProxyMode         `json:"mode"`
	Routing                 RoutingMode       `json:"routing"`
	FuseEnabled             bool              `json:"fuseEnabled"`
	FuseAction              FuseAction        `json:"fuseAction"`
	AutoRecover             bool              `json:"autoRecover"`
	ProbeIntervalSeconds    int               `json:"probeIntervalSeconds"`
	FailureThreshold        int               `json:"failureThreshold"`
	LatencyThresholdMs      int               `json:"latencyThresholdMs"`
	RecoverSuccesses        int               `json:"recoverSuccesses"`
	WakeHoldSeconds         int               `json:"wakeHoldSeconds"`
	ForbiddenRegions        []string          `json:"forbiddenRegions"`
	AutoSwitchUnsafeNode    bool              `json:"autoSwitchUnsafeNode"`
	CloseAppsOnFuse         bool              `json:"closeAppsOnFuse"`
	CloseAppsOnGuardTrips   bool              `json:"closeAppsOnGuardTrips"`
	LeakGuard               bool              `json:"leakGuard"`
	DirectOnlyMainland      bool              `json:"directOnlyMainland"`
	DisableSystemIPv6       bool              `json:"disableSystemIPv6"`
	LockSystemDNS           bool              `json:"lockSystemDns"`
	DisabledAICategories    []string          `json:"disabledAICategories"`
	CustomAIDomains         []string          `json:"customAIDomains"`
	CustomDirectDomains     []string          `json:"customDirectDomains"`
	CustomProxyDomains      []string          `json:"customProxyDomains"`
	ExtraAIProcesses        []string          `json:"extraAIProcesses"`
	GameMode                bool              `json:"gameMode"`
	GameAutoDetect          bool              `json:"gameAutoDetect"`
	ExtraGameProcesses      []string          `json:"extraGameProcesses"`
	Subscription            *SubscriptionInfo `json:"subscription,omitempty"`
	SubscriptionUpdateHours int               `json:"subscriptionUpdateHours"`
}

func DefaultSettings() GuardSettings {
	return GuardSettings{
		Schema: CurrentSchema, Enabled: true, Mode: ModeProxy, Routing: RoutingSmart,
		FuseEnabled: true, FuseAction: FuseWhitelist, AutoRecover: true,
		ProbeIntervalSeconds: 2, FailureThreshold: 2, LatencyThresholdMs: 3000, RecoverSuccesses: 4,
		WakeHoldSeconds: 8, ForbiddenRegions: []string{"CN", "HK", "MO"}, AutoSwitchUnsafeNode: true,
		CloseAppsOnFuse: true, LeakGuard: true, DirectOnlyMainland: true, DisableSystemIPv6: true,
		LockSystemDNS: true, SubscriptionUpdateHours: 12,
		DisabledAICategories: []string{}, CustomAIDomains: []string{}, CustomDirectDomains: []string{},
		CustomProxyDomains: []string{}, ExtraAIProcesses: []string{},
		GameAutoDetect: false, ExtraGameProcesses: []string{},
	}
}

func (s *GuardSettings) UnmarshalJSON(data []byte) error {
	type plain GuardSettings
	defaults := DefaultSettings()
	value := plain(defaults)
	if err := decodeWireObject(data, &value); err != nil {
		return err
	}
	if value.Mode != ModeProxy && value.Mode != ModeDirect {
		value.Mode = defaults.Mode
	}
	if value.Routing != RoutingSmart && value.Routing != RoutingGlobal {
		value.Routing = defaults.Routing
	}
	if value.FuseAction != FuseCutAll && value.FuseAction != FuseWhitelist {
		value.FuseAction = defaults.FuseAction
	}
	*s = GuardSettings(value)
	return nil
}

func (s GuardSettings) Sanitized() GuardSettings {
	s.Schema = CurrentSchema
	s.ProbeIntervalSeconds = clamp(s.ProbeIntervalSeconds, 1, 10)
	s.FailureThreshold = clamp(s.FailureThreshold, 1, 20)
	s.LatencyThresholdMs = clamp(s.LatencyThresholdMs, 300, 10000)
	s.RecoverSuccesses = clamp(s.RecoverSuccesses, 1, 30)
	s.WakeHoldSeconds = clamp(s.WakeHoldSeconds, 0, 60)
	s.SubscriptionUpdateHours = clamp(s.SubscriptionUpdateHours, 1, 168)
	s.ForbiddenRegions = NormalizeRegions(s.ForbiddenRegions)
	if !slices.Contains(s.ForbiddenRegions, "CN") {
		s.ForbiddenRegions = append([]string{"CN"}, s.ForbiddenRegions...)
	}
	s.CustomAIDomains = CleanDomains(s.CustomAIDomains)
	s.CustomDirectDomains = CleanDomains(s.CustomDirectDomains)
	s.CustomProxyDomains = CleanDomains(s.CustomProxyDomains)
	s.ExtraAIProcesses = CleanProcessNames(s.ExtraAIProcesses)
	s.ExtraGameProcesses = CleanProcessNames(s.ExtraGameProcesses)
	return s
}

func clamp(value, lo, hi int) int { return min(max(value, lo), hi) }

func NormalizeRegions(list []string) []string {
	out := []string{}
	for _, raw := range list {
		s := strings.ToUpper(strings.TrimSpace(raw))
		if len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z' && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

var domainChars = regexp.MustCompile(`^[a-z0-9.-]+$`)

func CleanDomains(list []string) []string {
	out := []string{}
	seen := make(map[string]bool)
	for _, raw := range list {
		s := strings.ToLower(strings.TrimSpace(raw))
		if _, rest, ok := strings.Cut(s, "://"); ok {
			s = rest
		}
		s, _, _ = strings.Cut(s, "/")
		s = strings.TrimLeft(s, ".*+")
		if len(s) > 253 || !strings.Contains(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") || !domainChars.MatchString(s) || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

var processNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9 ._()-]{0,63}\.exe$`)

func CleanProcessNames(list []string) []string {
	out := []string{}
	seen := make(map[string]bool)
	for _, raw := range list {
		s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".exe") + ".exe"
		if processNamePattern.MatchString(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
