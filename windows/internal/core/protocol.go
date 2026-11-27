package core

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

const (
	ProtocolVersion = 1
	MaxMessageBytes = 4 * 1024 * 1024
	PipeName        = `\\.\pipe\aiguard-control`
	ServiceName     = "AIGuard"
)

var Ports = struct {
	Controller, Probe, DirectProbe, DNS int
}{19097, 17892, 17893, 1053}

type GuardPhase string

const (
	PhaseDisabled  GuardPhase = "disabled"
	PhaseStarting  GuardPhase = "starting"
	PhaseProtected GuardPhase = "protected"
	PhaseTripped   GuardPhase = "tripped"
	PhaseError     GuardPhase = "error"
)

type ExitStatus struct {
	Trace     *ExitTrace `json:"trace,omitempty"`
	CheckedAt *int64     `json:"checkedAt,omitempty"`
	Error     *string    `json:"error,omitempty"`
}

func (s *ExitStatus) UnmarshalJSON(data []byte) error {
	type plain ExitStatus
	var value plain
	if err := decodeWireObject(data, &value); err != nil {
		return err
	}
	*s = ExitStatus(value)
	return nil
}

type LatencySample struct {
	At int64 `json:"at"`
	MS *int  `json:"ms,omitempty"`
}

func (s *LatencySample) UnmarshalJSON(data []byte) error {
	type plain LatencySample
	var value plain
	if err := decodeWireObject(data, &value, "at"); err != nil {
		return err
	}
	*s = LatencySample(value)
	return nil
}

type GuardStatus struct {
	Version                string            `json:"version"`
	Protocol               int               `json:"protocol"`
	Phase                  GuardPhase        `json:"phase"`
	EffectiveMode          ProxyMode         `json:"effectiveMode"`
	Routing                RoutingMode       `json:"routing"`
	Fuse                   FuseSnapshot      `json:"fuse"`
	FuseSince              *int64            `json:"fuseSince,omitempty"`
	FuseHoldRemainingMs    *int64            `json:"fuseHoldRemainingMs,omitempty"`
	FuseLatched            bool              `json:"fuseLatched"`
	CoreRunning            bool              `json:"coreRunning"`
	CoreVersion            *string           `json:"coreVersion,omitempty"`
	CoreRestarts           int               `json:"coreRestarts"`
	TunUp                  bool              `json:"tunUp"`
	TunInterface           *string           `json:"tunInterface,omitempty"`
	FirewallPolicy         string            `json:"firewallPolicy"`
	IPv6Blocked            *bool             `json:"ipv6Blocked,omitempty"`
	IPv6DisabledInterfaces int               `json:"ipv6DisabledInterfaces"`
	SystemDNSLocked        bool              `json:"systemDnsLocked"`
	Exit                   ExitStatus        `json:"exit"`
	HeartbeatAlive         bool              `json:"heartbeatAlive"`
	Latency                []LatencySample   `json:"latency"`
	PrimaryInterface       *string           `json:"primaryInterface,omitempty"`
	Conflicts              []string          `json:"conflicts"`
	Subscription           *SubscriptionInfo `json:"subscription,omitempty"`
	CaptiveUntil           *int64            `json:"captiveUntil,omitempty"`
	LastError              *string           `json:"lastError,omitempty"`
	NodeCount              *int              `json:"nodeCount,omitempty"`
	GameMode               bool              `json:"gameMode"`
	GameReason             *string           `json:"gameReason,omitempty"`
	GameBlockedApps        int               `json:"gameBlockedApps"`
	UpdatedAt              int64             `json:"updatedAt"`
}

func DefaultGuardStatus() GuardStatus {
	return GuardStatus{
		Protocol: ProtocolVersion, Phase: PhaseStarting, EffectiveMode: ModeDirect, Routing: RoutingSmart,
		FirewallPolicy: "none", Latency: []LatencySample{}, Conflicts: []string{},
	}
}

func (s *GuardStatus) UnmarshalJSON(data []byte) error {
	type plain GuardStatus
	value := plain(DefaultGuardStatus())
	if err := decodeWireObject(data, &value); err != nil {
		return err
	}
	switch value.Phase {
	case PhaseDisabled, PhaseStarting, PhaseProtected, PhaseTripped, PhaseError:
	default:
		value.Phase = PhaseStarting
	}
	if value.EffectiveMode != ModeDirect && value.EffectiveMode != ModeProxy {
		value.EffectiveMode = ModeDirect
	}
	if value.Routing != RoutingSmart && value.Routing != RoutingGlobal {
		value.Routing = RoutingSmart
	}
	*s = GuardStatus(value)
	return nil
}

type EventLevel string

const (
	EventInfo     EventLevel = "info"
	EventWarning  EventLevel = "warning"
	EventCritical EventLevel = "critical"
)

type GuardEvent struct {
	ID      int        `json:"id"`
	At      int64      `json:"at"`
	Level   EventLevel `json:"level"`
	Message string     `json:"message"`
}

func (e *GuardEvent) UnmarshalJSON(data []byte) error {
	type plain GuardEvent
	var value plain
	if err := decodeWireObject(data, &value, "id", "at", "level", "message"); err != nil {
		return err
	}
	switch value.Level {
	case EventInfo, EventWarning, EventCritical:
		*e = GuardEvent(value)
		return nil
	default:
		return fmt.Errorf("unknown event level %q", value.Level)
	}
}

type ControllerInfo struct {
	BaseURL string `json:"baseUrl"`
	Secret  string `json:"secret"`
}

func (c *ControllerInfo) UnmarshalJSON(data []byte) error {
	type plain ControllerInfo
	var value plain
	if err := decodeWireObject(data, &value, "baseUrl", "secret"); err != nil {
		return err
	}
	*c = ControllerInfo(value)
	return nil
}

const (
	RequestStatus              = "status"
	RequestGetSettings         = "getSettings"
	RequestUpdateSettings      = "updateSettings"
	RequestImportSubscription  = "importSubscription"
	RequestRefreshSubscription = "refreshSubscription"
	RequestRemoveSubscription  = "removeSubscription"
	RequestTripFuse            = "tripFuse"
	RequestRestoreNetwork      = "restoreNetwork"
	RequestCaptiveLogin        = "captiveLogin"
	RequestEndCaptiveLogin     = "endCaptiveLogin"
	RequestControllerInfo      = "controllerInfo"
	RequestEvents              = "events"
	RequestClearEvents         = "clearEvents"
	RequestFlushConnections    = "flushConnections"
	RequestRestartCore         = "restartCore"
)

type Request struct {
	Type     string
	Settings *GuardSettings
	URL      string
	Force    bool
	Minutes  int
	After    int
}

type requestJSON struct {
	Type     string         `json:"type"`
	Settings *GuardSettings `json:"settings,omitempty"`
	URL      *string        `json:"url,omitempty"`
	Force    *bool          `json:"force,omitempty"`
	Minutes  *int           `json:"minutes,omitempty"`
	After    *int           `json:"after,omitempty"`
}

func (r Request) MarshalJSON() ([]byte, error) {
	data := requestJSON{Type: r.Type}
	switch r.Type {
	case RequestUpdateSettings:
		if r.Settings == nil {
			return nil, fmt.Errorf("%s requires settings", r.Type)
		}
		data.Settings = r.Settings
	case RequestImportSubscription:
		data.URL = &r.URL
	case RequestRestoreNetwork:
		data.Force = &r.Force
	case RequestCaptiveLogin:
		data.Minutes = &r.Minutes
	case RequestEvents:
		data.After = &r.After
	default:
		if !parameterlessRequest(r.Type) {
			return nil, fmt.Errorf("unknown request type %q", r.Type)
		}
	}
	return json.Marshal(data)
}

func (r *Request) UnmarshalJSON(data []byte) error {
	fields, err := wireFields(data)
	if err != nil {
		return err
	}
	var out Request
	if err := decodeRequiredField(fields, "type", &out.Type); err != nil {
		return err
	}
	switch out.Type {
	case RequestUpdateSettings:
		err = decodeRequiredField(fields, "settings", &out.Settings)
	case RequestImportSubscription:
		err = decodeRequiredField(fields, "url", &out.URL)
	case RequestRestoreNetwork:
		err = decodeRequiredField(fields, "force", &out.Force)
	case RequestCaptiveLogin:
		err = decodeRequiredField(fields, "minutes", &out.Minutes)
	case RequestEvents:
		err = decodeRequiredField(fields, "after", &out.After)
	default:
		if !parameterlessRequest(out.Type) {
			return fmt.Errorf("unknown request type %q", out.Type)
		}
	}
	if err != nil {
		return err
	}
	*r = out
	return nil
}

func parameterlessRequest(kind string) bool {
	switch kind {
	case RequestStatus, RequestGetSettings, RequestRefreshSubscription, RequestRemoveSubscription,
		RequestTripFuse, RequestEndCaptiveLogin, RequestControllerInfo, RequestClearEvents,
		RequestFlushConnections, RequestRestartCore:
		return true
	default:
		return false
	}
}

type IpcEnvelope struct {
	Token   string  `json:"token"`
	Request Request `json:"request"`
}

func (e *IpcEnvelope) UnmarshalJSON(data []byte) error {
	type plain IpcEnvelope
	var value plain
	if err := decodeWireObject(data, &value, "token", "request"); err != nil {
		return err
	}
	*e = IpcEnvelope(value)
	return nil
}

type IpcResponse struct {
	OK               bool            `json:"ok"`
	Error            *string         `json:"error,omitempty"`
	Status           *GuardStatus    `json:"status,omitempty"`
	Settings         *GuardSettings  `json:"settings,omitempty"`
	Controller       *ControllerInfo `json:"controller,omitempty"`
	Events           *[]GuardEvent   `json:"events,omitempty"`
	EventsGeneration *string         `json:"eventsGeneration,omitempty"`
}

func DefaultIpcResponse() IpcResponse { return IpcResponse{OK: true} }

func FailureResponse(message string) IpcResponse { return IpcResponse{Error: &message} }

func (r *IpcResponse) UnmarshalJSON(data []byte) error {
	type plain IpcResponse
	value := plain(DefaultIpcResponse())
	if err := decodeWireObject(data, &value); err != nil {
		return err
	}
	*r = IpcResponse(value)
	return nil
}

func wireFields(data []byte) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, fmt.Errorf("expected a JSON object")
	}
	return fields, nil
}

func decodeRequiredField(fields map[string]json.RawMessage, name string, value any) error {
	raw := fields[name]
	if raw == nil || string(raw) == "null" {
		return fmt.Errorf("missing required JSON field %q", name)
	}
	return decodeWireField(raw, value)
}

func decodeWireField(raw json.RawMessage, value any) error {
	switch p := value.(type) {
	case *int:
		var n int32
		if err := json.Unmarshal(raw, &n); err != nil {
			return err
		}
		*p = int(n)
	case **int:
		n := new(int)
		if err := decodeWireField(raw, n); err != nil {
			return err
		}
		*p = n
	case *[]string:
		var items []*string
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		strings := make([]string, 0, len(items))
		for _, s := range items {
			if s == nil {
				return fmt.Errorf("expected a non-null string in array")
			}
			strings = append(strings, *s)
		}
		*p = strings
	default:
		return json.Unmarshal(raw, value)
	}
	return nil
}

// match wire keys exactly and let non-null fields keep their defaults on null input
func decodeWireObject(data []byte, value any, required ...string) error {
	fields, err := wireFields(data)
	if err != nil {
		return err
	}
	for _, name := range required {
		if raw := fields[name]; raw == nil || string(raw) == "null" {
			return fmt.Errorf("missing required JSON field %q", name)
		}
	}
	dest := reflect.ValueOf(value).Elem()
	for i := range dest.NumField() {
		name, _, _ := strings.Cut(dest.Type().Field(i).Tag.Get("json"), ",")
		if raw := fields[name]; raw != nil && string(raw) != "null" {
			if err := decodeWireField(raw, dest.Field(i).Addr().Interface()); err != nil {
				return fmt.Errorf("JSON field %q: %w", name, err)
			}
		}
	}
	return nil
}

func CompareVersions(a, b string) int {
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	part := func(parts []string, i int) int64 {
		if i < len(parts) {
			if n, err := strconv.ParseInt(parts[i], 10, 32); err == nil {
				return n
			}
		}
		return 0
	}
	for i := range max(len(x), len(y)) {
		l, r := part(x, i), part(y, i)
		if l < r {
			return -1
		}
		if l > r {
			return 1
		}
	}
	return 0
}
