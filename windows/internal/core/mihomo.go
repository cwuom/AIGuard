package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	CloudflareTraceURL   = "https://www.cloudflare.com/cdn-cgi/trace"
	IPInfoURL            = "https://ipinfo.io/json"
	DefaultFetchMaxBytes = 1 << 20
	traceMaxBytes        = 64 * 1024
)

type jsonObject map[string]jsonField

// jsonField retains the JSON token type, so strings, booleans and numbers follow Kotlin's parsing rules
type jsonField json.RawMessage

func (v *jsonField) UnmarshalJSON(data []byte) error {
	*v = append((*v)[:0], data...)
	return nil
}

func (v jsonField) obj() jsonObject {
	var out jsonObject
	_ = json.Unmarshal(v, &out)
	return out
}

func (v jsonField) array() []jsonField {
	var out []jsonField
	if err := json.Unmarshal(v, &out); err != nil {
		return nil
	}
	return out
}

func (v jsonField) str() *string {
	if len(v) == 0 || v[0] != '"' {
		return nil
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return nil
	}
	return &s
}

func (v jsonField) primitive() string {
	if s := v.str(); s != nil {
		return *s
	}
	return string(v)
}

func (v jsonField) int() *int {
	n, err := strconv.ParseInt(v.primitive(), 10, 32)
	if err != nil {
		return nil
	}
	i := int(n)
	return &i
}

func (v jsonField) long() int64 {
	n, err := strconv.ParseInt(v.primitive(), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func (v jsonField) bool() (bool, bool) {
	switch v.primitive() {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func (v jsonField) strings() []string {
	out := []string{}
	for _, item := range v.array() {
		if s := item.str(); s != nil {
			out = append(out, *s)
		}
	}
	return out
}

func parseJSONObject(text string) jsonObject { return jsonField(text).obj() }

func firstString(values ...jsonField) *string {
	for _, v := range values {
		if s := v.str(); s != nil {
			return s
		}
	}
	return nil
}

func valueOrZero[T any](p *T) (value T) {
	if p != nil {
		return *p
	}
	return value
}

type MihomoApi struct {
	client          *http.Client
	base            *url.URL
	secret          string
	reloadMu        sync.RWMutex
	lastReloadError *string
}

func NewMihomoApi(baseURL, secret string) *MihomoApi {
	base, _ := url.Parse(baseURL)
	return &MihomoApi{
		client: &http.Client{Transport: newTransport(3*time.Second, 8*time.Second)},
		base:   base, secret: secret,
	}
}

func (a *MihomoApi) LastReloadError(_ context.Context) *string {
	a.reloadMu.RLock()
	defer a.reloadMu.RUnlock()
	return copyOptional(a.lastReloadError)
}

func (a *MihomoApi) endpoint(query url.Values, segments []string) string {
	u := *a.base
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	for _, segment := range segments {
		path += "/" + url.PathEscape(segment)
	}
	u.RawPath = path
	u.Path, _ = url.PathUnescape(path)
	if len(query) != 0 {
		q := u.Query()
		maps.Copy(q, query)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func (a *MihomoApi) call(ctx context.Context, timeoutMs int64, method string, body map[string]string, query url.Values, segments ...string) (int, string, bool) {
	if a == nil || a.base == nil || a.client == nil {
		return 0, "", false
	}
	ctx, cancel, ok := requestContext(ctx, timeoutMs)
	if !ok {
		return 0, "", false
	}
	defer cancel()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, "", false
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.endpoint(query, segments), reader)
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("Authorization", "Bearer "+a.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := doWithoutReplay(a.client, req, cancel)
	if err != nil {
		return 0, "", false
	}
	defer response.Body.Close()
	result, err := io.ReadAll(idleBodyReader{response.Body, 8 * time.Second, cancel})
	if err != nil {
		return 0, "", false
	}
	return response.StatusCode, string(result), true
}

func (a *MihomoApi) getJSON(ctx context.Context, timeoutMs int64, query url.Values, segments ...string) jsonObject {
	code, text, ok := a.call(ctx, timeoutMs, http.MethodGet, nil, query, segments...)
	if !ok || code != http.StatusOK {
		return nil
	}
	return parseJSONObject(text)
}

func (a *MihomoApi) Version(ctx context.Context) (string, bool) {
	v := a.getJSON(ctx, 2000, nil, "version")["version"].str()
	return valueOrZero(v), v != nil
}

func delayQuery(testURL string, timeoutMs int) url.Values {
	return url.Values{"url": {testURL}, "timeout": {strconv.Itoa(timeoutMs)}}
}

func (a *MihomoApi) Delay(ctx context.Context, proxy, testURL string, timeoutMs int) (int, bool) {
	ms := a.getJSON(ctx, int64(timeoutMs)+2000, delayQuery(testURL, timeoutMs), "proxies", proxy, "delay")["delay"].int()
	if ms == nil || *ms <= 0 {
		return 0, false
	}
	return *ms, true
}

func successfulChange(code int) bool { return code == http.StatusOK || code == http.StatusNoContent }

func (a *MihomoApi) Select(ctx context.Context, group, proxy string) bool {
	code, _, ok := a.call(ctx, 5000, http.MethodPut, map[string]string{"name": proxy}, nil, "proxies", group)
	return ok && successfulChange(code)
}

type GroupInfo struct {
	Now *string
	All []string
}

func (a *MihomoApi) Group(ctx context.Context, name string) (*GroupInfo, bool) {
	o := a.getJSON(ctx, 5000, nil, "proxies", name)
	if o == nil {
		return nil, false
	}
	return &GroupInfo{Now: o["now"].str(), All: o["all"].strings()}, true
}

func (a *MihomoApi) IsAlive(ctx context.Context, name string) (bool, bool) {
	return a.getJSON(ctx, 5000, nil, "proxies", name)["alive"].bool()
}

func (a *MihomoApi) ReloadConfig(ctx context.Context, path string) bool {
	query := url.Values{"force": {"true"}}
	code, text, ok := a.call(ctx, 20000, http.MethodPut, map[string]string{"path": path}, query, "configs")
	if !ok {
		return false
	}
	if successfulChange(code) {
		return true
	}
	units := utf16Units(text)
	message := decodeUTF16(units[:min(300, len(units))])
	a.reloadMu.Lock()
	a.lastReloadError = &message
	a.reloadMu.Unlock()
	return false
}

func (a *MihomoApi) ReloadProvider(ctx context.Context, name string) bool {
	code, _, ok := a.call(ctx, 20000, http.MethodPut, nil, nil, "providers", "proxies", name)
	return ok && successfulChange(code)
}

func (a *MihomoApi) ProviderCount(ctx context.Context, name string) (int, bool) {
	proxies := a.getJSON(ctx, 5000, nil, "providers", "proxies", name)["proxies"].array()
	return len(proxies), proxies != nil
}

type ProxyItem struct {
	Name, Type string
	Now        *string
	All        []string
	LastDelay  *int
	Alive      bool
	Tested     bool
}

func (a *MihomoApi) Proxies(ctx context.Context) (map[string]ProxyItem, bool) {
	c1, top, ok := a.call(ctx, 5000, http.MethodGet, nil, nil, "proxies")
	if !ok {
		return nil, false
	}
	c2, providers, ok := a.call(ctx, 5000, http.MethodGet, nil, nil, "providers", "proxies")
	if !ok || c1 != http.StatusOK || c2 != http.StatusOK {
		return nil, false
	}
	return ParseProxies(top, &providers)
}

func (a *MihomoApi) GroupDelay(ctx context.Context, name, testURL string, timeoutMs int) (map[string]int, bool) {
	o := a.getJSON(ctx, int64(timeoutMs)+10000, delayQuery(testURL, timeoutMs), "group", name, "delay")
	if o == nil {
		return nil, false
	}
	out := make(map[string]int)
	for name, v := range o {
		if delay := v.int(); delay != nil {
			out[name] = *delay
		}
	}
	return out, true
}

type Connection struct {
	ID, Host, Destination, Network string
	Chain, Rule                    string
	Upload, Download               int64
	Start                          *int64
	Leaf                           string
}

type Route string

const (
	RouteProxy  Route = "proxy"
	RouteDirect Route = "direct"
	RouteReject Route = "reject"
)

func (c Connection) Route() Route {
	switch c.Leaf {
	case "DIRECT":
		return RouteDirect
	case "REJECT", "REJECT-DROP":
		return RouteReject
	default:
		return RouteProxy
	}
}

type ConnectionsSnapshot struct {
	Connections                []Connection
	UploadTotal, DownloadTotal int64
}

func (a *MihomoApi) Connections(ctx context.Context) (*ConnectionsSnapshot, bool) {
	o := a.getJSON(ctx, 5000, nil, "connections")
	if o == nil {
		return nil, false
	}
	return connectionsFromJSON(o), true
}

func (a *MihomoApi) CloseConnection(ctx context.Context, id string) bool {
	code, _, ok := a.call(ctx, 5000, http.MethodDelete, nil, nil, "connections", id)
	return ok && successfulChange(code)
}

func (a *MihomoApi) FlushConnections(ctx context.Context) bool {
	code, _, ok := a.call(ctx, 5000, http.MethodDelete, nil, nil, "connections")
	return ok && successfulChange(code)
}

func ParseProxies(top string, providers *string) (map[string]ProxyItem, bool) {
	proxies := parseJSONObject(top)["proxies"].obj()
	if proxies == nil {
		return nil, false
	}
	out := make(map[string]ProxyItem)
	for name, v := range proxies {
		if p := v.obj(); p != nil {
			out[name] = proxyItem(name, p)
		}
	}
	if providers == nil {
		return out, true
	}
	pmap := parseJSONObject(*providers)["providers"]
	if pmap.obj() == nil {
		return nil, false
	}
	// preserve provider iteration order when two providers expose the same node name
	dec := json.NewDecoder(bytes.NewReader(pmap))
	if _, err := dec.Token(); err != nil {
		return nil, false
	}
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return nil, false
		}
		var provider jsonField
		if err := dec.Decode(&provider); err != nil {
			return nil, false
		}
		for _, v := range provider.obj()["proxies"].array() {
			p := v.obj()
			if name := p["name"].str(); name != nil {
				if _, exists := out[*name]; !exists {
					out[*name] = proxyItem(*name, p)
				}
			}
		}
	}
	return out, true
}

func proxyItem(name string, p jsonObject) ProxyItem {
	history := p["history"].array()
	item := ProxyItem{Name: name, Type: valueOrZero(p["type"].str()), Now: p["now"].str(), All: p["all"].strings(), Tested: len(history) != 0, Alive: true}
	if item.Tested {
		if delay := history[len(history)-1].obj()["delay"].int(); delay != nil && *delay > 0 {
			item.LastDelay = delay
		}
	}
	if alive, ok := p["alive"].bool(); ok {
		item.Alive = alive
	}
	return item
}

func ParseConnections(text string) (*ConnectionsSnapshot, bool) {
	o := parseJSONObject(text)
	if o == nil {
		return nil, false
	}
	return connectionsFromJSON(o), true
}

func connectionsFromJSON(o jsonObject) *ConnectionsSnapshot {
	out := &ConnectionsSnapshot{
		Connections: []Connection{}, UploadTotal: o["uploadTotal"].long(), DownloadTotal: o["downloadTotal"].long(),
	}
	for _, value := range o["connections"].array() {
		c := value.obj()
		id := valueOrZero(c["id"].str())
		if id == "" {
			continue
		}
		m := c["metadata"].obj()
		host := valueOrZero(m["host"].str())
		if host == "" {
			host = valueOrZero(m["sniffHost"].str())
		}
		port := m["destinationPort"].str()
		if port == nil {
			if n := m["destinationPort"].int(); n != nil {
				text := strconv.Itoa(*n)
				port = &text
			}
		}
		chains := c["chains"].strings()
		var leaf string
		if len(chains) != 0 {
			leaf = chains[0]
		}
		chains = slices.DeleteFunc(chains, func(name string) bool { return strings.HasPrefix(name, GroupInternalPrefix) })
		slices.Reverse(chains)
		var rules []string
		for _, key := range []string{"rule", "rulePayload"} {
			if rule := valueOrZero(c[key].str()); rule != "" {
				rules = append(rules, rule)
			}
		}
		var start *int64
		if t, err := time.Parse(time.RFC3339Nano, valueOrZero(c["start"].str())); err == nil {
			ms := t.UnixMilli()
			start = &ms
		}
		out.Connections = append(out.Connections, Connection{
			ID: id, Host: host, Destination: valueOrZero(m["destinationIP"].str()) + ":" + valueOrZero(port),
			Network: strings.ToUpper(valueOrZero(m["network"].str())), Chain: strings.Join(chains, " → "),
			Rule: strings.Join(rules, " · "), Upload: c["upload"].long(), Download: c["download"].long(), Start: start, Leaf: leaf,
		})
	}
	return out
}

// time reads only while a response body is in use, so idle connections stay reusable
type idleBodyReader struct {
	io.Reader
	timeout time.Duration
	cancel  context.CancelFunc
}

func (r idleBodyReader) Read(p []byte) (int, error) {
	timer := time.AfterFunc(r.timeout, r.cancel)
	defer timer.Stop()
	return r.Reader.Read(p)
}

func newTransport(connect, read time.Duration) *http.Transport {
	dialer := &net.Dialer{Timeout: connect, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext:       dialer.DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 5, IdleConnTimeout: 5 * time.Minute,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: read,
	}
}

type oneAttemptTransport struct {
	base   http.RoundTripper
	cancel context.CancelFunc
}

func (t oneAttemptTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var attempts atomic.Int32
	trace := &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			if attempts.Add(1) > 1 {
				t.cancel()
			}
		},
	}
	resp, err := t.base.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if resp != nil && attempts.Load() > 1 {
		resp.Body.Close()
		return nil, context.Canceled
	}
	return resp, err
}

// report an interrupted connection as a failure even when net/http attempts an automatic replay
func doWithoutReplay(client *http.Client, req *http.Request, cancel context.CancelFunc) (*http.Response, error) {
	call := *client
	call.Transport = oneAttemptTransport{base: client.Transport, cancel: cancel}
	return call.Do(req)
}

func requestContext(ctx context.Context, timeoutMs int64) (context.Context, context.CancelFunc, bool) {
	if ctx == nil || timeoutMs < 0 || timeoutMs > math.MaxInt64/int64(time.Millisecond) {
		return nil, nil, false
	}
	if timeoutMs == 0 {
		ctx, cancel := context.WithCancel(ctx)
		return ctx, cancel, true
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	return ctx, cancel, true
}

type ProxiedFetcher struct {
	user, password string
	mu             sync.Mutex
	clients        map[int]*fetchClient
}

type fetchClient struct {
	client   *http.Client
	lifetime context.Context
	cancel   context.CancelFunc
}

func NewProxiedFetcher(user, password string) *ProxiedFetcher {
	return &ProxiedFetcher{user: user, password: password}
}

func proxyKey(port *int) (int, bool) {
	if port == nil {
		return 0, true
	}
	return *port, *port > 0 && *port <= 65535
}

func (f *ProxiedFetcher) client(port int) *fetchClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	if client := f.clients[port]; client != nil {
		return client
	}
	if f.clients == nil {
		f.clients = make(map[int]*fetchClient)
	}
	transport := newTransport(10*time.Second, 10*time.Second)
	transport.MaxConnsPerHost = 1
	transport.MaxIdleConnsPerHost = 1
	if port != 0 {
		proxy := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			User: url.UserPassword(latin1(f.user), latin1(f.password))}
		transport.Proxy = http.ProxyURL(proxy)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	c := &fetchClient{client: &http.Client{Transport: transport}, lifetime: lifetime, cancel: cancel}
	f.clients[port] = c
	return c
}

func latin1(s string) string {
	var out strings.Builder
	for _, ch := range s {
		if ch > 255 {
			ch = '?'
		}
		out.WriteByte(byte(ch))
	}
	return out.String()
}

func (f *ProxiedFetcher) Reset(_ context.Context, port *int) {
	key, ok := proxyKey(port)
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.clients[key]; c != nil {
		delete(f.clients, key)
		c.cancel()
		c.client.CloseIdleConnections()
	}
}

func (f *ProxiedFetcher) ResetAll(_ context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.clients {
		c.client.CloseIdleConnections()
	}
	clear(f.clients)
}

type FetchResult struct {
	Code    int
	Body    []byte
	Headers map[string]string
}

func (f *ProxiedFetcher) Fetch(ctx context.Context, target string, port *int, timeoutMs int64, maxBytes int, headers map[string]string) (*FetchResult, bool) {
	key, ok := proxyKey(port)
	if !ok || maxBytes < 0 || f == nil {
		return nil, false
	}
	ctx, cancel, ok := requestContext(ctx, timeoutMs)
	if !ok {
		return nil, false
	}
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") || req.URL.Hostname() == "" {
		return nil, false
	}
	req.Header.Set("Cache-Control", "no-cache")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := f.client(key)
	if client.lifetime.Err() != nil {
		return nil, false
	}
	stop := context.AfterFunc(client.lifetime, cancel)
	defer stop()
	response, err := doWithoutReplay(client.client, req, cancel)
	if err != nil {
		return nil, false
	}
	defer response.Body.Close()

	limit := int64(maxBytes)
	if response.ContentLength > limit {
		return nil, false
	}
	if limit < math.MaxInt64 {
		limit++
	}
	body, err := io.ReadAll(io.LimitReader(idleBodyReader{response.Body, 10 * time.Second, cancel}, limit))
	if err != nil || len(body) > maxBytes {
		return nil, false
	}
	out := &FetchResult{Code: response.StatusCode, Body: body, Headers: make(map[string]string)}
	for k := range response.Header {
		values := response.Header.Values(k)
		if len(values) != 0 {
			out.Headers[strings.ToLower(k)] = values[len(values)-1]
		}
	}
	return out, true
}

func (f *ProxiedFetcher) text(ctx context.Context, target string, port int, timeoutMs int64) (string, bool) {
	r, ok := f.Fetch(ctx, target, &port, timeoutMs, traceMaxBytes, nil)
	if !ok || r.Code != http.StatusOK {
		return "", false
	}
	return strings.ToValidUTF8(string(r.Body), "\uFFFD"), true
}

func (f *ProxiedFetcher) Heartbeat(ctx context.Context, port int, timeoutMs int64) (*ExitTrace, bool) {
	if text, ok := f.text(ctx, CloudflareTraceURL, port, timeoutMs); ok {
		trace := ParseCloudflareTrace(text)
		return trace, trace != nil
	}
	return nil, false
}

func (f *ProxiedFetcher) IPInfo(ctx context.Context, port int, timeoutMs int64) (*ExitTrace, bool) {
	if timeoutMs < 200 {
		return nil, false
	}
	if text, ok := f.text(ctx, IPInfoURL, port, timeoutMs); ok {
		trace := ParseJSONTrace(text)
		return trace, trace != nil
	}
	return nil, false
}

func (f *ProxiedFetcher) ExitTrace(ctx context.Context, port int) (*ExitTrace, bool) {
	if trace, ok := f.Heartbeat(ctx, port, 6000); ok {
		return trace, true
	}
	return f.IPInfo(ctx, port, 6000)
}

func (f *ProxiedFetcher) ResolveDirect(ctx context.Context, name string, port int) ([]string, bool) {
	q := url.Values{"name": {name}, "type": {"1"}}
	text, ok := f.text(ctx, "https://223.5.5.5/resolve?"+q.Encode(), port, 5000)
	if !ok {
		return nil, false
	}
	o := parseJSONObject(text)
	if o == nil {
		return nil, false
	}
	out := []string{}
	for _, value := range o["Answer"].array() {
		answer := value.obj()
		if valueOrZero(answer["type"].int()) == 1 {
			if data := answer["data"].str(); data != nil {
				out = append(out, *data)
			}
		}
	}
	return out, true
}
