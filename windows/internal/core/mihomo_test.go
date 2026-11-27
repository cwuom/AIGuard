package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMihomoAPIRequestsAndFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer controller-secret" {
			t.Error("missing controller bearer authentication")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.EscapedPath() {
		case "GET /api/version":
			fmt.Fprint(w, `{"version":"v1.2.3"}`)
		case "GET /api/proxies/%E8%8A%82%E7%82%B9%20A%2FB/delay", "GET /api/group/%E8%8A%82%E7%82%B9%20A%2FB/delay":
			if q := r.URL.Query(); q.Get("url") != TestURL || q.Get("timeout") != "1234" {
				t.Errorf("unexpected delay query %v", q)
			}
			fmt.Fprint(w, `{"delay":51,"bad":null}`)
		case "GET /api/proxies/offline":
			fmt.Fprint(w, `{"now":"JP 01","all":["JP 01",12],"alive":false}`)
		case "PUT /api/proxies/group":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["name"] != "节点 A/B" {
				t.Errorf("unexpected select body %v (%v)", body, err)
			}
			w.WriteHeader(http.StatusNoContent)
		case "PUT /api/configs":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || r.URL.Query().Get("force") != "true" {
				t.Errorf("unexpected reload request (%v)", err)
			}
			if body["path"] == `C:\runtime\valid.yaml` {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, strings.Repeat("坏", 320))
		case "PUT /api/providers/proxies/sub":
			w.WriteHeader(http.StatusNoContent)
		case "GET /api/providers/proxies/sub":
			fmt.Fprint(w, `{"proxies":[{},{}]}`)
		case "GET /api/proxies":
			fmt.Fprint(w, `{"proxies":{"DIRECT":{"type":"Direct"}}}`)
		case "GET /api/providers/proxies":
			fmt.Fprint(w, `{"providers":{"sub":{"proxies":[{"name":"JP 01","alive":true}]}}}`)
		case "GET /api/connections":
			fmt.Fprint(w, `{"uploadTotal":1,"downloadTotal":2}`)
		case "DELETE /api/connections/id%2Fx":
			w.WriteHeader(http.StatusNoContent)
		case "DELETE /api/connections":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	api := NewMihomoApi(server.URL+"/api/", "controller-secret")
	ctx := t.Context()
	version, ok := api.Version(ctx)
	want(t, ok, true)
	want(t, version, "v1.2.3")
	delay, ok := api.Delay(ctx, "节点 A/B", TestURL, 1234)
	want(t, ok, true)
	want(t, delay, 51)
	delays, ok := api.GroupDelay(ctx, "节点 A/B", TestURL, 1234)
	want(t, ok, true)
	want(t, delays, map[string]int{"delay": 51})
	group, ok := api.Group(ctx, "offline")
	want(t, ok, true)
	want(t, group, &GroupInfo{Now: ptr("JP 01"), All: []string{"JP 01"}})
	alive, ok := api.IsAlive(ctx, "offline")
	want(t, ok, true)
	want(t, alive, false)
	alive, ok = api.IsAlive(ctx, "absent")
	want(t, ok, false)
	want(t, alive, false)
	want(t, api.Select(ctx, "group", "节点 A/B"), true)
	want(t, api.ReloadProvider(ctx, "sub"), true)
	n, ok := api.ProviderCount(ctx, "sub")
	want(t, ok, true)
	want(t, n, 2)
	want(t, api.ReloadConfig(ctx, "bad"), false)
	want(t, api.LastReloadError(ctx), ptr(strings.Repeat("坏", 300)))
	want(t, api.ReloadConfig(ctx, `C:\runtime\valid.yaml`), true)
	want(t, api.LastReloadError(ctx), ptr(strings.Repeat("坏", 300)))
	proxies, ok := api.Proxies(ctx)
	want(t, ok, true)
	want(t, len(proxies), 2)
	want(t, proxies["JP 01"].Alive, true)
	connections, ok := api.Connections(ctx)
	want(t, ok, true)
	want(t, connections, &ConnectionsSnapshot{Connections: []Connection{}, UploadTotal: 1, DownloadTotal: 2})
	want(t, api.CloseConnection(ctx, "id/x"), true)
	want(t, api.FlushConnections(ctx), true)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	version, ok = api.Version(cancelled)
	want(t, version, "")
	want(t, ok, false)
	version, ok = NewMihomoApi("://invalid", "").Version(ctx)
	want(t, version, "")
	want(t, ok, false)
}

func testPort(t *testing.T, server *httptest.Server) int {
	t.Helper()
	_, p, err := net.SplitHostPort(server.Listener.Addr().String())
	want(t, err, nil)
	port, err := strconv.Atoi(p)
	want(t, err, nil)
	return port
}

func TestProxiedFetchAuthenticationAndResponseLimit(t *testing.T) {
	credential := "Basic " + base64.StdEncoding.EncodeToString([]byte("probe:pw"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Proxy-Authorization"); got != credential || r.URL.Host != "fixture.invalid" {
			t.Errorf("unexpected HTTP proxy authentication or target %q %q", got, r.URL.Host)
		}
		switch r.URL.Path {
		case "/small":
			if r.Header.Get("Cache-Control") != "no-cache" || r.Header.Get("User-Agent") != "fixture" {
				t.Error("fetch headers were not sent")
			}
			w.Header().Set("Profile-Title", "Fixture")
			w.WriteHeader(http.StatusAccepted)
			fmt.Fprint(w, "body")
		case "/known-limit":
			w.Header().Set("Content-Length", "5")
			fmt.Fprint(w, "12345")
		case "/chunked-limit":
			w.(http.Flusher).Flush()
			fmt.Fprint(w, "12345")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	port := testPort(t, server)
	f := NewProxiedFetcher("probe", "pw")
	t.Cleanup(func() { f.ResetAll(context.Background()) })
	ctx := t.Context()
	r, ok := f.Fetch(ctx, "http://fixture.invalid/small", &port, 1000, 4, map[string]string{"User-Agent": "fixture"})
	want(t, ok, true)
	want(t, r.Code, http.StatusAccepted)
	want(t, string(r.Body), "body")
	want(t, ProfileName(r.Headers), ptr("Fixture"))
	for _, path := range []string{"/known-limit", "/chunked-limit"} {
		r, ok := f.Fetch(ctx, "http://fixture.invalid"+path, &port, 1000, 4, nil)
		want(t, ok, false)
		want(t, r, nil)
	}
	r, ok = f.Fetch(ctx, "://invalid", &port, 1000, DefaultFetchMaxBytes, nil)
	want(t, ok, false)
	want(t, r, nil)
}

func TestHeartbeatReusesAuthenticatedTunnelUntilReset(t *testing.T) {
	var tunnels, heartbeats atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials reached the TLS origin")
		}
		switch r.Host + r.URL.Path {
		case "www.cloudflare.com/cdn-cgi/trace":
			if heartbeats.Add(1) == 4 {
				c, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				c.Close()
				return
			}
			fmt.Fprint(w, "ip=192.0.2.1\nloc=SG\n")
		case "ipinfo.io/json":
			fmt.Fprint(w, `{"ip":"192.0.2.2","country":"JP"}`)
		case "223.5.5.5/resolve":
			if q := r.URL.Query(); q.Get("name") != "a b.example.org" || q.Get("type") != "1" {
				t.Errorf("unexpected resolution query %v", q)
			}
			fmt.Fprint(w, `{"Answer":[{"type":1,"data":"192.0.2.1"},{"type":28,"data":"::1"},{"type":"1","data":"192.0.2.2"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(origin.Close)

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwdw==" {
			t.Error("expected authenticated CONNECT")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		switch r.Host {
		case "www.cloudflare.com:443":
			tunnels.Add(1)
		case "ipinfo.io:443", "223.5.5.5:443":
		default:
			t.Errorf("unexpected tunnel destination %s", r.Host)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		upstream, err := net.Dial("tcp", origin.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer client.Close()
		rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := rw.Flush(); err != nil {
			t.Error(err)
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(upstream, rw.Reader)
			upstream.Close()
		}()
		io.Copy(client, upstream)
		client.Close()
		<-done
	}))
	t.Cleanup(proxy.Close)
	port := testPort(t, proxy)
	f := NewProxiedFetcher("user", "pw")
	t.Cleanup(func() { f.ResetAll(context.Background()) })
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	originURL, err := url.Parse(origin.URL)
	want(t, err, nil)
	trustFixture := func() {
		transport := f.client(port).client.Transport.(*http.Transport)
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: originURL.Hostname()}
	}
	trustFixture()
	ctx := t.Context()
	for range 2 {
		trace, ok := f.Heartbeat(ctx, port, 2000)
		want(t, ok, true)
		want(t, trace, ptr(ExitTrace{"192.0.2.1", "SG"}))
	}
	want(t, tunnels.Load(), int32(1))
	want(t, heartbeats.Load(), int32(2))
	f.Reset(ctx, &port)
	trustFixture()
	trace, ok := f.ExitTrace(ctx, port)
	want(t, ok, true)
	want(t, trace, ptr(ExitTrace{"192.0.2.1", "SG"}))
	want(t, tunnels.Load(), int32(2))
	want(t, heartbeats.Load(), int32(3))
	trace, ok = f.IPInfo(ctx, port, 199)
	want(t, ok, false)
	want(t, trace, nil)
	trace, ok = f.IPInfo(ctx, port, 2000)
	want(t, ok, true)
	want(t, trace, ptr(ExitTrace{"192.0.2.2", "JP"}))
	addrs, ok := f.ResolveDirect(ctx, "a b.example.org", port)
	want(t, ok, true)
	want(t, addrs, []string{"192.0.2.1", "192.0.2.2"})

	trace, ok = f.Heartbeat(ctx, port, 2000)
	want(t, ok, false)
	want(t, trace, nil)
	trace, ok = f.Heartbeat(ctx, port, 2000)
	want(t, ok, true)
	want(t, trace, ptr(ExitTrace{"192.0.2.1", "SG"}))
}
