package gateway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"opencode2api/internal/config"
	"opencode2api/internal/identity"
	"opencode2api/internal/models"
	wire "opencode2api/internal/protocol"
	"opencode2api/internal/rotation"
)

// ipAbuseBody is the response OpenCode's free gateway returns for an egress IP
// it has flagged. The gateway must recognise it instead of treating the 403 as
// a request-shape rejection that another key, lane or proxy can fix.
const ipAbuseBody = `{"type":"error","error":{"type":"FreeTierError","message":"OpenCode's free models aren't available from your current network because we've detected abusive traffic from this IP address. This isn't related to your account. If you're on a VPN or proxy, turn it off and try again, or subscribe to OpenCode Go at https://opencode.ai/go to keep building."}}`

func TestIsNetworkAbuseBlock(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"ip block", http.StatusForbidden, ipAbuseBody, true},
		{"short form", http.StatusForbidden, `{"error":{"message":"Forbidden, OpenCode Free Model Gateway Detect Abuse Traffic"}}`, true},
		{"abuse of traffic", http.StatusForbidden, `{"error":{"message":"Abuse of traffic"}}`, true},
		{"network wording", http.StatusForbidden, `{"error":{"message":"OpenCode's free models aren't available from your current network"}}`, true},
		{"shape gate", http.StatusForbidden, `{"type":"error","error":{"type":"FreeTierError","message":"OpenCode's free tier can only be used from within OpenCode"}}`, false},
		{"wrong status", http.StatusTooManyRequests, ipAbuseBody, false},
		{"empty", http.StatusForbidden, ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNetworkAbuseBlock(tc.status, []byte(tc.body)); got != tc.want {
				t.Fatalf("isNetworkAbuseBlock(%d, %q) = %v, want %v", tc.status, tc.body, got, tc.want)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// blockedClient simulates an egress the free tier has flagged: every request
// through it gets the IP abuse 403, whatever the upstream address.
func blockedClient(counter *atomic.Int64) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		counter.Add(1)
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(ipAbuseBody)),
			Request:    r,
		}, nil
	})}
}

// okClient accepts every request without touching the network.
func okClient(counter *atomic.Int64) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		counter.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    r,
		}, nil
	})}
}

// newBlockTestGateway builds the smallest Gateway the anonymous lane needs:
// healthy proxies whose clients the test replaces.
func newBlockTestGateway(t *testing.T, proxies int) (*Gateway, *proxyTransports) {
	t.Helper()
	transports := &proxyTransports{}
	for i := range proxies {
		transport := &proxyTransport{index: i, name: "direct"}
		transport.healthy.Store(true)
		transports.items = append(transports.items, transport)
	}
	return &Gateway{
		cfg:        config.Config{Retry: config.RetryConfig{MaxAttempts: 3, TimeoutSeconds: 30}},
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		transports: transports,
		zenNodes:   &upstreamNodes{transports: transports},
		anonymous:  anonymousPool(true, transports, 15*time.Second),
		catalog:    models.Catalog(config.TierZen, nil),
	}, transports
}

func testRequestIDs() identity.RequestIDs {
	return identity.RequestIDs{Session: "ses_test", Project: "opencode2api:test"}
}

func testFreeRoute() models.Route {
	return models.Route{ID: "deepseek-v4.1-flash-free", Tier: config.TierZen, Protocol: wire.Chat, Anonymous: true}
}

func testBodies() map[config.Tier][]byte {
	return map[config.Tier][]byte{config.TierZen: []byte(`{"model":"deepseek-v4.1-flash-free","stream":true,"messages":[{"role":"user","content":"hi"}]}`)}
}

func attachTestClient(transports *proxyTransports, index int, client *http.Client) {
	transports.items[index].client = client
	transports.items[index].bun = client
}

// TestDoAnonymousUpstreamStopsAfterIPTierBlock pins the contract that an IP
// abuse 403 is terminal for the request: the gateway must not try the second
// lane on the same egress (the same IP answers the same way) and must report
// the block distinctly from an ordinary upstream rejection.
func TestDoAnonymousUpstreamStopsAfterIPTierBlock(t *testing.T) {
	var requests atomic.Int64
	g, transports := newBlockTestGateway(t, 1)
	attachTestClient(transports, 0, blockedClient(&requests))

	resp, err, attempts := g.doAnonymousUpstream(context.Background(), testFreeRoute(), testBodies(), testRequestIDs(), 0)
	if !errors.Is(err, errFreeTierIPBlocked) {
		t.Fatalf("error = %v, want errFreeTierIPBlocked", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("upstream requests = %d, want 1 (the second lane must not retry the same egress)", requests.Load())
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("response = %v, want the upstream 403 returned to the caller", resp)
	}
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil || !strings.Contains(string(body), "abusive traffic") {
		t.Fatalf("response body = %q (err %v), want the upstream body intact", body, readErr)
	}
	_ = resp.Body.Close()

	// A later request must not hammer the same egress again.
	before := requests.Load()
	resp2, err2, attempts2 := g.doAnonymousUpstream(context.Background(), testFreeRoute(), testBodies(), testRequestIDs(), 0)
	if !errors.Is(err2, errFreeTierIPBlocked) {
		t.Fatalf("second call error = %v, want errFreeTierIPBlocked", err2)
	}
	if resp2 != nil {
		t.Fatalf("second call response = %v, want nil", resp2)
	}
	if attempts2 != 0 {
		t.Fatalf("second call attempts = %d, want 0", attempts2)
	}
	if requests.Load() != before {
		t.Fatalf("second call sent %d more upstream requests, want 0", requests.Load()-before)
	}
}

// TestDoAnonymousUpstreamServesHealthyProxyAfterBlock pins that the block is a
// property of one egress: another configured exit must still be able to serve
// the request.
func TestDoAnonymousUpstreamServesHealthyProxyAfterBlock(t *testing.T) {
	var blockedRequests, goodRequests atomic.Int64
	g, transports := newBlockTestGateway(t, 2)
	attachTestClient(transports, 0, blockedClient(&blockedRequests))
	attachTestClient(transports, 1, okClient(&goodRequests))
	// An empty session starts the cursor round-robin at the first proxy.
	resp, err, _ := g.doAnonymousUpstream(context.Background(), testFreeRoute(), testBodies(), identity.RequestIDs{Session: ""}, 0)
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("response = %v, err = %v, want a 200 from the second exit", resp, err)
	}
	_ = resp.Body.Close()
	if blockedRequests.Load() == 0 {
		t.Fatal("the blocked exit was never tried; the test did not exercise failover")
	}
	if goodRequests.Load() == 0 {
		t.Fatal("the healthy exit was never used")
	}
}

// TestAnonymousCursorSkipsBlockedProxy pins that a blocked egress is not
// reached through the cursor's cooldown fallback either: otherwise every
// client retry keeps hitting the flagged IP.
func TestAnonymousCursorSkipsBlockedProxy(t *testing.T) {
	transports := &proxyTransports{}
	for i, name := range []string{"blocked", "good"} {
		transport := &proxyTransport{index: i, name: name}
		transport.healthy.Store(true)
		transports.items = append(transports.items, transport)
	}
	pool := anonymousPool(true, transports, 15*time.Second)
	if len(pool.nodes) != 2 {
		t.Fatalf("anonymous nodes = %d, want 2", len(pool.nodes))
	}
	pool.nodes[0].proxy.markBlocked(time.Now().Add(time.Minute))

	cursor := pool.CursorFor("")
	first := cursor.Next()
	if first == nil || first.proxy != transports.items[1] {
		t.Fatalf("first node = %v, want the unblocked proxy", first)
	}
	if next := cursor.Next(); next != nil {
		t.Fatalf("second node = %v, want nil once only the blocked proxy remains", next)
	}
}

// TestDoAnonymousUpstreamCountsAttempts pins the attempt counter that feeds
// telemetry and the request budget. It used to stay at zero for every
// anonymous request.
func TestDoAnonymousUpstreamCountsAttempts(t *testing.T) {
	var requests atomic.Int64
	g, transports := newBlockTestGateway(t, 1)
	attachTestClient(transports, 0, okClient(&requests))

	resp, err, attempts := g.doAnonymousUpstream(context.Background(), testFreeRoute(), testBodies(), testRequestIDs(), 0)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if resp == nil {
		t.Fatal("response = nil")
	}
	_ = resp.Body.Close()
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

// TestDoUpstreamTiersStopsAtIPTierBlock pins that the block also ends the
// request: keyed tiers cannot help when the egress itself is flagged.
func TestDoUpstreamTiersStopsAtIPTierBlock(t *testing.T) {
	var requests atomic.Int64
	g, transports := newBlockTestGateway(t, 1)
	attachTestClient(transports, 0, blockedClient(&requests))
	g.zenNodes = &upstreamNodes{transports: transports, nodes: []*upstreamNode{{key: "sk-zen"}}}
	route := testFreeRoute()
	route.KeyTiers = []config.Tier{config.TierZen}

	_, _, _, err := g.doUpstreamTiers(context.Background(), route, testBodies(), testRequestIDs(), 0)
	if !errors.Is(err, errFreeTierIPBlocked) {
		t.Fatalf("error = %v, want errFreeTierIPBlocked", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("upstream requests = %d, want 1 (no keyed retry on a flagged egress)", requests.Load())
	}
}

// TestBlockedExitReturnsAfterTTL pins that the block is temporary: once the
// TTL passes the exit is usable again, so a fixed network recovers without a
// restart or a config reload.
func TestBlockedExitReturnsAfterTTL(t *testing.T) {
	transports := &proxyTransports{}
	transport := &proxyTransport{index: 0, name: "direct"}
	transport.healthy.Store(true)
	transports.items = append(transports.items, transport)
	pool := anonymousPool(true, transports, 15*time.Second)

	pool.nodes[0].proxy.markBlocked(time.Now().Add(-time.Second))
	cursor := pool.CursorFor("")
	if node := cursor.Next(); node == nil {
		t.Fatal("an expired block still kept the exit out of the cursor")
	}
}

// TestHandleInferenceAnswersBlockWithItsOwnStatus pins the client-visible
// contract: a blocked request is answered with the gateway's 503 and its own
// message, not the upstream 403 telling the reader to turn off a VPN.
func TestHandleInferenceAnswersBlockWithItsOwnStatus(t *testing.T) {
	var requests atomic.Int64
	g, transports := newBlockTestGateway(t, 1)
	attachTestClient(transports, 0, blockedClient(&requests))
	rotationManager, err := rotation.New("", config.RotationConfig{})
	if err != nil {
		t.Fatalf("rotation manager: %v", err)
	}
	g.rotation = rotationManager
	g.cfg.ServerKeys = []string{"sk-local"}
	g.cfg.Anonymous = true
	g.catalog = models.Catalog(config.TierZen, map[string]string{"deepseek-v4.1-flash-free": "chat"})

	body := `{"model":"deepseek-v4.1-flash-free","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-local")
	recorder := httptest.NewRecorder()
	g.handleInference(wire.Chat)(recorder, req)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "turn it off") {
		t.Fatalf("body still forwards the upstream advice: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "free_tier_ip_blocked") {
		t.Fatalf("body = %s, want the free_tier_ip_blocked error type", recorder.Body.String())
	}
}

// TestProbeAttemptReportsNetworkAbuseBlock pins the probe reason so operators
// can tell an egress block apart from a request-shape rejection in the WebUI
// and the availability file.
func TestProbeAttemptReportsNetworkAbuseBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, ipAbuseBody)
	}))
	defer srv.Close()

	g := &Gateway{}
	result := g.probeAttempt(context.Background(), srv.Client(), srv.URL, "public", "deepseek-v4.1-flash-free", wire.Chat, testRequestIDs(), "")
	if result.reason != "network_abuse_blocked" {
		t.Fatalf("probe reason = %q, want network_abuse_blocked", result.reason)
	}
	if !result.attempted || result.success {
		t.Fatalf("probe result = %+v, want attempted and unsuccessful", result)
	}
}
