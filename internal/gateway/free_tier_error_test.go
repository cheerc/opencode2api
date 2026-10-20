package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"opencode2api/internal/config"
	"opencode2api/internal/models"
	wire "opencode2api/internal/protocol"
)

// contextLengthBody is the free tier's answer when a request exceeds the
// model's context window. Retrying it on another key or tier cannot succeed.
const contextLengthBody = `{"error":{"message":"Your request resulted in more tokens than this model's maximum context length allows. Please reduce the length of the messages or run compaction.","type":"invalid_request_error","code":"context_length_exceeded"}}`

// respondClient answers every request with the given status and body.
func respondClient(counter *atomic.Int64, status int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		counter.Add(1)
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	})}
}

func keyedRoute() models.Route {
	route := testFreeRoute()
	route.KeyTiers = []config.Tier{config.TierZen}
	return route
}

// TestDoUpstreamTiersStopsAtContextLength pins that a deterministic client error
// ends the request: another key or tier cannot make an over-long context fit,
// and replaying it buries the real cause behind a later authentication error.
func TestDoUpstreamTiersStopsAtContextLength(t *testing.T) {
	var requests atomic.Int64
	g, transports := newBlockTestGateway(t, 1)
	attachTestClient(transports, 0, respondClient(&requests, http.StatusBadRequest, contextLengthBody))
	g.zenNodes = &upstreamNodes{transports: transports, nodes: []*upstreamNode{{key: "sk-zen"}}}

	resp, _, _, err := g.doUpstreamTiers(context.Background(), keyedRoute(), testBodies(), testRequestIDs(), 0)
	if err != nil {
		t.Fatalf("error = %v, want the upstream 400 returned as a response", err)
	}
	if resp == nil {
		t.Fatal("response = nil")
	}
	defer resp.Body.Close()
	if requests.Load() != 1 {
		t.Fatalf("upstream requests = %d, want 1 (no keyed retry of a deterministic 400)", requests.Load())
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "context_length_exceeded") {
		t.Fatalf("body = %q, want the upstream 400 body preserved", body)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// TestDoUpstreamTiersKeepsAuthErrorsRetryable pins the boundary of the rule
// above: a 401 can be specific to one key, so it must still reach the next key.
func TestDoUpstreamTiersKeepsAuthErrorsRetryable(t *testing.T) {
	var requests atomic.Int64
	g, transports := newBlockTestGateway(t, 1)
	attachTestClient(transports, 0, respondClient(&requests, http.StatusUnauthorized, `{"error":{"message":"Invalid credential"}}`))
	g.zenNodes = &upstreamNodes{transports: transports, nodes: []*upstreamNode{{key: "sk-zen"}}}
	g.cfg.Retry.MaxAttempts = 2

	resp, _, _, err := g.doUpstreamTiers(context.Background(), keyedRoute(), testBodies(), testRequestIDs(), 0)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if resp == nil {
		t.Fatal("response = nil")
	}
	_ = resp.Body.Close()
	if requests.Load() < 2 {
		t.Fatalf("upstream requests = %d, want a second key attempt after a 401", requests.Load())
	}
}

// TestIsDeterministicClientResponse pins the classification the rule uses.
func TestIsDeterministicClientResponse(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"context length", http.StatusBadRequest, contextLengthBody, true},
		{"generic invalid_request", http.StatusBadRequest, `{"error":{"type":"invalid_request_error","message":"messages: at least one message is required"}}`, true},
		{"validation error", http.StatusUnprocessableEntity, `{"error":{"type":"invalid_request_error","message":"bad shape"}}`, true},
		{"auth", http.StatusUnauthorized, `{"error":{"message":"Invalid credential"}}`, false},
		{"forbidden", http.StatusForbidden, ipAbuseBody, false},
		{"rate limit", http.StatusTooManyRequests, `{"error":{"message":"slow down"}}`, false},
		{"server", http.StatusInternalServerError, `{"error":{"message":"boom"}}`, false},
		{"empty body", http.StatusBadRequest, ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDeterministicClientResponse(tc.status, []byte(tc.body)); got != tc.want {
				t.Fatalf("isDeterministicClientResponse(%d, %q) = %v, want %v", tc.status, tc.body, got, tc.want)
			}
		})
	}
}

// TestCopyErrorResponseKeepsUpstreamStatus pins that the client sees the
// upstream status and message, so a 400 is not reported as a 401.
func TestCopyErrorResponseKeepsUpstreamStatus(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(contextLengthBody)),
	}
	recorder := httptest.NewRecorder()
	copyErrorResponse(recorder, wire.Chat, resp, "req_test")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "maximum context length") {
		t.Fatalf("body = %s, want the upstream message", recorder.Body.String())
	}
}
