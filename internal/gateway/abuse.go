package gateway

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// errFreeTierIPBlocked reports that OpenCode's free gateway refused the request
// because it flagged the egress IP, not the request, the key or the session.
// Unlike the shape gates, another lane, key or retry cannot fix it: the same
// IP gets the same answer, and retrying only extends the penalty. The request
// must therefore leave the anonymous lane instead of walking its upstreams,
// and the exit must stay out of the cursor until the block expires.
var errFreeTierIPBlocked = errors.New("free tier blocked the egress IP")

// freeTierBlockedMessage is what a client receives while its exit is blocked.
// The upstream message tells people to turn off a VPN, which is wrong for a
// server that egresses through a proxy; this one names the real cause and the
// two ways out.
const freeTierBlockedMessage = "OpenCode is blocking free-model traffic from the IP this gateway leaves from, so retrying now cannot succeed. Route the request through another exit or wait for the block to expire."

// freeTierBlockTTL keeps a blocked exit out of the anonymous cursor. Upstream
// does not publish the block duration, so this is a conservative backoff: long
// enough to stop the retry storm, short enough that an unblocked IP recovers
// without a restart.
const freeTierBlockTTL = 15 * time.Minute

// freeTierBlockTTL returns the backoff applied to an exit the free tier flagged.
func (g *Gateway) freeTierBlockTTL() time.Duration {
	if g != nil && g.freeTierBlock > 0 {
		return g.freeTierBlock
	}
	return freeTierBlockTTL
}

// abuseProbeLimit bounds how much of a 403 body is read to classify it.
const abuseProbeLimit = 16 << 10

// isNetworkAbuseBlock reports whether status and body are the upstream's IP
// abuse rejection. The response is a 403 whose message names the egress
// network, in one of the wordings the gateway has been served:
//
//   - "…free models aren't available from your current network because we've
//     detected abusive traffic from this IP address…"
//   - "Forbidden, OpenCode Free Model Gateway Detect Abuse Traffic"
//   - "Abuse of traffic"
//
// The shape gate's 403 ("free tier can only be used from within OpenCode") is
// deliberately not matched: that one is a request-shape problem, which another
// lane or a refreshed body can still fix.
func isNetworkAbuseBlock(status int, body []byte) bool {
	if status != http.StatusForbidden {
		return false
	}
	text := strings.ToLower(string(body))
	if strings.Contains(text, "abusive traffic") ||
		strings.Contains(text, "abuse traffic") ||
		strings.Contains(text, "abuse of traffic") {
		return true
	}
	return strings.Contains(text, "free models aren't available") &&
		strings.Contains(text, "from your current network")
}

// peekNetworkAbuseBlock classifies a response without consuming its body:
// the bytes it reads are put back in front of the rest so downstream error
// handling, and a retry on another exit, still see the full payload.
func peekNetworkAbuseBlock(resp *http.Response) bool {
	if resp == nil || resp.Body == nil || resp.StatusCode != http.StatusForbidden {
		return false
	}
	prefix, err := io.ReadAll(io.LimitReader(resp.Body, abuseProbeLimit))
	if err != nil {
		// The body is unusable; restore what was read and let the ordinary
		// error path deal with the response.
		resp.Body = replayBody(prefix, resp.Body)
		return false
	}
	resp.Body = replayBody(prefix, resp.Body)
	return isNetworkAbuseBlock(resp.StatusCode, prefix)
}

// replayBody returns a body that yields prefix and then the rest of original.
func replayBody(prefix []byte, original io.ReadCloser) io.ReadCloser {
	return &prefixBody{Reader: io.MultiReader(bytes.NewReader(prefix), original), closer: original}
}

type prefixBody struct {
	io.Reader
	closer io.Closer
}

func (b *prefixBody) Close() error { return b.closer.Close() }
