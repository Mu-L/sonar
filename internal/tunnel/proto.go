// Package tunnel is the daemon's half of a share: it holds one outbound
// connection to the relay and answers, on the machine's behalf, the HTTP
// requests that arrive on the share's public address.
//
// The shape is one WebSocket to the relay's /v1/tunnel with
// [github.com/hashicorp/yamux] over it. The daemon is the yamux client and the
// relay the yamux server; the daemon opens one control stream and the relay
// opens one stream per inbound HTTP request. Nothing listens here: a laptop is
// behind NAT, so it dials out and the relay accepts.
//
// Only the client half lives in this repository. The relay is a separate,
// private service, and these few frame types are duplicated there rather than
// shared: the two are pinned by testdata/tunnel-frames.ndjson, which is
// checked in to both repositories byte for byte.
package tunnel

// Path is the relay route a daemon dials.
const Path = "/v1/tunnel"

// ProtocolVersion is the control protocol this client speaks.
const ProtocolVersion = 1

// Frame types on the control stream.
const (
	// FrameHello is the daemon's first frame.
	FrameHello = "hello"
	// FrameWelcome is the relay's answer: the share is live at URL.
	FrameWelcome = "welcome"
	// FrameGoingAway warns that the relay is about to close this connection.
	// In-flight requests keep being served until it does.
	FrameGoingAway = "going_away"
	// FrameError refuses a hello; the relay closes the connection after it.
	FrameError = "error"
)

// going_away reasons.
const (
	// GoingAwayShutdown: the relay is restarting. Reconnect after
	// RetryAfterMS, with jitter.
	GoingAwayShutdown = "shutdown"
	// GoingAwayReplaced: another daemon took this share. Do not reconnect, or
	// the two take it from each other forever.
	GoingAwayReplaced = "replaced"
)

// error reasons.
const (
	ErrReasonUnsupportedVersion = "unsupported_version"
	ErrReasonBadHello           = "bad_hello"
)

// Frame is one line on the control stream: newline-delimited JSON, one frame
// per line. Fields a frame type does not use are omitted from the wire.
type Frame struct {
	Type string `json:"type"`
	// Version is the protocol version, on hello and welcome.
	Version int `json:"version,omitempty"`
	// Client is what the daemon calls itself, on hello.
	Client string `json:"client,omitempty"`
	// URL is where the share is reachable, on welcome.
	URL string `json:"url,omitempty"`
	// Reason is machine-readable, on going_away and error.
	Reason string `json:"reason,omitempty"`
	// RetryAfterMS is how long to wait before reconnecting, on going_away.
	RetryAfterMS int64 `json:"retry_after_ms,omitempty"`
	// Message is for a person, on error.
	Message string `json:"message,omitempty"`
}
