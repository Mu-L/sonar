package tunnel

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// The relay holds the other half of this protocol in a separate, private
// repository, and neither can import the other. testdata/tunnel-frames.ndjson
// is checked in to both, byte for byte: it is the wire, literally, one frame
// per line as the encoder writes it.
//
// If this test fails, the wire changed. Change the fixture in BOTH
// repositories, or put the field back.
func TestFramesMatchTheSharedFixture(t *testing.T) {
	frames := []Frame{
		{Type: FrameHello, Version: ProtocolVersion, Client: "sonar/v0.7.0"},
		{Type: FrameWelcome, Version: ProtocolVersion, URL: "https://share.trysonar.dev"},
		{Type: FrameStatus, State: ServiceDegraded},
		{Type: FrameStatus, State: ServiceLive},
		{Type: FrameGoingAway, Reason: GoingAwayShutdown, RetryAfterMS: 2000},
		{Type: FrameGoingAway, Reason: GoingAwayReplaced},
		{Type: FrameGoingAway, Reason: GoingAwayServiceGone},
		{Type: FrameError, Reason: ErrReasonUnsupportedVersion,
			Message: "this relay speaks tunnel protocol 1"},
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, f := range frames {
		if err := enc.Encode(f); err != nil {
			t.Fatalf("encoding %s: %v", f.Type, err)
		}
	}

	want, err := os.ReadFile("testdata/tunnel-frames.ndjson")
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("the control frames no longer match the shared fixture.\n got:\n%s\nwant:\n%s",
			buf.String(), want)
	}

	dec := json.NewDecoder(bytes.NewReader(want))
	for i, w := range frames {
		var got Frame
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("decoding frame %d: %v", i, err)
		}
		if got != w {
			t.Errorf("frame %d round-tripped to %+v, want %+v", i, got, w)
		}
	}
}

// The path and the version are the same contract as the frames.
func TestPathAndVersionAreFixed(t *testing.T) {
	if Path != "/v1/tunnel" {
		t.Errorf("Path is %q; the relay serves /v1/tunnel", Path)
	}
	if ProtocolVersion != 1 {
		t.Errorf("ProtocolVersion is %d, want 1", ProtocolVersion)
	}
}

func TestControlURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		bad      bool
	}{
		{in: "https://relay.trysonar.dev", want: "wss://relay.trysonar.dev/v1/tunnel"},
		{in: "http://127.0.0.1:8788", want: "ws://127.0.0.1:8788/v1/tunnel"},
		{in: "http://127.0.0.1:8788/", want: "ws://127.0.0.1:8788/v1/tunnel"},
		{in: "wss://relay.trysonar.dev/v1/tunnel", want: "wss://relay.trysonar.dev/v1/tunnel"},
		{in: "ws://127.0.0.1:8788/custom", want: "ws://127.0.0.1:8788/custom"},
		{in: "", bad: true},
		{in: "relay.trysonar.dev", bad: true},
		{in: "ftp://relay.trysonar.dev", bad: true},
	} {
		got, err := ControlURL(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("ControlURL(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ControlURL(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ControlURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Backoff doubles to a ceiling, and jitter keeps every wait inside the upper
// half of the window — so a relay coming back finds its daemons spread out
// rather than arriving together.
func TestBackoffAndJitter(t *testing.T) {
	c, err := newClient(Config{RelayURL: "http://relay.test", Key: "k", LocalPort: 5173,
		MinBackoff: 100 * time.Millisecond, MaxBackoff: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for attempt, want := range map[int]time.Duration{
		0: 100 * time.Millisecond,
		1: 200 * time.Millisecond,
		2: 400 * time.Millisecond,
		3: 800 * time.Millisecond,
		4: time.Second,
		9: time.Second,
	} {
		if got := c.backoff(attempt); got != want {
			t.Errorf("backoff(%d) = %v, want %v", attempt, got, want)
		}
	}
	for i := 0; i < 200; i++ {
		d := jitter(time.Second)
		if d < 500*time.Millisecond || d > time.Second {
			t.Fatalf("jitter(1s) = %v, outside [500ms, 1s]", d)
		}
	}
	if got := jitter(0); got != 0 {
		t.Errorf("jitter(0) = %v", got)
	}
}

func TestRunRejectsAnImpossibleConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no key":   {RelayURL: "http://relay.test", LocalPort: 5173},
		"no port":  {RelayURL: "http://relay.test", Key: "k"},
		"bad port": {RelayURL: "http://relay.test", Key: "k", LocalPort: 70000},
		"no relay": {Key: "k", LocalPort: 5173},
		"bad relay": {RelayURL: "not a url at all", Key: "k", LocalPort: 5173,
			LocalHost: "127.0.0.1"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newClient(cfg); err == nil {
				t.Error("the config was accepted")
			}
		})
	}
}
