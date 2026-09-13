package tunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

const testKey = "tunnel-key"

// ---- the relay, faked --------------------------------------------------

// fakeRelay is the far half of the tunnel: it accepts the WebSocket, runs the
// yamux server, answers the hello, and then opens one stream per request the
// way the real relay's RoundTripper does.
type fakeRelay struct {
	srv      *httptest.Server
	sessions chan *relaySession
	refuse   atomic.Value // string: an error reason to answer hello with
}

type relaySession struct {
	sess  *yamux.Session
	hello Frame
	mu    sync.Mutex
	enc   *json.Encoder
	// frames carries what the daemon reports after the handshake, which in
	// phase 1 is the state of the app it is sharing.
	frames chan Frame
}

func newFakeRelay(t *testing.T) *fakeRelay {
	t.Helper()
	fr := &fakeRelay{sessions: make(chan *relaySession, 8)}
	mux := http.NewServeMux()
	mux.HandleFunc(Path, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		nc := websocket.NetConn(ctx, c, websocket.MessageBinary)
		sess, err := yamux.Server(nc, yamuxConfig())
		if err != nil {
			return
		}
		defer sess.Close()
		ctrl, err := sess.AcceptStream()
		if err != nil {
			return
		}
		// One decoder for the life of the stream: a second one could swallow
		// frames the first had already buffered.
		dec := json.NewDecoder(ctrl)
		var hello Frame
		if err := dec.Decode(&hello); err != nil {
			return
		}
		enc := json.NewEncoder(ctrl)
		if reason, _ := fr.refuse.Load().(string); reason != "" {
			_ = enc.Encode(Frame{Type: FrameError, Reason: reason, Message: "refused"})
			// Hold the connection open until the client has read the frame and
			// closed; returning here would race the close against the frame.
			select {
			case <-sess.CloseChan():
			case <-time.After(10 * time.Second):
			}
			return
		}
		if err := enc.Encode(Frame{
			Type: FrameWelcome, Version: ProtocolVersion, URL: "https://share.test"}); err != nil {
			return
		}
		rs := &relaySession{sess: sess, hello: hello, enc: enc, frames: make(chan Frame, 32)}
		go func() {
			for {
				var f Frame
				if err := dec.Decode(&f); err != nil {
					close(rs.frames)
					return
				}
				select {
				case rs.frames <- f:
				default: // a test that is not reading must not block the stream
				}
			}
		}()
		select {
		case fr.sessions <- rs:
		default:
		}
		<-sess.CloseChan()
	})
	fr.srv = httptest.NewServer(mux)
	t.Cleanup(fr.srv.Close)
	return fr
}

func (fr *fakeRelay) wait(t *testing.T) *relaySession {
	t.Helper()
	select {
	case rs := <-fr.sessions:
		return rs
	case <-time.After(20 * time.Second):
		t.Fatal("no daemon connected to the relay")
		return nil
	}
}

func (rs *relaySession) send(t *testing.T, f Frame) {
	t.Helper()
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if err := rs.enc.Encode(f); err != nil {
		t.Errorf("sending a %s frame: %v", f.Type, err)
	}
}

// exchange is the relay's data path in miniature: one stream, the request
// written onto it, the response read back off it.
func (rs *relaySession) exchange(t *testing.T, req *http.Request) (*http.Response, *bufio.Reader, *yamux.Stream) {
	t.Helper()
	stream, err := rs.sess.OpenStream()
	if err != nil {
		t.Fatalf("opening a stream: %v", err)
	}
	go func() { _ = req.Write(stream) }()
	br := bufio.NewReader(stream)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	return resp, br, stream
}

func (rs *relaySession) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://share.test"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, stream := rs.exchange(t, req)
	defer stream.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body of %s: %v", path, err)
	}
	return resp, string(body)
}

// ---- the app on this machine -------------------------------------------

type appControls struct {
	release  chan struct{}
	gotFirst chan struct{}
	sseDone  atomic.Bool
}

func newAppControls() *appControls {
	return &appControls{release: make(chan struct{}), gotFirst: make(chan struct{})}
}

const trickleTotal = 16 << 20

// newApp is the dev server being shared.
func newApp(t *testing.T, ctl *appControls) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from the app")
	})

	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"host":  r.Host,
			"xfh":   r.Header.Get("X-Forwarded-Host"),
			"xfp":   r.Header.Get("X-Forwarded-Proto"),
			"xff":   r.Header.Get("X-Forwarded-For"),
			"agent": r.Header.Get("User-Agent"),
		})
	})

	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		ctl.sseDone.Store(false)
		w.Header().Set("Content-Type", "text/event-stream")
		rc := http.NewResponseController(w)
		fmt.Fprint(w, "data: one\n\n")
		if err := rc.Flush(); err != nil {
			t.Errorf("flushing: %v", err)
		}
		select {
		case <-ctl.release:
		case <-time.After(15 * time.Second):
			t.Error("the SSE handler was never released")
		}
		fmt.Fprint(w, "data: two\n\n")
		_ = rc.Flush()
		ctl.sseDone.Store(true)
	})

	mux.HandleFunc("/trickle", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(trickleTotal))
		chunk := make([]byte, 1<<20)
		for i := range chunk {
			chunk[i] = 'a'
		}
		if _, err := w.Write(chunk); err != nil {
			return
		}
		_ = http.NewResponseController(w).Flush()
		select {
		case <-ctl.release:
		case <-time.After(15 * time.Second):
			t.Error("the trickle handler was never released")
			return
		}
		for i := 0; i < (trickleTotal>>20)-1; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})

	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		first := make([]byte, 1<<20)
		if _, err := io.ReadFull(r.Body, first); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		close(ctl.gotFirst)
		rest, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "%d", int64(len(first))+rest)
	})

	// The dev server's live-reload socket, in miniature: the 101 and the first
	// payload go out in one write, and the bytes the visitor sent alongside
	// the request have to arrive too.
	mux.HandleFunc("/upgrade", func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijacking in the app: %v", err)
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: test-echo\r\nConnection: Upgrade\r\n\r\nGREETING")); err != nil {
			return
		}
		early := make([]byte, len("EARLY"))
		if _, err := io.ReadFull(brw, early); err != nil {
			t.Errorf("reading the bytes sent with the request: %v", err)
			return
		}
		if string(early) != "EARLY" {
			t.Errorf("the bytes sent with the request arrived as %q", early)
		}
		_, _ = io.Copy(conn, brw)
	})

	mux.HandleFunc("/echo/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Path[len("/echo/"):])
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func appPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// ---- running the client ------------------------------------------------

type running struct {
	statuses chan Status
	// finished is closed when Run returns; err is only read after that, so
	// both the test and the cleanup can wait for the same result.
	finished chan struct{}
	err      error
	cancel   context.CancelFunc
}

func runClient(t *testing.T, fr *fakeRelay, cfg Config) *running {
	t.Helper()
	if cfg.RelayURL == "" {
		cfg.RelayURL = fr.srv.URL
	}
	if cfg.Key == "" {
		cfg.Key = testKey
	}
	if cfg.LocalHost == "" {
		cfg.LocalHost = "127.0.0.1"
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = 20 * time.Millisecond
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 200 * time.Millisecond
	}
	statuses := make(chan Status, 64)
	cfg.OnStatus = func(s Status) {
		select {
		case statuses <- s:
		default:
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{statuses: statuses, finished: make(chan struct{}), cancel: cancel}
	go func() {
		r.err = Run(ctx, cfg)
		close(r.finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.finished:
		case <-time.After(20 * time.Second):
			t.Error("Run did not return")
		}
	})
	return r
}

func (r *running) waitState(t *testing.T, want State) Status {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case s := <-r.statuses:
			if s.State == want {
				return s
			}
		case <-deadline:
			t.Fatalf("the client never reached %s", want)
		}
	}
}

func (r *running) waitDone(t *testing.T) error {
	t.Helper()
	select {
	case <-r.finished:
		return r.err
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

// ---- the tests ---------------------------------------------------------

// A dev server refuses a Host it does not know — Vite answers "Blocked
// request. This host is not allowed" — so the daemon rewrites Host to the
// address the app is actually listening on and preserves what the visitor
// asked for in X-Forwarded-Host.
func TestForwardsARequestWithTheHostRewritten(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	port := appPort(t, app)
	run := runClient(t, fr, Config{LocalPort: port})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	if rs.hello.Type != FrameHello || rs.hello.Version != ProtocolVersion {
		t.Errorf("hello was %+v", rs.hello)
	}

	resp, body := rs.get(t, "/hello")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status is %d, want 200", resp.StatusCode)
	}
	if body != "hello from the app" {
		t.Errorf("body is %q", body)
	}

	// ReverseProxy sends an empty User-Agent rather than none when the visitor
	// had none, and that is what the relay puts on the wire; the daemon must
	// not put a Go user agent back on.
	hreq, _ := http.NewRequest(http.MethodGet, "http://share.test/headers", nil)
	hreq.Header["User-Agent"] = []string{""}
	hresp, _, hstream := rs.exchange(t, hreq)
	rawBody, err := io.ReadAll(hresp.Body)
	if err != nil {
		t.Fatalf("reading /headers: %v", err)
	}
	hstream.Close()
	raw := string(rawBody)
	var got map[string]string
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decoding %q: %v", raw, err)
	}
	wantHost := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if got["host"] != wantHost {
		t.Errorf("the app saw Host %q, want %q", got["host"], wantHost)
	}
	if got["xfh"] != "share.test" {
		t.Errorf("X-Forwarded-Host is %q, want the share's own hostname", got["xfh"])
	}
	if got["xfp"] != "https" {
		t.Errorf("X-Forwarded-Proto is %q, want https", got["xfp"])
	}
	if got["agent"] != "" {
		t.Errorf("User-Agent is %q; a request that had none should still have none", got["agent"])
	}
}

// The relay is the only end that knows who the visitor is, so what it sets
// stands.
func TestKeepsTheRelaysForwardedHeaders(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app)})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	req, _ := http.NewRequest(http.MethodGet, "http://share.test/headers", nil)
	req.Header.Set("X-Forwarded-Host", "share.trysonar.dev")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	resp, _, stream := rs.exchange(t, req)
	defer stream.Close()
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got["xfh"] != "share.trysonar.dev" || got["xfp"] != "http" || got["xff"] != "203.0.113.9" {
		t.Errorf("the daemon overwrote the relay's headers: %+v", got)
	}
}

func TestStreamsEventsAsTheyAreWritten(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app)})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	req, _ := http.NewRequest(http.MethodGet, "http://share.test/sse", nil)
	resp, _, stream := rs.exchange(t, req)
	defer stream.Close()

	first := make([]byte, len("data: one\n\n"))
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatalf("reading the first event: %v", err)
	}
	if string(first) != "data: one\n\n" {
		t.Errorf("first event is %q", first)
	}
	if ctl.sseDone.Load() {
		t.Error("the first event only arrived after the handler finished; it was buffered")
	}
	close(ctl.release)
	second := make([]byte, len("data: two\n\n"))
	if _, err := io.ReadFull(resp.Body, second); err != nil {
		t.Fatalf("reading the second event: %v", err)
	}
	if string(second) != "data: two\n\n" {
		t.Errorf("second event is %q", second)
	}
}

func TestDoesNotBufferALargeResponse(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app)})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	req, _ := http.NewRequest(http.MethodGet, "http://share.test/trickle", nil)
	resp, _, stream := rs.exchange(t, req)
	defer stream.Close()

	// The app holds the remaining 15 MB until this first megabyte lands, so a
	// daemon that buffered would deadlock here rather than quietly pass.
	head := make([]byte, 1<<20)
	if _, err := io.ReadFull(resp.Body, head); err != nil {
		t.Fatalf("reading the first megabyte: %v", err)
	}
	close(ctl.release)
	rest, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("reading the rest: %v", err)
	}
	if total := int64(len(head)) + rest; total != trickleTotal {
		t.Errorf("got %d bytes, want %d", total, trickleTotal)
	}
}

func TestDoesNotBufferALargeRequest(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app)})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	pr, pw := io.Pipe()
	go func() {
		chunk := make([]byte, 1<<20)
		if _, err := pw.Write(chunk); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		select {
		case <-ctl.gotFirst:
		case <-time.After(15 * time.Second):
			_ = pw.CloseWithError(errors.New("the app never read the first megabyte"))
			return
		}
		for i := 0; i < 15; i++ {
			if _, err := pw.Write(chunk); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
		}
		_ = pw.Close()
	}()

	req, _ := http.NewRequest(http.MethodPost, "http://share.test/upload", pr)
	resp, _, stream := rs.exchange(t, req)
	defer stream.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status is %d: %s", resp.StatusCode, body)
	}
	if string(body) != fmt.Sprint(16<<20) {
		t.Errorf("the app read %s bytes, want %d", body, 16<<20)
	}
}

// The splice is what makes an upgrade transparent: after the request headers
// the daemon parses nothing, so payload in the same packet as the request goes
// through, and so does payload in the same packet as the 101.
func TestUpgradeCarriesBytesBufferedWithTheHandshake(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app)})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	stream, err := rs.sess.OpenStream()
	if err != nil {
		t.Fatalf("opening a stream: %v", err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("GET /upgrade HTTP/1.1\r\nHost: share.test\r\n" +
		"Connection: Upgrade\r\nUpgrade: test-echo\r\n\r\nEARLY")); err != nil {
		t.Fatalf("writing the upgrade request: %v", err)
	}

	br := bufio.NewReader(stream)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading the upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status is %d, want 101", resp.StatusCode)
	}
	greeting := make([]byte, len("GREETING"))
	if _, err := io.ReadFull(br, greeting); err != nil {
		t.Fatalf("reading the payload that came with the 101: %v", err)
	}
	if string(greeting) != "GREETING" {
		t.Errorf("payload is %q, want GREETING", greeting)
	}
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("writing after the upgrade: %v", err)
	}
	back := make([]byte, 4)
	if _, err := io.ReadFull(br, back); err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	if string(back) != "ping" {
		t.Errorf("echo is %q", back)
	}
}

func TestForwardsConcurrentRequests(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app)})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			want := strconv.Itoa(i)
			req, err := http.NewRequest(http.MethodGet, "http://share.test/echo/"+want, nil)
			if err != nil {
				errs <- err
				return
			}
			stream, err := rs.sess.OpenStream()
			if err != nil {
				errs <- err
				return
			}
			defer stream.Close()
			go func() { _ = req.Write(stream) }()
			resp, err := http.ReadResponse(bufio.NewReader(stream), req)
			if err != nil {
				errs <- err
				return
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errs <- err
				return
			}
			if string(body) != want {
				errs <- fmt.Errorf("request %s came back as %q", want, body)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// A dropped control connection is not the end of a share: the client goes back
// to connecting and comes back.
func TestReconnectsAfterTheConnectionDrops(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app)})
	run.waitState(t, StateConnected)
	first := fr.wait(t)

	_ = first.sess.Close() // the laptop's network drops

	run.waitState(t, StateConnecting)
	run.waitState(t, StateConnected)
	second := fr.wait(t)
	if _, body := second.get(t, "/hello"); body != "hello from the app" {
		t.Errorf("the reconnected tunnel returned %q", body)
	}
}

// A relay restart: the daemon reconnects on the hint it was given, and the
// connection that is going away still serves what it already has.
func TestGoingAwayReconnectsAndKeepsServingInFlight(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app)})
	run.waitState(t, StateConnected)
	old := fr.wait(t)

	old.send(t, Frame{Type: FrameGoingAway, Reason: GoingAwayShutdown, RetryAfterMS: 20})

	run.waitState(t, StateConnecting)
	run.waitState(t, StateConnected)
	fresh := fr.wait(t)

	// The old connection is still good for a request in flight.
	if _, body := old.get(t, "/hello"); body != "hello from the app" {
		t.Errorf("the going-away connection stopped serving: %q", body)
	}
	if _, body := fresh.get(t, "/hello"); body != "hello from the app" {
		t.Errorf("the new connection returned %q", body)
	}
}

// Being replaced is terminal. Reconnecting would take the share back from the
// daemon that just took it, and the two would do that forever.
func TestGoingAwayReplacedStopsTheClient(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app)})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	rs.send(t, Frame{Type: FrameGoingAway, Reason: GoingAwayReplaced})
	if err := run.waitDone(t); !errors.Is(err, ErrReplaced) {
		t.Errorf("Run returned %v, want ErrReplaced", err)
	}
}

// A wrong key cannot be fixed by trying again, so it stops rather than
// hammering the relay.
func TestARefusedKeyStopsTheClient(t *testing.T) {
	fr := newFakeRelay(t)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app), Key: "wrong"})
	if err := run.waitDone(t); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("Run returned %v, want ErrUnauthorized", err)
	}
}

func TestAnUnsupportedVersionStopsTheClient(t *testing.T) {
	fr := newFakeRelay(t)
	fr.refuse.Store(ErrReasonUnsupportedVersion)
	ctl := newAppControls()
	app := newApp(t, ctl)
	run := runClient(t, fr, Config{LocalPort: appPort(t, app)})
	if err := run.waitDone(t); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("Run returned %v, want ErrUnsupportedVersion", err)
	}
}

// The commonest failure of all: the dev server was stopped and the share was
// not. The visitor gets a sentence, not a reset connection.
func TestSaysSoWhenTheAppIsNotRunning(t *testing.T) {
	fr := newFakeRelay(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // nothing is listening there now

	run := runClient(t, fr, Config{LocalPort: port})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	resp, body := rs.get(t, "/hello")
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status is %d, want 502", resp.StatusCode)
	}
	if !strings.Contains(body, "Nothing is listening") {
		t.Errorf("body is %q", body)
	}
}
