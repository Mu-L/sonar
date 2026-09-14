package tunnel

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

// flappyApp is a local service that can be stopped and started again on the
// same port — a dev server being restarted, from the tunnel's point of view.
//
// It reclaims the same port deliberately: from outside, "the dev server came
// back" and "a different project just bound that port" are indistinguishable.
// That is exactly why the client does not resume after it has stopped.
type flappyApp struct {
	t    *testing.T
	mu   sync.Mutex
	port int
	srv  *http.Server
}

func newFlappyApp(t *testing.T) *flappyApp {
	t.Helper()
	a := &flappyApp{t: t}
	a.start()
	t.Cleanup(a.stop)
	return a
}

func (a *flappyApp) start() {
	a.t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	addr := "127.0.0.1:0"
	if a.port != 0 {
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(a.port))
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		a.t.Fatalf("starting the app on %s: %v", addr, err)
	}
	a.port = ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from the app")
	})}
	a.srv = srv
	go func() { _ = srv.Serve(ln) }()
}

func (a *flappyApp) stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv != nil {
		_ = a.srv.Close()
		a.srv = nil
	}
}

func (rs *relaySession) waitFrame(t *testing.T, typ string) Frame {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case f, ok := <-rs.frames:
			if !ok {
				t.Fatalf("the control stream closed before a %s frame arrived", typ)
			}
			if f.Type == typ {
				return f
			}
		case <-deadline:
			t.Fatalf("no %s frame arrived", typ)
			return Frame{}
		}
	}
}

// The port stops listening: the relay is told, so it can answer visitors
// itself rather than being handed a stream to nothing.
func TestReportsDegradedWhenTheServiceStops(t *testing.T) {
	fr := newFakeRelay(t)
	app := newFlappyApp(t)
	run := runClient(t, fr, Config{LocalPort: app.port,
		WatchInterval: 20 * time.Millisecond, ServiceGrace: 30 * time.Second})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	app.stop()

	if f := rs.waitFrame(t, FrameStatus); f.State != ServiceDegraded {
		t.Errorf("the daemon reported %q, want %s", f.State, ServiceDegraded)
	}
	run.waitState(t, StateDegraded)
}

// A restart inside the window costs nothing: the same tunnel goes back to
// live and keeps serving. This is the case the window exists for.
func TestRecoversWhenTheServiceReturnsInsideTheWindow(t *testing.T) {
	fr := newFakeRelay(t)
	app := newFlappyApp(t)
	run := runClient(t, fr, Config{LocalPort: app.port,
		WatchInterval: 20 * time.Millisecond, ServiceGrace: 30 * time.Second})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	app.stop()
	if f := rs.waitFrame(t, FrameStatus); f.State != ServiceDegraded {
		t.Fatalf("the daemon reported %q, want %s", f.State, ServiceDegraded)
	}

	app.start() // the dev server finished restarting
	if f := rs.waitFrame(t, FrameStatus); f.State != ServiceLive {
		t.Fatalf("the daemon reported %q, want %s", f.State, ServiceLive)
	}
	if _, body := rs.get(t, "/"); body != "hello from the app" {
		t.Errorf("the recovered share returned %q", body)
	}

	// Still the same connection: recovering must not cost a reconnect.
	select {
	case <-fr.sessions:
		t.Error("the client reconnected to recover; the tunnel should have been kept")
	default:
	}
}

// Past the window the share is over: the client closes the control connection
// and does not try again.
func TestStopsAfterTheGraceWindowWithoutReconnecting(t *testing.T) {
	fr := newFakeRelay(t)
	app := newFlappyApp(t)
	grace := 300 * time.Millisecond
	run := runClient(t, fr, Config{LocalPort: app.port,
		WatchInterval: 20 * time.Millisecond, ServiceGrace: grace})
	run.waitState(t, StateConnected)
	fr.wait(t)

	app.stop()
	stopped := time.Now()
	err := run.waitDone(t)
	if !errors.Is(err, ErrServiceGone) {
		t.Fatalf("Run returned %v, want ErrServiceGone", err)
	}
	if waited := time.Since(stopped); waited < grace {
		t.Errorf("the share ended after %v, before the %v window closed", waited, grace)
	}

	select {
	case <-fr.sessions:
		t.Error("the client reconnected after the share had stopped")
	case <-time.After(500 * time.Millisecond):
	}
}

// The rule this whole design turns on: once stopped, nothing resumes, however
// fast the port comes back. Whatever binds it next may be a different project,
// and it must not inherit a URL someone has already handed out.
func TestDoesNotResumeAfterTheShareHasStopped(t *testing.T) {
	fr := newFakeRelay(t)
	app := newFlappyApp(t)
	run := runClient(t, fr, Config{LocalPort: app.port,
		WatchInterval: 20 * time.Millisecond, ServiceGrace: 200 * time.Millisecond})
	run.waitState(t, StateConnected)
	fr.wait(t)

	app.stop()
	if err := run.waitDone(t); !errors.Is(err, ErrServiceGone) {
		t.Fatalf("Run returned %v, want ErrServiceGone", err)
	}

	// Something binds the port again — the same app, or not.
	app.start()

	select {
	case <-fr.sessions:
		t.Error("the client resumed the share when the port came back; " +
			"a different project could have bound it")
	case <-time.After(time.Second):
	}
}

// The relay keeps its own clock on a degraded share, and it can be the one to
// end it — when this daemon's watcher is wedged, or its machine stopped
// looking. That is terminal here too: the client does not reconnect and hand
// the same public URL back to whatever is on that port now.
func TestTheRelayEndingTheShareStopsTheClient(t *testing.T) {
	fr := newFakeRelay(t)
	app := newFlappyApp(t)
	// A window long enough that this client's own timer never fires: the relay
	// is what ends this share.
	run := runClient(t, fr, Config{LocalPort: app.port,
		WatchInterval: 20 * time.Millisecond, ServiceGrace: time.Hour})
	run.waitState(t, StateConnected)
	rs := fr.wait(t)

	app.stop()
	if f := rs.waitFrame(t, FrameStatus); f.State != ServiceDegraded {
		t.Fatalf("the daemon reported %q, want %s", f.State, ServiceDegraded)
	}

	rs.send(t, Frame{Type: FrameGoingAway, Reason: GoingAwayServiceGone})

	if err := run.waitDone(t); !errors.Is(err, ErrServiceGone) {
		t.Fatalf("Run returned %v, want ErrServiceGone", err)
	}
	select {
	case <-fr.sessions:
		t.Error("the client reconnected after the relay had ended the share")
	case <-time.After(500 * time.Millisecond):
	}
}
