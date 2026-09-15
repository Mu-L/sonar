package session

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/raskrebs/sonar/internal/credentials"
)

// flowRelay is a relay that issues a distinct device code per start and lets a
// test decide, per device code, what the token route answers.
type flowRelay struct {
	mu       sync.Mutex
	n        int
	approved map[string]string // device code -> the token to issue
}

func newFlowRelay() *flowRelay { return &flowRelay{approved: map[string]string{}} }

func (f *flowRelay) approve(deviceCode, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approved[deviceCode] = token
}

func (f *flowRelay) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/device/code", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.n++
		n := f.n
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"device_code":      "device-" + itoa(n),
			"user_code":        "CODE-" + itoa(n),
			"verification_uri": "https://relay.example/device",
			"expires_in":       900,
			"interval":         1,
		})
	})
	mux.HandleFunc("POST /v1/device/token", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			DeviceCode string `json:"device_code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		token, ok := f.approved[body.DeviceCode]
		f.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusPreconditionRequired, map[string]any{"error": "authorization_pending"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": token,
			"account":      map[string]any{"id": "acct-" + token, "email": token + "@example.test"},
		})
	})
	return mux
}

func itoa(n int) string { return strconv.Itoa(n) }

func flowManager(t *testing.T, relay *flowRelay) *Manager {
	t.Helper()
	srv := httptest.NewServer(relay.handler())
	t.Cleanup(srv.Close)
	return New(Options{
		Relay: srv.URL,
		Store: credentials.New(t.TempDir()+"/credentials.json", nil),
		Now:   time.Now,
	})
}

// The bug this table exists to fix: the app starts a flow, `sonar share` starts
// another, and the app's next poll must still be the app's flow.
func TestTwoFlowsDoNotStealEachOther(t *testing.T) {
	relay := newFlowRelay()
	m := flowManager(t, relay)
	ctx := context.Background()

	app, err := m.StartFor(ctx, 1)
	if err != nil {
		t.Fatalf("app start: %v", err)
	}
	cli, err := m.StartFor(ctx, 2)
	if err != nil {
		t.Fatalf("cli start: %v", err)
	}
	if app.FlowID == "" || cli.FlowID == "" || app.FlowID == cli.FlowID {
		t.Fatalf("flow ids are not distinct: %q and %q", app.FlowID, cli.FlowID)
	}
	if app.UserCode == cli.UserCode {
		t.Fatalf("both flows got the same user code %q", app.UserCode)
	}

	// The first flow is still alive: it polls pending, not expired.
	got, err := m.PollFlow(ctx, app.FlowID, 1)
	if err != nil {
		t.Fatalf("polling the app's flow: %v", err)
	}
	if got.State != "pending" {
		t.Fatalf("the app's flow polled %q, want pending — the second start stole it", got.State)
	}

	// Approving the app's code signs the app in, not the CLI's flow.
	relay.approve("device-1", "apptoken")
	got, err = m.PollFlow(ctx, app.FlowID, 1)
	if err != nil {
		t.Fatalf("polling the approved flow: %v", err)
	}
	if got.State != "signed_in" {
		t.Fatalf("state = %q, want signed_in", got.State)
	}
	// And the CLI's flow is untouched and still pending.
	got, err = m.PollFlow(ctx, cli.FlowID, 2)
	if err != nil {
		t.Fatalf("polling the cli flow: %v", err)
	}
	if got.State != "pending" {
		t.Fatalf("the cli flow polled %q, want pending", got.State)
	}
}

// A client that never learned about flow ids still polls its own flow, because
// the connection that started it is remembered.
func TestPollWithNoFlowIDPrefersThisConnection(t *testing.T) {
	relay := newFlowRelay()
	m := flowManager(t, relay)
	ctx := context.Background()

	if _, err := m.StartFor(ctx, 1); err != nil { // the app's, started first
		t.Fatal(err)
	}
	if _, err := m.StartFor(ctx, 2); err != nil { // the CLI's, started second
		t.Fatal(err)
	}
	relay.approve("device-1", "apptoken") // approve the OLDER flow

	got, err := m.PollFlow(ctx, "", 1)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if got.State != "signed_in" {
		t.Fatalf("state = %q, want signed_in: a bare poll on connection 1 took connection 2's flow", got.State)
	}
}

// With neither a flow id nor a connection there is still an answer, and it is
// the one the single-pending version always gave: the newest flow.
func TestPollWithNothingTakesTheNewestFlow(t *testing.T) {
	relay := newFlowRelay()
	m := flowManager(t, relay)
	ctx := context.Background()

	if _, err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	relay.approve("device-2", "newest")

	got, err := m.Poll(ctx)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if got.State != "signed_in" {
		t.Fatalf("state = %q, want signed_in", got.State)
	}
}

func TestPollingAnUnknownFlowIsOverRatherThanSomeoneElses(t *testing.T) {
	relay := newFlowRelay()
	m := flowManager(t, relay)
	ctx := context.Background()

	live, err := m.StartFor(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	relay.approve("device-1", "token")

	got, err := m.PollFlow(ctx, "no-such-flow", 1)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if got.State != "expired" {
		t.Fatalf("state = %q, want expired", got.State)
	}
	// Naming a flow that is not there must not fall back onto the live one.
	if got.Account != nil {
		t.Fatal("polling an unknown flow signed someone in")
	}
	_ = live
}

func TestClosingAConnectionForgetsItsFlows(t *testing.T) {
	relay := newFlowRelay()
	m := flowManager(t, relay)
	ctx := context.Background()

	gone, err := m.StartFor(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := m.StartFor(ctx, 8)
	if err != nil {
		t.Fatal(err)
	}
	m.CancelConn(7)

	if got, _ := m.PollFlow(ctx, gone.FlowID, 7); got.State != "expired" {
		t.Fatalf("the dropped flow polled %q, want expired", got.State)
	}
	if got, _ := m.PollFlow(ctx, kept.FlowID, 8); got.State != "pending" {
		t.Fatalf("the surviving flow polled %q, want pending", got.State)
	}
}

func TestFlowsAreBounded(t *testing.T) {
	relay := newFlowRelay()
	m := flowManager(t, relay)
	ctx := context.Background()

	first, err := m.StartFor(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxFlows; i++ {
		if _, err := m.StartFor(ctx, uint64(100+i)); err != nil {
			t.Fatal(err)
		}
	}
	m.mu.Lock()
	n := len(m.flows)
	m.mu.Unlock()
	if n > maxFlows {
		t.Fatalf("holding %d flows, want at most %d", n, maxFlows)
	}
	if got, _ := m.PollFlow(ctx, first.FlowID, 1); got.State != "expired" {
		t.Fatalf("the oldest flow polled %q; it should have been dropped first", got.State)
	}
}

func TestAnAgedOutFlowIsSwept(t *testing.T) {
	relay := newFlowRelay()
	m := flowManager(t, relay)
	clock := time.Now()
	m.now = func() time.Time { return clock }
	ctx := context.Background()

	f, err := m.StartFor(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(16 * time.Minute) // the relay said 900s

	if got, _ := m.PollFlow(ctx, f.FlowID, 1); got.State != "expired" {
		t.Fatalf("an aged-out flow polled %q, want expired", got.State)
	}
	m.mu.Lock()
	n := len(m.flows)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d flows left after the sweep, want 0", n)
	}
}

// Signing out must not leave a half-finished approval for the account being
// signed out of.
func TestClearEndsEveryFlow(t *testing.T) {
	relay := newFlowRelay()
	m := flowManager(t, relay)
	ctx := context.Background()

	a, err := m.StartFor(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.StartFor(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Clear(ctx); err != nil {
		t.Fatalf("clear: %v", err)
	}
	for _, id := range []string{a.FlowID, b.FlowID} {
		if got, _ := m.PollFlow(ctx, id, 0); got.State != "expired" {
			t.Fatalf("a flow survived sign-out: %q", got.State)
		}
	}
}
