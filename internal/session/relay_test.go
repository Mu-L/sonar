package session

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"github.com/raskrebs/sonar/internal/credentials"
	"github.com/raskrebs/sonar/internal/daemon/rpc"
)

// A fake relay, because the real one cannot be made to answer 410 or 401 on
// demand and because a test must never spend a real device code. It serves the
// four routes this package calls, in the shapes AUTH.md and its "Where this
// document is behind the relay" section describe: `reason` on every 4xx,
// `interval` and `Retry-After` on slow_down, `token_type` on the 200.

type fakeRelay struct {
	*httptest.Server

	mu sync.Mutex
	// deviceCode is the code the fake minted; "" before /v1/device/code.
	deviceCode string
	// answers is what /v1/device/token returns, one per poll, in order. The
	// last is repeated once the list runs out.
	answers []tokenAnswer
	polls   int
	// token is the session /v1/me and /v1/session/revoke accept.
	token string
	// meStatus overrides the /v1/me status (401 for a revoked session).
	meStatus int
	// revokeStatus overrides the /v1/session/revoke status.
	revokeStatus int
	// revokes counts the revoke calls.
	revokes int
	// codeRequests records the body of every /v1/device/code.
	codeRequests []map[string]string
	// bearers records the Authorization header of every authenticated call.
	bearers []string
}

// tokenAnswer is one scripted reply to a poll.
type tokenAnswer struct {
	status int
	// body is the JSON to send. Empty means one built from status.
	body string
	// retryAfter sets the header; zero omits it.
	retryAfter int
}

func newFakeRelay(t *testing.T) *fakeRelay {
	t.Helper()
	f := &fakeRelay{token: "session-token-from-the-relay", meStatus: 200}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/device/code", f.deviceCodeRoute)
	mux.HandleFunc("POST /v1/device/token", f.deviceTokenRoute)
	mux.HandleFunc("GET /v1/me", f.meRoute)
	mux.HandleFunc("POST /v1/session/revoke", f.revokeRoute)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// pollCount is how many polls the fake has answered, read under its lock so
// -race sees the ordering.
func (f *fakeRelay) pollCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls
}

func (f *fakeRelay) revokeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revokes
}

func (f *fakeRelay) bearer(i int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.bearers) {
		return ""
	}
	return f.bearers[i]
}

func (f *fakeRelay) codeRequest(i int) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.codeRequests) {
		return nil
	}
	return f.codeRequests[i]
}

func (f *fakeRelay) mintedCode() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deviceCode
}

func (f *fakeRelay) script(answers ...tokenAnswer) {
	f.mu.Lock()
	f.answers = answers
	f.polls = 0
	f.mu.Unlock()
}

func (f *fakeRelay) deviceCodeRoute(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.codeRequests = append(f.codeRequests, body)
	f.deviceCode = "device-code-32-bytes-base64url"
	f.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"device_code":               "device-code-32-bytes-base64url",
		"user_code":                 "WXYZ-2K7M",
		"verification_uri":          "https://relay.example/device",
		"verification_uri_complete": "https://relay.example/device?code=WXYZ-2K7M",
		"expires_in":                900,
		"interval":                  5,
	})
}

func (f *fakeRelay) deviceTokenRoute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceCode string `json:"device_code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	f.mu.Lock()
	minted := f.deviceCode
	i := f.polls
	f.polls++
	answers := f.answers
	token := f.token
	f.mu.Unlock()

	if body.DeviceCode != minted {
		writeJSON(w, 410, map[string]any{"error": "expired_token", "reason": "that code is not one of ours"})
		return
	}
	if len(answers) == 0 {
		writeJSON(w, 428, map[string]any{"error": "authorization_pending", "reason": "waiting for approval"})
		return
	}
	if i >= len(answers) {
		i = len(answers) - 1
	}
	a := answers[i]
	if a.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(a.retryAfter))
	}
	if a.body != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(a.status)
		_, _ = w.Write([]byte(a.body))
		return
	}
	if a.status == 200 {
		writeJSON(w, 200, map[string]any{
			"access_token": token,
			"token_type":   "Bearer",
			"account":      testAccount(),
		})
		return
	}
	writeJSON(w, a.status, map[string]any{"error": "unexpected", "reason": "scripted"})
}

func (f *fakeRelay) meRoute(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.bearers = append(f.bearers, r.Header.Get("Authorization"))
	status, token := f.meStatus, f.token
	f.mu.Unlock()

	if r.Header.Get("Authorization") != "Bearer "+token {
		writeJSON(w, 401, map[string]any{"error": "unauthorized", "reason": "unknown session"})
		return
	}
	if status != 200 {
		writeJSON(w, status, map[string]any{"error": "unauthorized", "reason": "that session was revoked"})
		return
	}
	writeJSON(w, 200, testAccount())
}

func (f *fakeRelay) revokeRoute(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.revokes++
	f.bearers = append(f.bearers, r.Header.Get("Authorization"))
	status := f.revokeStatus
	f.mu.Unlock()
	if status == 0 {
		status = 200
	}
	if status != 200 {
		writeJSON(w, status, map[string]any{"error": "internal", "reason": "scripted"})
		return
	}
	writeJSON(w, 200, map[string]any{"revoked": true})
}

func testAccount() map[string]any {
	return map[string]any{
		"id":           "acct_1",
		"display_name": "Rasmus",
		"email":        "rasmus@example.com",
		"provider":     "github",
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// countingKeychain is a keychain that is a variable and counts its reads, so a
// test can assert the store is asked once per launch and not once per call.
type countingKeychain struct {
	mu     sync.Mutex
	secret *string
	gets   int
}

func (k *countingKeychain) Get() (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gets++
	if k.secret == nil {
		return "", credentials.ErrNotFound
	}
	return *k.secret, nil
}

func (k *countingKeychain) Set(secret string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.secret = &secret
	return nil
}

func (k *countingKeychain) Delete() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.secret == nil {
		return credentials.ErrNotFound
	}
	k.secret = nil
	return nil
}

func (k *countingKeychain) reads() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.gets
}

// newManager builds a manager over a fake relay and a store in a temp
// directory. The keychain is returned so a test can count its reads.
func newManager(t *testing.T, f *fakeRelay) (*Manager, *countingKeychain) {
	t.Helper()
	kc := &countingKeychain{}
	store := credentials.New(filepath.Join(t.TempDir(), "credentials.json"), kc)
	return New(Options{
		Relay:    f.URL,
		Store:    store,
		HTTP:     f.Client(),
		Version:  "v0.0.0-test",
		Hostname: "laptop",
	}), kc
}

// ---------------------------------------------------------------------------

// The whole flow: ask for a code, poll while nobody has typed it, and end with
// a session in the store and an account to show.
func TestTheWholeFlowEndsWithAStoredSession(t *testing.T) {
	f := newFakeRelay(t)
	m, kc := newManager(t, f)
	ctx := context.Background()

	f.script(
		tokenAnswer{status: 428, body: `{"error":"authorization_pending","reason":"waiting"}`},
		tokenAnswer{status: 200},
	)

	start, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if start.UserCode != "WXYZ-2K7M" {
		t.Errorf("user_code = %q", start.UserCode)
	}
	if start.VerificationURIComplete == "" || start.VerificationURI == "" {
		t.Errorf("start did not carry both URLs: %+v", start)
	}
	if start.Interval != 5 || start.ExpiresIn != 900 {
		t.Errorf("start = %+v, want interval 5 and expires_in 900", start)
	}
	// The approval page has to be able to say what is asking.
	if got := f.codeRequest(0); got["client"] != Client || got["hostname_hint"] != "laptop" || got["version"] == "" {
		t.Errorf("the code request did not name the client: %v", got)
	}

	first, err := m.Poll(ctx)
	if err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	if first.State != rpc.SessionPending || first.Interval != 5 {
		t.Errorf("first poll = %+v, want pending at 5", first)
	}

	done, err := m.Poll(ctx)
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if done.State != rpc.SessionSignedIn {
		t.Fatalf("second poll = %+v, want signed_in", done)
	}
	if done.Account == nil || done.Account.ID != "acct_1" {
		t.Errorf("signed in without the account: %+v", done)
	}
	if done.StoredIn != string(credentials.InKeychain) {
		t.Errorf("stored_in = %q, want keychain", done.StoredIn)
	}

	// The session is really in the store, and the status reads back the same.
	status := m.Status()
	if !status.SignedIn || status.Account == nil || status.Account.Email != "rasmus@example.com" {
		t.Errorf("status = %+v, want signed in as rasmus@example.com", status)
	}
	if status.Relay != f.URL {
		t.Errorf("status names relay %q, want %q", status.Relay, f.URL)
	}
	sess, where, err := m.Session()
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if sess.Token.Reveal() != f.token || where != credentials.InKeychain {
		t.Errorf("stored %q in %q", sess.Token.Reveal(), where)
	}

	// The keychain was never read: the flow wrote, and a write updates the
	// memory copy instead of costing a read.
	if kc.reads() != 0 {
		t.Errorf("the keychain was read %d times during a sign-in", kc.reads())
	}
}

// The token stays here. A client is handed the user_code and the URL; the
// device_code is never in anything that crosses the protocol.
func TestStartNeverHandsOutTheDeviceCode(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)

	start, err := m.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	encoded, err := json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || jsonHas(t, encoded, f.mintedCode()) {
		t.Errorf("session.start's result carries the device code: %s", encoded)
	}
}

func jsonHas(t *testing.T, blob []byte, needle string) bool {
	t.Helper()
	if needle == "" {
		t.Fatal("nothing to look for")
	}
	return bytesContains(blob, []byte(needle))
}

func bytesContains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

// slow_down carries the number to use, in the body and in the header. The
// relay's number is the one honoured, and it sticks for the next poll even if
// the caller ignores it.
func TestSlowDownHonoursTheRelaysNumber(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)
	ctx := context.Background()

	f.script(
		tokenAnswer{status: 429, body: `{"error":"slow_down","reason":"too fast","interval":10}`, retryAfter: 10},
		tokenAnswer{status: 429, body: `{"error":"slow_down","reason":"too fast","interval":15}`, retryAfter: 15},
		tokenAnswer{status: 428, body: `{"error":"authorization_pending","reason":"waiting"}`},
	)
	if _, err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	first, err := m.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if first.State != rpc.SessionSlowDown || first.Interval != 10 {
		t.Errorf("first slow_down = %+v, want slow_down at 10", first)
	}

	second, err := m.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if second.State != rpc.SessionSlowDown || second.Interval != 15 {
		t.Errorf("second slow_down = %+v, want slow_down at 15", second)
	}

	// The interval the relay asked for is now in force: the next pending
	// answer reports 15, not the 5 the flow started at.
	pending, err := m.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if pending.State != rpc.SessionPending || pending.Interval != 15 {
		t.Errorf("pending after two slow_downs = %+v, want pending at 15", pending)
	}
}

// The header alone is enough, for a relay that sends Retry-After and no
// interval in the body.
func TestSlowDownFallsBackToRetryAfter(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)
	ctx := context.Background()

	f.script(tokenAnswer{status: 429, body: `{"error":"slow_down","reason":"too fast"}`, retryAfter: 20})
	if _, err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got, err := m.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got.State != rpc.SessionSlowDown || got.Interval != 20 {
		t.Errorf("slow_down = %+v, want slow_down at 20 from Retry-After", got)
	}
}

// A 410 ends the flow, and says "no longer valid" rather than "expired",
// because it is also the answer for a typo and for a code already claimed.
func TestAGoneCodeEndsTheFlowAndIsNotCalledExpired(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)
	ctx := context.Background()

	f.script(tokenAnswer{status: 410, body: `{"error":"expired_token","reason":"no such code"}`})
	if _, err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	got, err := m.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got.State != rpc.SessionExpired {
		t.Fatalf("410 = %+v, want expired", got)
	}
	if got.Detail != goneDetail {
		t.Errorf("410 detail = %q, want the 'no longer valid' wording", got.Detail)
	}

	// The flow is over: a second poll does not go back to the relay with a
	// code the relay has already refused.
	before := f.pollCount()
	again, err := m.Poll(ctx)
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if again.State != rpc.SessionExpired {
		t.Errorf("second poll = %+v, want expired", again)
	}
	if after := f.pollCount(); after != before {
		t.Errorf("the dead flow was polled again: %d then %d", before, after)
	}
	if m.Status().SignedIn {
		t.Error("a refused code left the machine signed in")
	}
}

// A 403 is the person saying no.
func TestADeclinedFlowIsDenied(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)
	ctx := context.Background()

	f.script(tokenAnswer{status: 403, body: `{"error":"access_denied","reason":"declined"}`})
	if _, err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got, err := m.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got.State != rpc.SessionDenied {
		t.Errorf("403 = %+v, want denied", got)
	}
}

// Registering is the app handing its token over. The account comes from the
// relay, not from the caller.
func TestRegisterVerifiesTheTokenWithTheRelay(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)
	ctx := context.Background()

	out, err := m.Register(ctx, f.token, f.URL)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if out.Account.ID != "acct_1" || out.Account.DisplayName != "Rasmus" {
		t.Errorf("registered account = %+v, want the relay's answer", out.Account)
	}
	if out.StoredIn != string(credentials.InKeychain) {
		t.Errorf("stored_in = %q", out.StoredIn)
	}
	if got := f.bearer(0); got != "Bearer "+f.token {
		t.Errorf("the verify call sent %q", got)
	}
	if !m.Status().SignedIn {
		t.Error("registering did not leave the machine signed in")
	}
}

// A token the relay does not know is not stored.
func TestRegisterRefusesATokenTheRelayDoesNotKnow(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)

	_, err := m.Register(context.Background(), "not-a-session", "")
	if err == nil {
		t.Fatal("Register accepted a token the relay refused")
	}
	assertCode(t, err, rpc.CodeNotSignedIn)
	if m.Status().SignedIn {
		t.Error("a refused token was stored anyway")
	}
}

// An app pointed at another relay fails loudly instead of storing a token this
// daemon cannot spend.
func TestRegisterRefusesAnotherRelaysSession(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)

	_, err := m.Register(context.Background(), f.token, "https://relay.elsewhere")
	if err == nil {
		t.Fatal("Register accepted a session for another relay")
	}
	assertCode(t, err, rpc.CodeInvalidParams)

	// A trailing slash is the same relay, not another one.
	if _, err := m.Register(context.Background(), f.token, f.URL+"/"); err != nil {
		t.Errorf("Register refused its own relay written with a trailing slash: %v", err)
	}
}

// A 401 on an authenticated call is the relay saying the session is over. It
// is authoritative: the stored session goes, and the answer is not_signed_in.
func TestA401ClearsTheStoredSession(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)
	ctx := context.Background()

	if _, err := m.Register(ctx, f.token, ""); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Revoked from another machine.
	f.mu.Lock()
	f.meStatus = 401
	f.mu.Unlock()

	_, err := m.Verify(ctx)
	if err == nil {
		t.Fatal("Verify accepted a session the relay had revoked")
	}
	assertCode(t, err, rpc.CodeNotSignedIn)

	if status := m.Status(); status.SignedIn {
		t.Errorf("a revoked session is still reported as signed in: %+v", status)
	}
	if _, _, err := m.Session(); err == nil {
		t.Error("the session survived a 401")
	}
	// And it is gone from the store, not only from the memory copy: a second
	// manager over the same store finds nothing.
	fresh := New(Options{Relay: f.URL, Store: m.store, HTTP: f.Client()})
	if fresh.Status().SignedIn {
		t.Error("the session is still in the store after a 401")
	}
}

// status refreshed is the same answer, checked. An unreachable relay leaves
// the session standing: being offline is not being signed out.
func TestRefreshedStatusKeepsTheSessionWhenTheRelayIsUnreachable(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)
	ctx := context.Background()

	if _, err := m.Register(ctx, f.token, ""); err != nil {
		t.Fatalf("Register: %v", err)
	}
	f.Close() // the relay is now unreachable

	status := m.StatusRefreshed(ctx)
	if !status.SignedIn {
		t.Errorf("an unreachable relay signed the machine out: %+v", status)
	}
	if status.Reason == "" {
		t.Error("the status did not say the session could not be checked")
	}
}

// Signing out revokes, then clears — and clears either way.
func TestClearRevokesAndForgets(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)
	ctx := context.Background()

	if _, err := m.Register(ctx, f.token, ""); err != nil {
		t.Fatalf("Register: %v", err)
	}
	out, err := m.Clear(ctx)
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if !out.Revoked {
		t.Errorf("Clear = %+v, want revoked", out)
	}
	if got := f.revokeCount(); got != 1 {
		t.Errorf("the relay was told %d times, want once", got)
	}
	if m.Status().SignedIn {
		t.Error("still signed in after a clear")
	}
}

// The relay being unreachable must not leave someone signed in after they
// asked to sign out.
func TestClearForgetsEvenWhenTheRelayCannotBeTold(t *testing.T) {
	f := newFakeRelay(t)
	m, _ := newManager(t, f)
	ctx := context.Background()

	if _, err := m.Register(ctx, f.token, ""); err != nil {
		t.Fatalf("Register: %v", err)
	}
	f.Close()

	out, err := m.Clear(ctx)
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if out.Revoked {
		t.Errorf("Clear claimed a revoke it could not have made: %+v", out)
	}
	if out.Detail == "" {
		t.Error("Clear did not say why the relay was not told")
	}
	if m.Status().SignedIn {
		t.Error("an unreachable relay left the machine signed in after a sign-out")
	}
}

// The keychain is asked once per launch, however many times the daemon is
// asked who it is. A timed-out keychain operation is abandoned rather than
// killed, so asking per call piles up background work — and on macOS every ask
// can be a password dialog.
func TestTheStoreIsAskedOncePerLaunch(t *testing.T) {
	f := newFakeRelay(t)
	m, kc := newManager(t, f)

	for range 5 {
		m.Status()
	}
	if _, _, err := m.Session(); err == nil {
		t.Fatal("Session found something in an empty store")
	}
	if kc.reads() != 1 {
		t.Errorf("the keychain was read %d times, want 1", kc.reads())
	}

	// And a sign-in does not send the next caller back to it.
	if _, err := m.Register(context.Background(), f.token, ""); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for range 5 {
		m.Status()
	}
	if kc.reads() != 1 {
		t.Errorf("the keychain was read %d times after a sign-in, want 1", kc.reads())
	}
}

// A store that refused what it holds is "not signed in" with the reason
// attached, which is the line `sonar doctor` prints.
func TestARefusedStoreIsReportedWithItsReason(t *testing.T) {
	f := newFakeRelay(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	store := credentials.New(path, nil)

	if _, err := store.Save(credentials.Session{
		Token:   "stored-token",
		Account: credentials.Account{ID: "acct_1"},
		Relay:   f.URL,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("the directory check this asserts is a unix mode check")
	}
	// A 0600 file in a directory others can write is not private: they can
	// rename it away and leave one of their own.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Skipf("cannot loosen %s: %v", dir, err)
	}

	m := New(Options{Relay: f.URL, Store: credentials.New(path, nil), HTTP: f.Client()})
	status := m.Status()
	if status.SignedIn {
		t.Errorf("a refused store is reported as signed in: %+v", status)
	}
	if status.Reason == "" {
		t.Error("a refused store came back with no reason for `sonar doctor` to print")
	}
	var insecure *credentials.InsecureFileError
	if _, _, err := m.Session(); err == nil {
		t.Fatal("Session returned a refused store's session")
	} else if !errors.As(err, &insecure) && status.Reason == "" {
		t.Errorf("the reason did not come from the store: %v", err)
	}
}

func assertCode(t *testing.T, err error, want int) {
	t.Helper()
	var re *rpc.Error
	if !errors.As(err, &re) {
		t.Fatalf("error %v is not a protocol error", err)
	}
	if re.Code != want {
		t.Errorf("code = %d (%s), want %d (%s)", re.Code, rpc.CodeName(re.Code), want, rpc.CodeName(want))
	}
}
