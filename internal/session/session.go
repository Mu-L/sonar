// Package session is the daemon's half of signing in to the relay: the device
// flow, the session the flow produces, and the RPC methods clients drive it
// with (sonar-relay/docs/AUTH.md).
//
// # The daemon is authoritative
//
// AUTH.md's amended "Who holds the session" settles where a session lives: here.
// The daemon owns the stored session, it is what `share.create` will consult,
// and signing out here is what a revoke has to invalidate. The desktop app
// keeps its own copy in the OS keychain because that is a good store and keeps
// the token out of its webview, and hands it to this package with
// `session.register` so one sign-in produces one session on the relay rather
// than two.
//
// The store itself is internal/credentials: keychain first, a 0600 file second,
// because the headless Linux box this feature was aimed at has no keychain at
// all.
//
// # No CLI command
//
// There is no `sonar login`, `sonar logout` or `sonar whoami`, and that is
// deliberate: the CLI already has ~50 commands and the owner guards the surface
// (sonar-relay/docs/SHARE.md, "Auth, and what this changes in AUTH.md"). Signing
// in is a *step of the thing you asked for* — `share.create` on a machine with
// no session starts this flow inline — so every method here is reachable only
// over RPC. `sonar doctor` prints one line saying who you are, which is where
// `whoami` went.
//
// # The device code never leaves the daemon
//
// `session.start` returns the `user_code` a person types and the URL to type it
// into; the `device_code`, which is the credential half of the pair, stays in
// this process. `session.poll` never carries a device code either: it names a
// flow by an opaque id, so no client can poll a code it was not given, and none
// can leak one into a log, a crash report or a DOM.
//
// # More than one flow at a time
//
// The desktop app and an inline `sonar share` sign-in can be running at the
// same moment, and until 2026-09-15 they could not: one `pending` per daemon
// meant the second `session.start` replaced the first, so the person watching
// the first screen polled a flow that no longer existed and was told their code
// had expired. Flows are now a map. Each one remembers the connection that
// started it, and a poll resolves to the flow it names, else to the newest flow
// on the polling connection, else to the newest flow anywhere — so a client
// that has never heard of a flow id still polls its own.
//
// # The keychain is asked once
//
// internal/credentials is explicit that a timed-out keychain operation is
// abandoned rather than killed — go-keyring offers no cancellation, so its
// goroutine and, on macOS, its /usr/bin/security child run to completion in the
// background. A daemon that asked on every call would pile those up, and on
// macOS every ask can be a password dialog. So the store is read at most once
// per daemon launch and the answer is held in memory; every write updates the
// memory copy rather than costing a read.
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/raskrebs/sonar/internal/credentials"
	"github.com/raskrebs/sonar/internal/daemon/rpc"
)

// requestTimeout is one relay request's ceiling. Long enough for a slow link,
// short enough that a poll cannot pile up behind the one before it. The same
// number the desktop uses.
const requestTimeout = 20 * time.Second

// Client is what the relay's approval page calls this daemon, beside the
// version and the hostname hint, so the person approving sees what is asking.
const Client = "sonar-daemon"

// Options builds a Manager. Every field has a working default, so a test fills
// in only the seam it cares about.
type Options struct {
	// Relay is the relay's origin. Empty means config.Relay().
	Relay string
	// Store is where the session rests. Nil means credentials.Default().
	Store *credentials.Store
	// HTTP performs the relay calls. Nil means a client with requestTimeout
	// and no redirects followed.
	HTTP *http.Client
	// Version is the daemon's own version, sent to the approval page.
	Version string
	// Hostname is the hint the approval page shows. Empty means this machine's.
	Hostname string
	// Logger receives the one line each state change is worth. Nil discards.
	Logger *slog.Logger
	// Now is the clock, for the tests that assert on nothing else.
	Now func() time.Time
}

// Manager is the daemon's relay session: the store, the memory copy of what is
// in it, and the one device flow that may be pending at a time.
type Manager struct {
	relay   string
	store   *credentials.Store
	http    *http.Client
	version string
	host    string
	log     *slog.Logger
	now     func() time.Time

	mu sync.Mutex
	// loaded is the "asked once per launch" latch. cached and cachedIn hold
	// what the store said; cachedErr holds why it said nothing usable, which
	// is what `sonar doctor` prints.
	loaded    bool
	cached    *credentials.Session
	cachedIn  credentials.Location
	cachedErr error

	// flows are the device flows in progress, newest last in order. More than
	// one is the ordinary case, not a mistake: the app can be signing in while
	// someone runs `sonar share` over SSH on the same machine.
	flows map[string]*pending
	order []string
}

// maxFlows bounds how many device flows one daemon holds at once. Well above
// any real use — the app and a couple of terminals — and low enough that a
// client looping on session.start cannot grow the map without limit. The
// oldest is dropped, because the newest is the one on someone's screen.
const maxFlows = 8

// pending is one device flow in progress: the credential half of the code pair
// and the interval in force, which every slow_down raises.
type pending struct {
	// id is what a client polls by. Random, opaque, and not a secret: it
	// stands for the device code and never reveals it.
	id string
	// conn is the daemon connection that started the flow, or 0 when nothing
	// said. It is what makes a client that never passes a flow id safe: its
	// own connection's newest flow is the one it started.
	conn       uint64
	deviceCode string
	interval   int
	startedAt  time.Time
	expiresIn  int
}

// expired reports whether the code this flow holds is past the life the relay
// gave it. An expired flow is swept rather than polled: the relay would answer
// 410 for it, and holding it only keeps a dead code in memory.
func (p *pending) expired(now time.Time) bool {
	if p.expiresIn <= 0 {
		return false
	}
	return now.After(p.startedAt.Add(time.Duration(p.expiresIn) * time.Second))
}

// New builds a Manager.
func New(opts Options) *Manager {
	m := &Manager{
		relay:   opts.Relay,
		store:   opts.Store,
		http:    opts.HTTP,
		version: opts.Version,
		host:    opts.Hostname,
		log:     opts.Logger,
		now:     opts.Now,
	}
	if m.store == nil {
		m.store = credentials.Default()
	}
	if m.http == nil {
		m.http = &http.Client{
			Timeout: requestTimeout,
			// The relay answering a 3xx is a misconfiguration, not somewhere
			// to send a session.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if m.host == "" {
		m.host, _ = os.Hostname()
	}
	if m.log == nil {
		m.log = slog.New(slog.DiscardHandler)
	}
	if m.now == nil {
		m.now = time.Now
	}
	return m
}

// Relay is the origin this manager signs in to.
func (m *Manager) Relay() string { return m.relay }

// load returns the stored session, asking the store at most once per launch.
// The caller holds m.mu.
func (m *Manager) load() (*credentials.Session, credentials.Location, error) {
	if m.loaded {
		return m.cached, m.cachedIn, m.cachedErr
	}
	m.loaded = true
	sess, where, err := m.store.Load()
	switch {
	case err == nil:
		m.cached, m.cachedIn, m.cachedErr = &sess, where, nil
	case errors.Is(err, credentials.ErrNotSignedIn):
		// A store that could not be read is "not signed in" with a reason
		// attached: the daemon's answer is the same either way, and only
		// `sonar doctor` cares which it was.
		m.cached, m.cachedIn = nil, ""
		m.cachedErr = unwrapReason(err)
	default:
		m.cached, m.cachedIn = nil, ""
		m.cachedErr = err
	}
	return m.cached, m.cachedIn, m.cachedErr
}

// unwrapReason strips the "not signed in" sentinel off a Load error, leaving
// the cause — a credentials file others could replace, a record a newer sonar
// wrote, a keychain that did not answer. Nothing left means there was simply no
// session, which is not a reason for anything.
//
// Both wrapping shapes have to be handled: Load builds its error as
// `fmt.Errorf("%w: %w", ErrNotSignedIn, causes)`, and a multi-%w error unwraps
// to a *slice*, so the single-error Unwrap that reads naturally here would
// silently find nothing and throw the reason away.
func unwrapReason(err error) error {
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		rest := u.Unwrap()
		if rest == nil || errors.Is(rest, credentials.ErrNotSignedIn) {
			return nil
		}
		return rest
	case interface{ Unwrap() []error }:
		var kept []error
		for _, e := range u.Unwrap() {
			if e != nil && !errors.Is(e, credentials.ErrNotSignedIn) {
				kept = append(kept, e)
			}
		}
		return errors.Join(kept...)
	}
	return nil
}

// Session is the live session, for the callers that need the token:
// `share.create`, and the authenticated relay calls below. The location and the
// refusal reason come with it so nothing has to ask the store twice.
func (m *Manager) Session() (credentials.Session, credentials.Location, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.session()
}

// session is Session with m.mu already held.
func (m *Manager) session() (credentials.Session, credentials.Location, error) {
	sess, where, reason := m.load()
	if sess == nil {
		return credentials.Session{}, "", notSignedIn(reason)
	}
	return *sess, where, nil
}

// notSignedIn is the 1110 every caller gets when there is nothing stored,
// carrying the store's reason when there was one.
func notSignedIn(reason error) *rpc.Error {
	detail := "not signed in to the relay"
	if reason != nil {
		detail += ": " + reason.Error()
	}
	return rpc.NewError(rpc.CodeNotSignedIn, detail,
		"sign in from the Sonar app, or share a port and sonar will ask")
}

// save stores a session and updates the memory copy, so a sign-in does not cost
// a keychain read.
func (m *Manager) save(sess credentials.Session) (credentials.Location, error) {
	where, err := m.store.Save(sess)
	if err != nil {
		return "", err
	}
	m.loaded = true
	m.cached, m.cachedIn, m.cachedErr = &sess, where, nil
	return where, nil
}

// forget clears the store and the memory copy. The memory copy becomes "asked,
// nothing there" rather than "not asked", so the next call does not go back to
// a keychain for an item that is gone.
func (m *Manager) forget() error {
	err := m.store.Clear()
	m.loaded = true
	m.cached, m.cachedIn, m.cachedErr = nil, "", nil
	return err
}

// StatusRefreshed is `session.status {refresh: true}`: the stored answer, after
// checking it against the relay.
//
// Only a 401 changes anything — Verify clears the session, and the plain status
// then reports what is true. Every other failure, an unreachable relay
// included, is reported as a reason beside the session that is still stored,
// because being unable to check is not the same as being signed out.
func (m *Manager) StatusRefreshed(ctx context.Context) rpc.SessionStatusResult {
	if _, err := m.Verify(ctx); err != nil {
		out := m.Status()
		if out.SignedIn && out.Reason == "" {
			out.Reason = "the session could not be checked with the relay: " + err.Error()
		}
		return out
	}
	return m.Status()
}

// Status is `session.status`.
func (m *Manager) Status() rpc.SessionStatusResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := rpc.SessionStatusResult{Relay: m.relay}
	sess, where, reason := m.load()
	if sess == nil {
		if reason != nil {
			out.Reason = reason.Error()
		}
		return out
	}
	account := toAccount(sess.Account)
	out.SignedIn = true
	out.Account = &account
	out.StoredIn = string(where)
	// A session stored against another relay is not this daemon's session. It
	// is reported rather than hidden, because "signed in to the wrong relay"
	// and "not signed in" look identical from a screen otherwise.
	if sess.Relay != "" && sess.Relay != m.relay {
		out.Reason = fmt.Sprintf("this session is for %s, and this daemon uses %s", sess.Relay, m.relay)
	}
	return out
}

// toAccount converts the stored account to the wire's.
func toAccount(a credentials.Account) rpc.SessionAccount {
	return rpc.SessionAccount{
		ID:          a.ID,
		DisplayName: a.DisplayName,
		Email:       a.Email,
		AvatarURL:   a.AvatarURL,
		Provider:    a.Provider,
		CreatedAt:   a.CreatedAt,
	}
}

func fromAccount(a rpc.SessionAccount) credentials.Account {
	return credentials.Account{
		ID:          a.ID,
		DisplayName: a.DisplayName,
		Email:       a.Email,
		AvatarURL:   a.AvatarURL,
		Provider:    a.Provider,
		CreatedAt:   a.CreatedAt,
	}
}
