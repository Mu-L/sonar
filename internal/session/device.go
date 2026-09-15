package session

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/raskrebs/sonar/internal/credentials"
	"github.com/raskrebs/sonar/internal/daemon/rpc"
)

// The relay's own polling constants (`internal/relay/device.go` in
// sonar-relay). They are mirrored rather than fetched because they are only
// ever a fallback: the relay states the interval in the 200 and re-states it on
// every slow_down, and that number is the one that is honoured.
const (
	defaultInterval = 5
	slowDownStep    = 5
	maxInterval     = 60
)

// deviceCodeBody is `POST /v1/device/code`.
type deviceCodeBody struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// tokenBody is the `200` of `POST /v1/device/token`. The relay also sends
// `token_type: "Bearer"`, which nothing here needs.
type tokenBody struct {
	AccessToken string             `json:"access_token"`
	Account     rpc.SessionAccount `json:"account"`
}

// step is one poll's meaning, before anything is stored. Split from the request
// so the outcomes and the backoff can be tested without a relay, which is the
// only way to test the rare ones: nothing can make a real relay answer 410 on
// demand.
type step int

const (
	stepPending step = iota
	stepSlowDown
	stepDenied
	// stepGone is the relay's 410. Not "expired": it is also the answer for a
	// code that was never real and for one already claimed, deliberately, so
	// that a guess cannot be told from a typo.
	stepGone
	stepIssued
	stepFailed
)

// nextInterval is the backoff a slow_down asks for.
//
// The relay's number wins: it puts the new interval in the body and in
// Retry-After precisely so a client learns its backoff from the response rather
// than from a spec, and honouring it is the difference between one slow_down
// and a run of them. Two guards on top of what it says — never below the
// interval already in force, because a smaller number only earns another
// slow_down, and never above the relay's own ceiling, because a client that
// misbehaved once should not end up polling once an hour.
func nextInterval(fromBody *int, fromHeader, current int) int {
	if current < 1 {
		current = defaultInterval
	}
	if current > maxInterval {
		current = maxInterval
	}
	asked := 0
	switch {
	case fromBody != nil && *fromBody > 0:
		asked = *fromBody
	case fromHeader > 0:
		asked = fromHeader
	default:
		asked = current + slowDownStep
	}
	if asked < current {
		asked = current
	}
	if asked > maxInterval {
		asked = maxInterval
	}
	return asked
}

// classify maps one HTTP answer onto a step.
//
// The status is read first, because AUTH.md fixes a distinct status per state.
// The error code is the fallback for anything answering with RFC 8628's
// vocabulary at a status we did not expect — a proxy rewriting a 428, or a
// relay older than this build.
func classify(status int, code string) step {
	switch status {
	case http.StatusOK:
		return stepIssued
	case http.StatusPreconditionRequired: // 428
		return stepPending
	case http.StatusTooManyRequests: // 429; on this route the only 429 is slow_down
		return stepSlowDown
	case http.StatusForbidden:
		return stepDenied
	case http.StatusGone:
		return stepGone
	}
	switch code {
	case "authorization_pending":
		return stepPending
	case "slow_down":
		return stepSlowDown
	case "access_denied":
		return stepDenied
	case "expired_token":
		return stepGone
	}
	return stepFailed
}

// goneDetail is what a 410 is told to a person.
//
// Not "your code expired". AUTH.md's "Where this document is behind the relay"
// is explicit that 410 is also the answer for an unknown code and for one
// already claimed — made indistinguishable on purpose, so an attacker cannot
// learn whether a guessed code was ever real — and that a client rendering
// "expired" for a typo is misleading.
const goneDetail = "that code is no longer valid — it may have been mistyped, already used, or left too long"

// Start is `session.start`: `POST /v1/device/code`.
//
// The hostname goes with it because the approval page names what is asking, and
// a page that says only "approve this code" teaches people to approve codes. It
// is a hint, not an identifier: the relay keeps it only for the life of the
// pending code.
//
// Whatever was pending is over. One flow at a time, and the last code asked for
// is the one on someone's screen.
func (m *Manager) Start(ctx context.Context) (rpc.SessionStartResult, error) {
	got, err := m.do(ctx, http.MethodPost, "/v1/device/code", map[string]string{
		"client":        Client,
		"version":       m.version,
		"hostname_hint": m.host,
	}, "")
	if err != nil {
		return rpc.SessionStartResult{}, err
	}
	if got.status != http.StatusOK {
		return rpc.SessionStartResult{}, got.fail()
	}

	var body deviceCodeBody
	if err := got.decode(&body); err != nil {
		return rpc.SessionStartResult{}, err
	}
	if body.DeviceCode == "" || body.UserCode == "" {
		return rpc.SessionStartResult{}, rpc.NewError(rpc.CodeInternal,
			"the relay started a sign-in without a code", "")
	}

	interval := body.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	complete := body.VerificationURIComplete
	if complete == "" {
		complete = body.VerificationURI
	}

	m.mu.Lock()
	m.pending = &pending{
		deviceCode: body.DeviceCode,
		interval:   interval,
		startedAt:  m.now(),
		expiresIn:  body.ExpiresIn,
	}
	m.mu.Unlock()

	m.log.Info("started a relay sign-in", "relay", m.relay, "expires_in", body.ExpiresIn)
	return rpc.SessionStartResult{
		UserCode:                body.UserCode,
		VerificationURI:         body.VerificationURI,
		VerificationURIComplete: complete,
		ExpiresIn:               body.ExpiresIn,
		Interval:                interval,
	}, nil
}

// Poll is `session.poll`: one `POST /v1/device/token` for the flow this manager
// is holding. It takes no device code because the caller has never had one.
func (m *Manager) Poll(ctx context.Context) (rpc.SessionPollResult, error) {
	m.mu.Lock()
	flow := m.pending
	m.mu.Unlock()

	// Cancelled, finished, or never started. The flow is over either way, and
	// from a screen's point of view that is the same answer as a dead code —
	// so it is that answer, rather than an error for a poll that raced a
	// sign-in.
	if flow == nil {
		return rpc.SessionPollResult{State: rpc.SessionExpired,
			Detail: "there is no sign-in in progress"}, nil
	}

	got, err := m.do(ctx, http.MethodPost, "/v1/device/token",
		map[string]string{"device_code": flow.deviceCode}, "")
	if err != nil {
		// Unreachable is not the end of the flow: the code is still live on
		// the relay and the next poll may find the network back.
		return rpc.SessionPollResult{}, err
	}

	if got.status == http.StatusOK {
		return m.issued(got)
	}

	var body errorBody
	_ = json.Unmarshal(got.body, &body)

	switch classify(got.status, body.Error) {
	case stepPending:
		return rpc.SessionPollResult{State: rpc.SessionPending, Interval: flow.interval}, nil

	case stepSlowDown:
		interval := nextInterval(body.Interval, got.retryAfter, flow.interval)
		// Remember it, so a client that forgets to pass the number back still
		// cannot drive this below what the relay asked for.
		m.mu.Lock()
		if m.pending == flow {
			m.pending.interval = interval
		}
		m.mu.Unlock()
		return rpc.SessionPollResult{State: rpc.SessionSlowDown, Interval: interval}, nil

	case stepDenied:
		m.endFlow(flow)
		return rpc.SessionPollResult{State: rpc.SessionDenied,
			Detail: "the sign-in was declined"}, nil

	case stepGone:
		m.endFlow(flow)
		return rpc.SessionPollResult{State: rpc.SessionExpired, Detail: goneDetail}, nil

	case stepIssued:
		// A 200 is handled above; reaching here would mean the status changed
		// under us, and there is no token to hand back.
		m.endFlow(flow)
		return rpc.SessionPollResult{}, rpc.NewError(rpc.CodeInternal,
			"the relay answered 200 with no session", "")

	default:
		m.endFlow(flow)
		return rpc.SessionPollResult{}, got.fail()
	}
}

// issued reads the 200 and stores the session. The device code is spent
// whatever happens next — it is single-use, and the 200 is the only one it ever
// gets — so the flow ends before anything that can fail.
func (m *Manager) issued(got answer) (rpc.SessionPollResult, error) {
	var body tokenBody
	if err := got.decode(&body); err != nil {
		m.mu.Lock()
		m.pending = nil
		m.mu.Unlock()
		return rpc.SessionPollResult{}, err
	}

	m.mu.Lock()
	m.pending = nil
	if body.AccessToken == "" {
		m.mu.Unlock()
		return rpc.SessionPollResult{}, rpc.NewError(rpc.CodeInternal,
			"the relay approved the sign-in without issuing a session", "")
	}
	where, err := m.save(credentials.Session{
		Token:   credentials.Token(body.AccessToken),
		Account: fromAccount(body.Account),
		Relay:   m.relay,
	})
	m.mu.Unlock()
	if err != nil {
		return rpc.SessionPollResult{}, rpc.NewError(rpc.CodeInternal,
			"signed in, but the session could not be stored: "+err.Error(), "")
	}

	m.log.Info("signed in to the relay", "relay", m.relay,
		"account", body.Account.ID, "stored_in", string(where))
	account := body.Account
	return rpc.SessionPollResult{
		State:    rpc.SessionSignedIn,
		Account:  &account,
		StoredIn: string(where),
	}, nil
}

// endFlow drops the pending flow, unless another Start has already replaced it.
func (m *Manager) endFlow(flow *pending) {
	m.mu.Lock()
	if m.pending == flow {
		m.pending = nil
	}
	m.mu.Unlock()
}

// Cancel forgets the pending flow. The relay's code ages out on its own fifteen
// minutes later; there is nothing to tell it. Nothing calls this over RPC yet —
// `session.start` replacing the flow is how a client abandons one — and it is
// here because share.create's inline sign-in will need it when the caller
// walks away.
func (m *Manager) Cancel() {
	m.mu.Lock()
	m.pending = nil
	m.mu.Unlock()
}

// PendingExpiresAt is when the code on someone's screen stops being worth
// typing, or the zero time when no flow is pending.
func (m *Manager) PendingExpiresAt() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil || m.pending.expiresIn <= 0 {
		return time.Time{}
	}
	return m.pending.startedAt.Add(time.Duration(m.pending.expiresIn) * time.Second)
}
