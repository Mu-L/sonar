package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/raskrebs/sonar/internal/config"
	"github.com/raskrebs/sonar/internal/credentials"
	"github.com/raskrebs/sonar/internal/daemon/rpc"
)

// maxBodyBytes caps what is read from the relay. The largest answer in this
// file is an account; anything near this is not one.
const maxBodyBytes = 1 << 20

// errorBody is the shape every relay 4xx carries. AUTH.md's table shows
// `{"error": "…"}` alone; the running relay also sends `reason` on every one of
// them, and `interval` on slow_down ("Where this document is behind the relay").
type errorBody struct {
	Error    string `json:"error"`
	Reason   string `json:"reason"`
	Interval *int   `json:"interval"`
}

// answer is one relay response, already drained so the connection is reusable.
type answer struct {
	status int
	body   []byte
	// retryAfter is the header the relay sends alongside the interval in the
	// body. Zero when absent or unreadable.
	retryAfter int
}

// decode unmarshals a successful body.
func (a answer) decode(v any) error {
	if err := json.Unmarshal(a.body, v); err != nil {
		return rpc.NewError(rpc.CodeInternal,
			fmt.Sprintf("the relay's answer could not be read: %v", err), "")
	}
	return nil
}

// fail reads the error body and turns it into a protocol error. The relay's own
// `reason` is preferred when it sent one, because it is prose written to be
// read; the status and the code are the fallback.
func (a answer) fail() *rpc.Error {
	var body errorBody
	_ = json.Unmarshal(a.body, &body)
	detail := strings.TrimSpace(body.Reason)
	if detail == "" {
		detail = describe(a.status, body.Error)
	}
	return rpc.NewError(rpc.CodeInternal, detail, "")
}

func describe(status int, code string) string {
	if code == "" {
		return fmt.Sprintf("the relay answered %d", status)
	}
	return fmt.Sprintf("the relay answered %d (%s)", status, code)
}

// do performs one request against the relay. A transport failure is
// relay_unreachable (1112) and nothing else: a laptop that is offline is a
// normal state, and the answer to it is "try again", not an internal error.
func (m *Manager) do(ctx context.Context, method, path string, payload any, token string) (answer, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return answer{}, rpc.NewError(rpc.CodeInternal, "encoding the request: "+err.Error(), "")
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, m.relay+path, body)
	if err != nil {
		return answer{}, rpc.NewError(rpc.CodeInternal, "building the request: "+err.Error(), "")
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", Client+"/"+m.version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := m.http.Do(req)
	if err != nil {
		return answer{}, rpc.NewError(rpc.CodeRelayUnreachable,
			fmt.Sprintf("could not reach %s: %v", m.relay, unwrapURL(err)),
			"check the network, or `sonar config set share.relay <url>` if the relay moved")
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return answer{}, rpc.NewError(rpc.CodeRelayUnreachable,
			fmt.Sprintf("the connection to %s broke mid-answer: %v", m.relay, err), "")
	}
	return answer{status: resp.StatusCode, body: raw, retryAfter: retryAfter(resp)}, nil
}

// retryAfter reads the header the relay sends beside the interval. Only the
// delta-seconds form is accepted: the relay sends a number, and an HTTP-date
// here would be a different relay's convention, not this one's.
func retryAfter(resp *http.Response) int {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > maxInterval*10 {
			return 0
		}
	}
	return n
}

// unwrapURL strips the *url.Error wrapper so a message does not repeat the URL
// the caller already printed.
func unwrapURL(err error) error {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		if inner := ue.Unwrap(); inner != nil {
			return inner
		}
	}
	return err
}

// authenticated performs a request with the stored session's token, and treats
// a 401 as authoritative: the session is gone from the relay, so it goes from
// here too and the caller is told it is not signed in (1110).
//
// Clearing rather than reporting is the point. A dead token left in the store
// is a daemon that thinks it can share and cannot, and every later call trips
// over it again.
func (m *Manager) authenticated(ctx context.Context, method, path string, payload any) (answer, error) {
	m.mu.Lock()
	sess, _, err := m.session()
	m.mu.Unlock()
	if err != nil {
		return answer{}, err
	}

	got, err := m.do(ctx, method, path, payload, sess.Token.Reveal())
	if err != nil {
		return answer{}, err
	}
	if got.status == http.StatusUnauthorized {
		m.mu.Lock()
		clearErr := m.forget()
		m.mu.Unlock()
		m.log.Info("the stored relay session is no longer live; signed out locally")
		if clearErr != nil {
			return answer{}, rpc.NewError(rpc.CodeNotSignedIn,
				"the relay no longer knows this session, and it could not be removed locally: "+clearErr.Error(),
				"")
		}
		return answer{}, notSignedIn(errors.New("the relay no longer knows this session"))
	}
	return got, nil
}

// meBody is `GET /v1/me`.
type meBody struct {
	rpc.SessionAccount
}

// me asks the relay who a token belongs to. Used by session.register to verify
// a token a client handed over rather than believing what it said about it.
func (m *Manager) me(ctx context.Context, token string) (rpc.SessionAccount, error) {
	got, err := m.do(ctx, http.MethodGet, "/v1/me", nil, token)
	if err != nil {
		return rpc.SessionAccount{}, err
	}
	switch got.status {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return rpc.SessionAccount{}, rpc.NewError(rpc.CodeNotSignedIn,
			"the relay does not recognise that session token", "sign in again")
	default:
		return rpc.SessionAccount{}, got.fail()
	}
	var body meBody
	if err := got.decode(&body); err != nil {
		return rpc.SessionAccount{}, err
	}
	if body.ID == "" {
		return rpc.SessionAccount{}, rpc.NewError(rpc.CodeInternal,
			"the relay named no account for that session", "")
	}
	return body.SessionAccount, nil
}

// Register is `session.register`: the desktop app handing its token over so one
// sign-in produces one session rather than two (AUTH.md, "Who holds the
// session", step 2).
//
// The account comes from `GET /v1/me`, not from the caller. That round trip is
// the only proof the token is live, and it means no client can label someone
// else's token with a name of its own choosing.
func (m *Manager) Register(ctx context.Context, token, relay string) (rpc.SessionRegisterResult, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return rpc.SessionRegisterResult{}, rpc.NewError(rpc.CodeInvalidParams,
			"token is required", `{"token": "<the session the relay issued>"}`)
	}
	if relay = strings.TrimSpace(relay); relay != "" {
		// Compared as origins, so a trailing slash or a spelled-out default
		// port is not mistaken for a different relay.
		origin, err := config.Origin(relay)
		if err != nil {
			return rpc.SessionRegisterResult{}, rpc.NewError(rpc.CodeInvalidParams,
				"relay is not a URL: "+err.Error(), `{"relay": "https://relay.trysonar.dev"}`)
		}
		if origin != m.relay {
			return rpc.SessionRegisterResult{}, rpc.NewError(rpc.CodeInvalidParams,
				fmt.Sprintf("that session is for %s, and this daemon uses %s", relay, m.relay),
				"point both at the same relay: `sonar config set share.relay <url>`")
		}
	}

	account, err := m.me(ctx, token)
	if err != nil {
		return rpc.SessionRegisterResult{}, err
	}

	m.mu.Lock()
	where, saveErr := m.save(credentials.Session{
		Token:   credentials.Token(token),
		Account: fromAccount(account),
		Relay:   m.relay,
	})
	m.mu.Unlock()
	if saveErr != nil {
		return rpc.SessionRegisterResult{}, rpc.NewError(rpc.CodeInternal, saveErr.Error(), "")
	}

	m.log.Info("registered a relay session", "relay", m.relay, "account", account.ID, "stored_in", string(where))
	return rpc.SessionRegisterResult{Account: account, StoredIn: string(where)}, nil
}

// Clear is `session.clear`: revoke at the relay, then forget locally — in that
// order, and the forget happens either way.
//
// The clear is not conditional on the revoke. Someone who asked to sign out
// must end up signed out; a relay that could not be reached leaves a row on the
// server, and the next authenticated call from anywhere is what notices it. The
// other way round is a user who pressed the button and is still signed in.
func (m *Manager) Clear(ctx context.Context) (rpc.SessionClearResult, error) {
	m.mu.Lock()
	sess, _, loadErr := m.session()
	// Signing out ends every flow, not only the newest: a half-finished
	// sign-in on another screen is an approval for the account being signed
	// out of.
	m.flows, m.order = nil, nil
	m.mu.Unlock()

	out := rpc.SessionClearResult{Revoked: true}
	if loadErr == nil {
		if detail := m.revoke(ctx, sess.Token.Reveal()); detail != "" {
			out.Revoked, out.Detail = false, detail
			m.log.Warn("signing out locally without reaching the relay", "detail", detail)
		}
	}

	m.mu.Lock()
	err := m.forget()
	m.mu.Unlock()
	if err != nil {
		// The one real failure: there is still a session on this machine.
		return out, rpc.NewError(rpc.CodeInternal, err.Error(), "")
	}
	return out, nil
}

// revoke tells the relay the session is over, returning why it could not be
// told. A revoke of a session the relay no longer has is a success: the thing
// asked for is already true.
func (m *Manager) revoke(ctx context.Context, token string) string {
	got, err := m.do(ctx, http.MethodPost, "/v1/session/revoke", struct{}{}, token)
	if err != nil {
		var re *rpc.Error
		if errors.As(err, &re) {
			return re.Message
		}
		return err.Error()
	}
	if got.status < 300 || got.status == http.StatusUnauthorized {
		return ""
	}
	return got.fail().Message
}

// Verify checks the stored session against the relay and returns the account it
// belongs to. It is what `session.status {refresh: true}` runs, and what
// share.create will run before it opens a tunnel under an account.
//
// A 401 ends the session here as well as there — that rule lives in
// authenticated, and it is the whole reason this method exists rather than
// being a plain read. Anything else, including an unreachable relay, leaves the
// stored session exactly as it was: a laptop on a train is not signed out.
func (m *Manager) Verify(ctx context.Context) (rpc.SessionAccount, error) {
	got, err := m.authenticated(ctx, http.MethodGet, "/v1/me", nil)
	if err != nil {
		return rpc.SessionAccount{}, err
	}
	if got.status != http.StatusOK {
		return rpc.SessionAccount{}, got.fail()
	}
	var body meBody
	if err := got.decode(&body); err != nil {
		return rpc.SessionAccount{}, err
	}

	// The relay is the authority on the account's display fields too: a name
	// or an avatar changed at the provider should not stay stale here until
	// the next sign-in.
	m.mu.Lock()
	if m.cached != nil && body.ID != "" {
		updated := *m.cached
		updated.Account = fromAccount(body.SessionAccount)
		if _, err := m.save(updated); err != nil {
			m.log.Warn("could not update the stored account", "err", err)
		}
	}
	m.mu.Unlock()
	return body.SessionAccount, nil
}
