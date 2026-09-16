package share

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/raskrebs/sonar/internal/daemon/rpc"
	"github.com/raskrebs/sonar/internal/state"
)

// The share control plane, as sonar-relay serves it.
//
//	POST   /v1/shares              reserve or reclaim the slug for the key
//	GET    /v1/shares              this account's shares, live and reserved
//	DELETE /v1/shares/{slug}       stop a live share; the reservation survives
//	POST   /v1/shares/{slug}/extend
//
// Every one of them is authenticated by the account session, which
// internal/session holds. The shapes here mirror `internal/relay/shares.go` in
// sonar-relay, which is the source of truth; where this file and that one
// disagree, that one is right.

// The three TTL choices, and nothing else. A TTL field with a number and a unit
// is a question nobody wants to answer.
const (
	// TTLWhileItRuns ends the share when the service stops, or after eight
	// hours. Liveness is the primary control and this is its cap.
	TTLWhileItRuns = "while_it_runs"
	// TTLOneHour is for a link in a message you are about to send.
	TTLOneHour = "1h"
	// TTLOneDay is an overnight preview, and the free tier's ceiling.
	TTLOneDay = "24h"
)

// NormalizeTTL maps what a client sent onto one of the three choices. It
// mirrors the relay's own NormalizeTTL so a bad value is refused here, where the
// message can name the choices, rather than at the far end of an HTTP call.
func NormalizeTTL(ttl string) (string, bool) {
	switch strings.TrimSpace(strings.ToLower(ttl)) {
	case "", TTLWhileItRuns, "while-it-runs", "while it runs":
		return TTLWhileItRuns, true
	case TTLOneHour, "1hour", "60m", "1":
		return TTLOneHour, true
	case TTLOneDay, "1d", "24hour", "1440m", "24":
		return TTLOneDay, true
	}
	return "", false
}

// publishRequest is the body of `POST /v1/shares`.
//
// It carries both halves of the key and the relay decides which one it is: a
// client with a repo and a worktree sends them, one without sends the install,
// the project root and the port. Sending neither completely is the only error.
type publishRequest struct {
	Repo        string `json:"repo,omitempty"`
	Worktree    string `json:"worktree,omitempty"`
	ServiceName string `json:"service,omitempty"`

	InstallID   string `json:"install_id,omitempty"`
	ProjectRoot string `json:"project_root,omitempty"`
	Port        int    `json:"port,omitempty"`

	TTL string `json:"ttl"`
	// Replace answers the offer the previous attempt made: stop whatever live
	// share is in the way and take its place, in one round trip.
	Replace bool `json:"replace,omitempty"`
}

// shareView is a share as the relay describes it.
type shareView struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	URL    string `json:"url"`
	Status string `json:"status"`
	TTL    string `json:"ttl"`

	Repo        string `json:"repo"`
	Worktree    string `json:"worktree"`
	ServiceName string `json:"service"`
	InstallID   string `json:"install_id"`
	ProjectRoot string `json:"project_root"`
	Port        int    `json:"port"`

	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
	ExpiresIn    int    `json:"expires_in"`
	LastActiveAt string `json:"last_active_at"`
	BlockedAt    string `json:"blocked_at"`
	BytesOut     int64  `json:"bytes_out"`
}

// limitBody is the 409 the second live share gets. The live share travels with
// the refusal precisely so both clients can make it a question rather than an
// error.
type limitBody struct {
	Code   string    `json:"error"`
	Reason string    `json:"reason"`
	Limit  int       `json:"limit"`
	Live   shareView `json:"live"`
}

// errorBody is the relay's ordinary error shape.
type errorBody struct {
	Code   string `json:"error"`
	Reason string `json:"reason"`
}

// caller is the session, as this package needs it. An interface so the tests
// can drive every branch below against a fake relay without a credentials
// store, a keychain or a device flow.
type caller interface {
	Call(ctx context.Context, method, path string, payload any) (sessionResponse, error)
	Token() (string, error)
	Relay() string
}

type sessionResponse struct {
	Status int
	Body   []byte
}

// publish reserves or reclaims the slug for a key.
func (m *Manager) publish(ctx context.Context, req publishRequest, t target) (shareView, error) {
	got, err := m.session.Call(ctx, http.MethodPost, "/v1/shares", req)
	if err != nil {
		return shareView{}, relayError(err)
	}
	switch got.Status {
	case http.StatusOK:
		return decodeShare(got.Body)
	case http.StatusConflict:
		var body limitBody
		if err := json.Unmarshal(got.Body, &body); err != nil || body.Code != "share_limit_reached" {
			return shareView{}, httpFailure(got)
		}
		return shareView{}, rpc.ShareLimitError(
			limitDetail(body),
			"stop that share, or publish this one with replace",
			m.viewToShare(body.Live, "public"))
	case http.StatusUnavailableForLegalReasons:
		return shareView{}, rpc.NewError(rpc.CodeShareBlocked,
			"this share has been blocked by an operator", "write to abuse@ if that is wrong")
	default:
		return shareView{}, httpFailure(got)
	}
}

func limitDetail(body limitBody) string {
	what := body.Live.ServiceName
	if what == "" {
		what = body.Live.Slug
	}
	where := body.Live.Repo
	if where == "" {
		where = body.Live.ProjectRoot
	}
	detail := "already sharing " + what
	if where != "" {
		detail += " (" + where + ")"
	}
	if body.Live.URL != "" {
		detail += " at " + body.Live.URL
	}
	return detail
}

// Reservations is `GET /v1/shares`: everything this account holds on the relay,
// live and reserved. `share.list` deliberately does not call it — what a client
// wants from a daemon is what is live *here*, and a reservation is a slug with
// no target, no port and no process behind it on this machine — but the slugs
// an account is sitting on are worth being able to ask for.
func (m *Manager) Reservations(ctx context.Context) ([]state.Share, error) {
	got, err := m.session.Call(ctx, http.MethodGet, "/v1/shares", nil)
	if err != nil {
		return nil, relayError(err)
	}
	if got.Status != http.StatusOK {
		return nil, httpFailure(got)
	}
	var body struct {
		Shares []shareView `json:"shares"`
	}
	if err := json.Unmarshal(got.Body, &body); err != nil {
		return nil, rpc.NewError(rpc.CodeInternal, "the relay's share list could not be read: "+err.Error(), "")
	}
	out := make([]state.Share, 0, len(body.Shares))
	for _, v := range body.Shares {
		out = append(out, m.viewToShare(v, ReachPublic))
	}
	return out, nil
}

// stopRemote is `DELETE /v1/shares/{slug}`. The reservation survives, which is
// the whole point: asking again returns the same URL.
func (m *Manager) stopRemote(ctx context.Context, slug string) error {
	got, err := m.session.Call(ctx, http.MethodDelete, "/v1/shares/"+slug, nil)
	if err != nil {
		return relayError(err)
	}
	switch got.Status {
	case http.StatusOK, http.StatusNotFound:
		// A slug the relay does not know is the outcome this wanted.
		return nil
	default:
		return httpFailure(got)
	}
}

// extendRemote is `POST /v1/shares/{slug}/extend`.
func (m *Manager) extendRemote(ctx context.Context, slug, ttl string) (shareView, error) {
	got, err := m.session.Call(ctx, http.MethodPost,
		"/v1/shares/"+slug+"/extend", map[string]string{"ttl": ttl})
	if err != nil {
		return shareView{}, relayError(err)
	}
	switch got.Status {
	case http.StatusOK:
		return decodeShare(got.Body)
	case http.StatusGone:
		return shareView{}, rpc.NewError(rpc.CodeShareExpired,
			"this share is not running; publish it again to get the same URL back", "")
	case http.StatusUnavailableForLegalReasons:
		return shareView{}, rpc.NewError(rpc.CodeShareBlocked,
			"this share has been blocked by an operator", "")
	default:
		return shareView{}, httpFailure(got)
	}
}

func decodeShare(body []byte) (shareView, error) {
	var out shareView
	if err := json.Unmarshal(body, &out); err != nil {
		return shareView{}, rpc.NewError(rpc.CodeInternal,
			"the relay's answer could not be read: "+err.Error(), "")
	}
	if out.Slug == "" {
		return shareView{}, rpc.NewError(rpc.CodeInternal,
			"the relay published a share with no slug", "")
	}
	return out, nil
}

// relayError keeps a 1110 as a 1110 and turns everything else the session
// layer failed on — DNS, a refused connection, a timeout — into 1112.
//
// Distinguishing them matters to the CLI: `not_signed_in` is what starts the
// inline device flow, and doing that for an unreachable relay would put a
// person through a sign-in that cannot finish.
func relayError(err error) error {
	var e *rpc.Error
	if errors.As(err, &e) {
		return e
	}
	return rpc.NewError(rpc.CodeRelayUnreachable,
		"the relay could not be reached: "+err.Error(),
		"check the network, or `sonar config get share.relay`")
}

// httpFailure is a relay answer nothing above expected.
func httpFailure(got sessionResponse) error {
	var body errorBody
	_ = json.Unmarshal(got.Body, &body)
	detail := body.Reason
	if detail == "" {
		detail = body.Code
	}
	if detail == "" {
		detail = strings.TrimSpace(string(got.Body))
	}
	if detail == "" {
		detail = http.StatusText(got.Status)
	}
	if got.Status >= 500 {
		return rpc.Errorf(rpc.CodeRelayUnreachable, "the relay failed: %s", detail)
	}
	return rpc.Errorf(rpc.CodeInternal, "the relay refused the share: %s", detail)
}

// viewToShare is the relay's view rendered as the daemon's own row. Reach is
// carried in rather than read off the view because the relay has no reach
// column: everything it knows about is public, and a LAN share never reaches it.
func (m *Manager) viewToShare(v shareView, reach string) state.Share {
	out := state.Share{
		Host:       state.LocalhostName,
		ID:         v.ID,
		TargetPort: v.Port,
		Repo:       v.Repo,
		Worktree:   v.Worktree,
		Reach:      reach,
		URL:        v.URL,
		Status:     v.Status,
		CreatedAt:  v.CreatedAt,
		BytesOut:   v.BytesOut,
	}
	if v.ServiceName != "" {
		name := v.ServiceName
		out.TargetService = &name
	}
	if v.Repo == "" && v.ProjectRoot != "" && out.TargetGroup == nil {
		// A fallback-key share has no group name, but the directory is what a
		// person will recognise it by when a client has to name it.
		root := v.ProjectRoot
		out.TargetGroup = &root
	}
	if v.ExpiresAt != "" {
		at := v.ExpiresAt
		out.ExpiresAt = &at
	}
	if v.LastActiveAt != "" {
		at := v.LastActiveAt
		out.LastActiveAt = &at
	}
	return out
}
