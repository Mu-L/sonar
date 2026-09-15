package doctor

import (
	"context"
	"strings"
	"testing"

	"github.com/raskrebs/sonar/internal/daemon/rpc"
)

// signedIn is a daemon probe answering a session.status.
func withSession(env *Env, status *rpc.SessionStatusResult) *Env {
	env.Daemon = func(context.Context) DaemonInfo {
		return DaemonInfo{Reachable: true, Version: "v1.2.3", Session: status}
	}
	return env
}

// The line this check exists for: who you are and where the session is kept.
// It is where `sonar whoami` went.
func TestRelaySessionNamesTheAccountAndTheStore(t *testing.T) {
	env := withSession(fakeEnv(t), &rpc.SessionStatusResult{
		SignedIn: true,
		StoredIn: "keychain",
		Relay:    "https://relay.trysonar.dev",
		Account:  &rpc.SessionAccount{ID: "acct_1", DisplayName: "Rasmus", Email: "rasmus@example.com"},
	})
	got := run(t, env, checkRelaySession)
	wantStatus(t, got, StatusOK)
	if !strings.Contains(got.Summary, "Rasmus") || !strings.Contains(got.Summary, "relay.trysonar.dev") {
		t.Errorf("summary = %q, want the account and the relay", got.Summary)
	}
	if !strings.Contains(got.Detail, "keychain") {
		t.Errorf("detail = %q, want where the session is kept", got.Detail)
	}
}

// The file fallback is named as plainly as the keychain: on a headless box it
// is the normal case, not a degraded one.
func TestRelaySessionNamesTheFileStore(t *testing.T) {
	env := withSession(fakeEnv(t), &rpc.SessionStatusResult{
		SignedIn: true,
		StoredIn: "file",
		Relay:    "https://relay.trysonar.dev",
		Account:  &rpc.SessionAccount{ID: "acct_1", Email: "rasmus@example.com"},
	})
	got := run(t, env, checkRelaySession)
	wantStatus(t, got, StatusOK)
	if !strings.Contains(got.Detail, "credentials.json") {
		t.Errorf("detail = %q, want the credentials file named", got.Detail)
	}
	// No display name: the email is what a person recognises.
	if !strings.Contains(got.Summary, "rasmus@example.com") {
		t.Errorf("summary = %q", got.Summary)
	}
}

// No session is not a problem. Nothing but sharing needs an account.
func TestRelaySessionIsOKWithNoSession(t *testing.T) {
	env := withSession(fakeEnv(t), &rpc.SessionStatusResult{Relay: "https://relay.trysonar.dev"})
	got := run(t, env, checkRelaySession)
	wantStatus(t, got, StatusOK)
	if !strings.Contains(got.Summary, "not signed in") {
		t.Errorf("summary = %q", got.Summary)
	}
}

// A stored session that was refused is the row worth having: the store's own
// reason, which is the whole reason credentials.Load wraps one.
func TestRelaySessionWarnsWithTheStoresReason(t *testing.T) {
	env := withSession(fakeEnv(t), &rpc.SessionStatusResult{
		Relay:  "https://relay.trysonar.dev",
		Reason: "refusing to read /home/x/.config/sonar/credentials.json: the directory is writable by others",
	})
	got := run(t, env, checkRelaySession)
	wantStatus(t, got, StatusWarn)
	if !strings.Contains(got.Detail, "writable by others") {
		t.Errorf("detail = %q, want the store's reason", got.Detail)
	}
}

// Without a daemon the row skips rather than reading the keychain itself: the
// daemon is the one asker, and a diagnostic must not raise a password dialog.
func TestRelaySessionSkipsWithNoDaemon(t *testing.T) {
	got := run(t, fakeEnv(t), checkRelaySession)
	wantStatus(t, got, StatusSkip)
	if got.Fix == "" {
		t.Error("the skip did not say how to get an answer")
	}
}

// The check is in the list `sonar doctor` prints and `--only` selects.
func TestRelaySessionIsInTheCheckList(t *testing.T) {
	for _, id := range IDs() {
		if id == "relay_session" {
			return
		}
	}
	t.Errorf("relay_session is not among the checks: %v", IDs())
}
