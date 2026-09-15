package doctor

import (
	"context"
	"strings"

	"github.com/raskrebs/sonar/internal/config"
	"github.com/raskrebs/sonar/internal/daemon/rpc"
)

// checkRelaySession is the one line `sonar doctor` gains for signing in: who
// this machine is signed in to the relay as, and where that session is kept.
//
// This is where `whoami` went. `sonar login`, `sonar logout` and `sonar whoami`
// do not ship (sonar-relay/docs/SHARE.md, "Auth, and what this changes in
// AUTH.md"): signing in is a step of sharing, and the question "who am I?" is
// asked when something is wrong, which is the command people already run.
//
// It never reads the credential store itself. The daemon holds the session and
// asks its keychain once per launch — on macOS every read of that item can be a
// password dialog — so a `sonar doctor` that looked for itself would be a
// second asker and, on a machine with no daemon, a prompt raised by a
// diagnostic. With no daemon the row is a skip that says so.
//
// A session the daemon could not read is the row worth having: `warn` with the
// store's own reason, which is a credentials file others could replace, a
// record a newer sonar wrote, or a keychain that did not answer.
func checkRelaySession(ctx context.Context, env *Env) rpc.DoctorCheck {
	info := env.Daemon(ctx)
	relay := relayOf(env)

	if info.Session == nil {
		if !info.Reachable {
			return rpc.DoctorCheck{
				Status:  StatusSkip,
				Summary: "no daemon to ask who you are",
				Detail:  "the daemon holds the relay session; start it and run this again",
				Fix:     "sonar serve --detach",
			}
		}
		return rpc.DoctorCheck{
			Status:  StatusSkip,
			Summary: "this daemon does not serve sign-in",
			Detail:  "it is older than the session methods; " + relay + " cannot be reached from it",
		}
	}
	s := *info.Session
	if s.Relay != "" {
		relay = s.Relay
	}

	if s.SignedIn {
		who := accountName(s.Account)
		detail := "the session is in the " + storeName(s.StoredIn)
		if s.Reason != "" {
			// Signed in, but to something else: worth a warning, because from
			// a screen this is indistinguishable from being signed in here.
			return rpc.DoctorCheck{
				Status:  StatusWarn,
				Summary: "signed in as " + who + ", but not to " + relay,
				Detail:  s.Reason,
			}
		}
		return rpc.DoctorCheck{
			Status:  StatusOK,
			Summary: "signed in to " + relay + " as " + who,
			Detail:  detail,
		}
	}

	if s.Reason != "" {
		return rpc.DoctorCheck{
			Status:  StatusWarn,
			Summary: "a stored session was refused",
			Detail:  s.Reason + " — sonar is treating this machine as signed out; signing in again replaces it",
		}
	}
	return rpc.DoctorCheck{
		Status:  StatusOK,
		Summary: "not signed in to " + relay,
		Detail:  "sharing a port asks you to sign in; nothing else needs an account",
	}
}

// relayOf is the relay this machine would use, for the rows answered before a
// daemon could say.
func relayOf(env *Env) string {
	cfg, _ := config.LoadFrom(env.ConfigPath)
	return cfg.Relay()
}

// storeName spells a credentials.Location for a person.
func storeName(where string) string {
	switch where {
	case "keychain":
		return "OS keychain"
	case "file":
		return "credentials file (~/.config/sonar/credentials.json, mode 0600)"
	case "":
		return "session store"
	}
	return where
}

// accountName is the most recognisable thing the relay told us about an
// account. The id is the fallback: every account has one.
func accountName(a *rpc.SessionAccount) string {
	if a == nil {
		return "an unnamed account"
	}
	if name := strings.TrimSpace(a.DisplayName); name != "" {
		if email := strings.TrimSpace(a.Email); email != "" && email != name {
			return name + " <" + email + ">"
		}
		return name
	}
	if email := strings.TrimSpace(a.Email); email != "" {
		return email
	}
	if id := strings.TrimSpace(a.ID); id != "" {
		return id
	}
	return "an unnamed account"
}
