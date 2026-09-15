package session

import (
	"slices"
	"testing"

	"github.com/raskrebs/sonar/internal/daemon"
	"github.com/raskrebs/sonar/internal/daemon/rpc"
)

// Every session method the schema describes is a method the daemon actually
// serves. A method in the schema and not in the dispatcher is a client that
// calls it and gets "unknown method".
func TestEverySessionMethodIsServed(t *testing.T) {
	served := daemon.RegisteredMethods()
	for name := range rpc.Methods() {
		if len(name) < 8 || name[:8] != "session." {
			continue
		}
		if !slices.Contains(served, name) {
			t.Errorf("%s is in the schema and not in the dispatcher", name)
		}
	}
}

// The token-carrying method is the local-only one, and the two that run the
// device flow deliberately are not: signing a headless box in from a laptop is
// the case the device flow exists for.
func TestOnlyRegisterIsLocalOnly(t *testing.T) {
	if !daemon.IsLocalOnly("session.register") {
		t.Error("session.register is not local-only: a token could be forwarded to another machine")
	}
	for _, name := range []string{"session.status", "session.start", "session.poll", "session.clear"} {
		if daemon.IsLocalOnly(name) {
			t.Errorf("%s is local-only, which would block signing in a remote host", name)
		}
	}
}

// The daemon announces the family so a client can feature-detect it before
// calling, the way it does for every other namespace.
func TestTheSessionCapabilityIsAnnounced(t *testing.T) {
	if !slices.Contains(daemon.Capabilities(), "session") {
		t.Errorf("capabilities = %v, missing \"session\"", daemon.Capabilities())
	}
}

// With no manager installed — a process that imported the handlers but never
// started a daemon — the handlers refuse rather than dereferencing nil.
func TestHandlersRefuseWithoutAManager(t *testing.T) {
	SetManager(nil)
	if _, err := requireManager(); err == nil {
		t.Error("requireManager answered with no manager installed")
	}
}
