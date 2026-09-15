package daemon

import (
	"sort"
	"sync"

	"github.com/raskrebs/sonar/internal/daemon/rpc"
)

// Methods that must be served by the daemon on the machine the caller is
// sitting at, and nowhere else.
//
// The socket is 0600 and local, so "the caller is on this machine" is normally
// free. `sonar daemon stdio` is the exception: it dials that socket and pumps
// bytes between it and stdin/stdout, which is how `ssh <host> sonar daemon
// stdio` gives another machine the whole protocol. From the daemon's side that
// is an ordinary local connection — the pump parses nothing and forges nothing
// — so the connection has to say what it is, which is what daemon.bridged does.
//
// The first method to need this is `session.register`, which hands the daemon a
// relay session token. Two things follow, and both are enforced here rather
// than in the handler:
//
//   - It is never forwarded. A `{"host": "prod"}` on it, or a `remote.call`
//     naming it, would put this machine's token on a machine someone else
//     administers. Both paths meet in ForwardTo.
//   - It is never accepted on a bridged connection. The other direction of the
//     same mistake: a token arriving over somebody's SSH session would make
//     this daemon share under their account.
//
// Nothing else is local-only, and `session.start`/`session.poll` deliberately
// are not: running the device flow *on* a headless box from a laptop is the
// case the device flow exists for.

var (
	localOnlyMu sync.RWMutex
	localOnly   = map[string]bool{}
)

// RegisterLocalOnly marks a method as local-only. Called from the init() of
// the package that owns the method, beside its RegisterHandler.
func RegisterLocalOnly(method string) {
	localOnlyMu.Lock()
	localOnly[method] = true
	localOnlyMu.Unlock()
}

// IsLocalOnly reports whether a method may only be served for a client on this
// machine.
func IsLocalOnly(method string) bool {
	localOnlyMu.RLock()
	defer localOnlyMu.RUnlock()
	return localOnly[method]
}

// LocalOnlyMethods lists them, sorted. `daemon.schema` does not publish this:
// it is a property of how a method is reached, not of its wire shape.
func LocalOnlyMethods() []string {
	localOnlyMu.RLock()
	out := make([]string, 0, len(localOnly))
	for m := range localOnly {
		out = append(out, m)
	}
	localOnlyMu.RUnlock()
	sort.Strings(out)
	return out
}

// errNotLocal is the refusal both halves of the guard return. It names the
// method rather than the reason in detail, because the two reasons ("you asked
// me to send it elsewhere" and "you reached me from elsewhere") are the same
// answer to the caller: do this on the machine it is about.
func errNotLocal(method, why string) *rpc.Error {
	return rpc.NewError(rpc.CodePermission,
		method+" only works for a client on the same machine as the daemon: "+why,
		"run it against that machine's own daemon")
}
