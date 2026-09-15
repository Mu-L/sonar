package share

import (
	"testing"

	"github.com/raskrebs/sonar/internal/daemon/rpc"
	"github.com/raskrebs/sonar/internal/state"
)

func mustResolve(t *testing.T, snap state.Snapshot, port int) target {
	t.Helper()
	got, err := resolveTarget(snap, rpc.Selector{Port: &port})
	if err != nil {
		t.Fatalf("resolving port %d: %v", port, err)
	}
	return got
}

func TestACommittedServiceResolvesToTheCommittedKey(t *testing.T) {
	got := mustResolve(t, committedSnapshot(3000, "acme", "feature", "web"), 3000)
	if !got.committed() {
		t.Fatal("a service from a sonar.yaml did not get the committed key")
	}
	if got.Repo != "acme" || got.Worktree != "acme@feature" || got.Service != "web" {
		t.Fatalf("key = (%q, %q, %q)", got.Repo, got.Worktree, got.Service)
	}
}

// The relay's committed key needs all three columns set, and a main checkout's
// Group.Worktree is empty. The group name stands in, and it can never collide
// with a linked worktree's name because that one is spelled `repo@worktree`.
func TestAMainCheckoutGetsAWorktreeColumn(t *testing.T) {
	got := mustResolve(t, committedSnapshot(3000, "acme", "", "web"), 3000)
	if got.Worktree == "" {
		t.Fatal("the main checkout sent an empty worktree; the relay's unique index would not dedupe it")
	}
	if got.Worktree != "acme" {
		t.Fatalf("worktree = %q, want the group name", got.Worktree)
	}
	// A linked worktree's column is the whole group name, so it is never the
	// bare directory name that could collide with a repository's.
	wt := mustResolve(t, committedSnapshot(3000, "acme", "feature", "web"), 3000)
	if wt.Worktree != "acme@feature" {
		t.Fatalf("a linked worktree's column = %q, want the group name", wt.Worktree)
	}

	// And it is a different key from a worktree that happens to be called
	// "acme", which is what stops two checkouts sharing a URL.
	other := mustResolve(t, committedSnapshot(3000, "acme", "acme", "web"), 3000)
	if sameKey(got, other) {
		t.Fatal("a main checkout and a worktree named after the repo got the same key")
	}
}

func TestAPortWithNoConfigFallsBackToTheMachineAndDirectory(t *testing.T) {
	got := mustResolve(t, fallbackSnapshot(8080, "/tmp/scratch"), 8080)
	if got.committed() {
		t.Fatal("a port with no group got the committed key")
	}
	if got.ProjectRoot != "/tmp/scratch" || got.Port != 8080 {
		t.Fatalf("fallback key = (%q, %d)", got.ProjectRoot, got.Port)
	}
}

// A group that exists but has no sonar.yaml service on this port — a compose
// project, a git root the scanner guessed — is still the fallback key. There is
// no service name to put in the committed one.
func TestAGroupWithNoMatchingServiceIsStillTheFallback(t *testing.T) {
	root := "/src/acme"
	name := "acme"
	snap := snapWith(state.Port{Port: 3000, Group: &name, ProjectRoot: &root})
	snap.Groups = []state.Group{{
		Host: state.LocalhostName, Name: name, Repo: name, RootDir: &root,
		Services: []state.Service{{Name: "api", PortActual: ptr(4000)}},
	}}
	got := mustResolve(t, snap, 3000)
	if got.committed() {
		t.Fatalf("port 3000 took the key of the service on 4000: %+v", got)
	}
	if got.ProjectRoot != root {
		t.Fatalf("project root = %q", got.ProjectRoot)
	}
}

// A `port: auto` service is where PortActual is, not where Port says.
func TestAnAutoPortServiceIsFoundByWhereItActuallyIs(t *testing.T) {
	root := "/src/acme"
	name := "acme"
	snap := snapWith(state.Port{Port: 3001, Group: &name, ProjectRoot: &root})
	snap.Groups = []state.Group{{
		Host: state.LocalhostName, Name: name, Repo: name, RootDir: &root,
		Services: []state.Service{{Name: "web", PortAuto: true, PortActual: ptr(3001)}},
	}}
	got := mustResolve(t, snap, 3001)
	if got.Service != "web" {
		t.Fatalf("service = %q, want web", got.Service)
	}
}

// One service that bound both 127.0.0.1 and ::1 is two rows and one target.
func TestADualStackServiceIsOneTarget(t *testing.T) {
	snap := snapWith(
		state.Port{Port: 3000, PID: 99, BindAddress: "127.0.0.1", Cwd: "/src/x"},
		state.Port{Port: 3000, PID: 99, BindAddress: "::1", Cwd: "/src/x"},
	)
	if _, err := resolveTarget(snap, rpc.Selector{Port: ptr(3000)}); err != nil {
		t.Fatalf("a dual-stack service was ambiguous: %v", err)
	}
}

func TestTwoProcessesOnOnePortAreAmbiguous(t *testing.T) {
	snap := snapWith(
		state.Port{Port: 3000, PID: 1, BindAddress: "127.0.0.1"},
		state.Port{Port: 3000, PID: 2, BindAddress: "192.168.1.9"},
	)
	_, err := resolveTarget(snap, rpc.Selector{Port: ptr(3000)})
	if err == nil {
		t.Fatal("two processes on one port resolved to one target")
	}
}

// A share is a tunnel from this machine. A remote host's port is a different
// daemon's business.
func TestARemoteHostsPortIsNotShareable(t *testing.T) {
	snap := snapWith(state.Port{Host: "buildbox", Port: 3000})
	_, err := resolveTarget(snap, rpc.Selector{Port: ptr(3000)})
	if err == nil {
		t.Fatal("a remote host's port was accepted as a share target")
	}
}

func TestNormalizeTTLTakesTheThreeChoicesAndNothingElse(t *testing.T) {
	for _, in := range []string{"", "while-it-runs", "while_it_runs", "WHILE-IT-RUNS"} {
		if got, ok := NormalizeTTL(in); !ok || got != TTLWhileItRuns {
			t.Fatalf("NormalizeTTL(%q) = %q, %v", in, got, ok)
		}
	}
	if got, ok := NormalizeTTL("1h"); !ok || got != TTLOneHour {
		t.Fatalf("1h = %q, %v", got, ok)
	}
	if got, ok := NormalizeTTL("1d"); !ok || got != TTLOneDay {
		t.Fatalf("1d = %q, %v", got, ok)
	}
	if _, ok := NormalizeTTL("7d"); ok {
		t.Fatal("7d was accepted; 24h is the ceiling")
	}
}

func TestTheInstallIDIsStableAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/install_id"

	first := loadInstallID(path)
	if len(first) != 32 {
		t.Fatalf("install id = %q", first)
	}
	if second := loadInstallID(path); second != first {
		t.Fatalf("the install id moved: %q then %q", first, second)
	}
	if sanitizeInstallID("not hex at all") != "" {
		t.Fatal("a hand-edited file was accepted")
	}
}
