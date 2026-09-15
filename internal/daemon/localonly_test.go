package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/raskrebs/sonar/internal/daemon/rpc"
)

// A method registered only by this file, so the guard can be tested without
// importing the package that owns the real one (internal/session, which imports
// this package). The handler answers ok, so a refusal is unambiguously the
// guard and not a failure inside the handler.
const guardedMethod = "test.localonly"

var guardCalls = make(chan struct{}, 16)

func init() {
	RegisterHandler(guardedMethod, func(context.Context, *Request) (any, error) {
		guardCalls <- struct{}{}
		return rpc.OKResult{OK: true}, nil
	})
	RegisterLocalOnly(guardedMethod)
}

// On an ordinary socket connection a local-only method is served like any
// other: the guard is about where the caller is, not about the method being
// special.
func TestALocalOnlyMethodIsServedOnAnOrdinaryConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newHarness(t, ctx)
	c := h.dial(ctx)

	var out rpc.OKResult
	if err := c.call(guardedMethod, rpc.Empty{}, &out); err != nil {
		t.Fatalf("%s: %v", guardedMethod, err)
	}
	if !out.OK {
		t.Error("the handler did not run")
	}
	<-guardCalls
}

// Once a connection has said it is a bridge, a local-only method is refused on
// it — before the handler, so a token cannot reach the store even if the
// handler would have taken it.
func TestALocalOnlyMethodIsRefusedOnABridgedConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newHarness(t, ctx)
	c := h.dial(ctx)

	var ok rpc.OKResult
	if err := c.call("daemon.bridged", rpc.Empty{}, &ok); err != nil {
		t.Fatalf("daemon.bridged: %v", err)
	}

	err := c.call(guardedMethod, rpc.Empty{}, nil)
	if err == nil {
		t.Fatal("a bridged connection was served a local-only method")
	}
	if err.Data.Code != "permission_denied" {
		t.Errorf("code = %q, want permission_denied (%s)", err.Data.Code, err.Message)
	}
	select {
	case <-guardCalls:
		t.Fatal("the handler ran on a bridged connection")
	default:
	}

	// Ordinary methods still work: the bridge is a bridge, not a lockout.
	var hello rpc.DaemonHelloResult
	if err := c.call("daemon.hello", rpc.DaemonHelloParams{Client: "test"}, &hello); err != nil {
		t.Fatalf("daemon.hello on a bridged connection: %v", err)
	}
}

// The mark cannot be taken back. Nothing clears it, and that is what makes it
// safe for `sonar daemon stdio` to set it before it copies a byte the far side
// sent.
func TestBridgedIsOneWay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newHarness(t, ctx)
	c := h.dial(ctx)

	for range 2 {
		if err := c.call("daemon.bridged", rpc.Empty{}, nil); err != nil {
			t.Fatalf("daemon.bridged: %v", err)
		}
	}
	// A second hello is the closest thing to a reset a client has.
	if err := c.call("daemon.hello", rpc.DaemonHelloParams{Client: "test"}, nil); err != nil {
		t.Fatalf("daemon.hello: %v", err)
	}
	if err := c.call(guardedMethod, rpc.Empty{}, nil); err == nil {
		t.Fatal("a connection unmarked itself as bridged")
	}
}

// forwardRouter is a router that records what it was asked to forward. A
// local-only method must never reach it.
type forwardRouter struct{ forwarded []string }

func (r *forwardRouter) Known(name string) bool { return name == "prod" }

func (r *forwardRouter) Forward(_ context.Context, _, method string, _ json.RawMessage) (json.RawMessage, RemoteStream, error) {
	r.forwarded = append(r.forwarded, method)
	return json.RawMessage(`{"ok":true}`), nil, nil
}

// The other direction of the same mistake: a `{"host": …}` on a local-only
// method would put this machine's credential on a machine someone else
// administers.
func TestALocalOnlyMethodIsNeverForwarded(t *testing.T) {
	r := &forwardRouter{}
	SetRouter(r)
	t.Cleanup(func() { SetRouter(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newHarness(t, ctx)
	c := h.dial(ctx)

	err := c.call(guardedMethod, map[string]any{"host": "prod"}, nil)
	if err == nil {
		t.Fatal("a local-only method was forwarded to another host")
	}
	if err.Data.Code != "permission_denied" {
		t.Errorf("code = %q, want permission_denied (%s)", err.Data.Code, err.Message)
	}
	if len(r.forwarded) != 0 {
		t.Errorf("it reached the bridge anyway: %v", r.forwarded)
	}
}

// `remote.call {host, method}` is the other way to reach ForwardTo, and the
// guard sits in ForwardTo precisely so both are covered by one check. This
// exercises the seam directly: internal/remote owns the handler and cannot be
// imported from here.
func TestForwardToRefusesALocalOnlyMethod(t *testing.T) {
	r := &forwardRouter{}
	SetRouter(r)
	t.Cleanup(func() { SetRouter(nil) })

	_, err := ForwardTo(context.Background(), &Request{Method: "remote.call"}, "prod",
		guardedMethod, json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("ForwardTo forwarded a local-only method")
	}
	var re *rpc.Error
	if !errors.As(err, &re) {
		t.Fatalf("error %v is not a protocol error", err)
	}
	if re.Code != rpc.CodePermission {
		t.Errorf("code = %d (%s), want permission_denied", re.Code, rpc.CodeName(re.Code))
	}
	if len(r.forwarded) != 0 {
		t.Errorf("it reached the bridge anyway: %v", r.forwarded)
	}
}

// The registry is the list, and it is what the report is written from.
func TestTheLocalOnlyRegistryListsWhatIsRegistered(t *testing.T) {
	found := false
	for _, m := range LocalOnlyMethods() {
		if m == guardedMethod {
			found = true
		}
	}
	if !found {
		t.Errorf("LocalOnlyMethods() = %v, missing %s", LocalOnlyMethods(), guardedMethod)
	}
	if !IsLocalOnly(guardedMethod) {
		t.Errorf("IsLocalOnly(%s) = false", guardedMethod)
	}
	if IsLocalOnly("ports.list") {
		t.Error("ports.list is local-only, which would break every remote host")
	}
}
