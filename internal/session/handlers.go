package session

import (
	"context"
	"sync"

	"github.com/raskrebs/sonar/internal/config"
	"github.com/raskrebs/sonar/internal/daemon"
	"github.com/raskrebs/sonar/internal/daemon/rpc"
)

// The manager is process-global because the daemon is: one daemon, one relay
// session. It is installed by the OnStart hook and dropped by OnShutdown, the
// way internal/remote installs its connection manager (contract §8: the
// handlers live here, and the daemon package never imports this one).
var (
	managerMu sync.RWMutex
	manager   *Manager
)

// Current returns the running manager, or nil before the daemon has started
// one. `sonar doctor` and, from phase 3, `share.create` read it.
func Current() *Manager {
	managerMu.RLock()
	defer managerMu.RUnlock()
	return manager
}

// SetManager installs a manager. Exported for the tests that drive the handlers
// against a fake relay without starting a daemon; production goes through the
// OnStart hook.
func SetManager(m *Manager) {
	managerMu.Lock()
	manager = m
	managerMu.Unlock()
}

func init() {
	daemon.RegisterHandler("session.status", handleStatus)
	daemon.RegisterHandler("session.register", handleRegister)
	daemon.RegisterHandler("session.start", handleStart)
	daemon.RegisterHandler("session.poll", handlePoll)
	daemon.RegisterHandler("session.clear", handleClear)
	daemon.RegisterCapability("session")

	// The one method here that carries a credential is the one method here
	// that must never cross a machine boundary, in either direction. See
	// internal/daemon/localonly.go for what that means and where it is
	// enforced; `session.start` and `session.poll` deliberately stay routable,
	// because running the device flow *on* a headless box from a laptop is the
	// case the device flow exists for.
	daemon.RegisterLocalOnly("session.register")

	daemon.OnStart(start)
	daemon.OnShutdown(func(bool) { SetManager(nil) })
}

func start(rt *daemon.Runtime) {
	cfg, warnings := config.Load()
	for _, w := range warnings {
		rt.Logger.Warn(w)
	}
	relay := cfg.Relay()
	SetManager(New(Options{
		Relay:   relay,
		Version: rt.Version,
		Logger:  rt.Logger,
	}))
	rt.Logger.Debug("relay session ready", "relay", relay)
}

// requireManager is the "session support is not running" guard. It cannot
// normally fail — the hook installs the manager before the first connection is
// accepted — but a handler must never dereference nil.
func requireManager() (*Manager, error) {
	m := Current()
	if m == nil {
		return nil, rpc.NewError(rpc.CodeInternal, "the relay session manager is not running", "")
	}
	return m, nil
}

func handleStatus(ctx context.Context, req *daemon.Request) (any, error) {
	var p rpc.SessionStatusParams
	if err := req.Bind(&p); err != nil {
		return nil, err
	}
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	if p.Refresh {
		return m.StatusRefreshed(ctx), nil
	}
	return m.Status(), nil
}

func handleRegister(ctx context.Context, req *daemon.Request) (any, error) {
	var p rpc.SessionRegisterParams
	if err := req.Bind(&p); err != nil {
		return nil, err
	}
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	out, err := m.Register(ctx, p.Token, p.Relay)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func handleStart(ctx context.Context, _ *daemon.Request) (any, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	out, err := m.Start(ctx)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func handlePoll(ctx context.Context, _ *daemon.Request) (any, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	out, err := m.Poll(ctx)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func handleClear(ctx context.Context, _ *daemon.Request) (any, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	out, err := m.Clear(ctx)
	if err != nil {
		// Clear reports the local session as gone even when it could not tell
		// the relay, so the error and a useful result can both be true. The
		// protocol has room for one of them; the error is the one that must
		// not be lost, because it means a session is still on this machine.
		return nil, err
	}
	return out, nil
}
