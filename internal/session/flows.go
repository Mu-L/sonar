package session

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// The flow table.
//
// One device flow per daemon was a bug with a sharp edge: the app and an inline
// `sonar share` sign-in would each call `session.start`, the second would
// replace the first, and the person watching the first screen would poll into
// "that code is no longer valid" having done nothing wrong. Neither client did
// anything unusual — they just both signed in.
//
// So flows are keyed, and two things resolve a poll to the right one:
//
//   - the flow id, handed back by `session.start` and passed to `session.poll`.
//     It is opaque and is not a credential: the device code it stands for never
//     leaves this process, which is the property that made `session.poll` take
//     no device code in the first place.
//   - the connection that started the flow. A client that never passes a flow
//     id — an older desktop, say — polls the newest flow on its own connection,
//     so it still cannot be handed someone else's code.
//
// Only a client with neither falls back to "the newest flow on the daemon",
// which is exactly what the single-pending version always did.

// newFlowID mints an id for a flow. Random rather than a counter so that ids
// are not guessable across daemons and cannot be confused between restarts —
// polling a flow id that was reused would be the same bug in a smaller window.
func newFlowID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A clock-derived id is worse and still unique within one daemon,
		// which is all this has to be. crypto/rand failing is not a reason to
		// refuse a sign-in.
		return "flow-" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// addFlow records a flow, sweeping what has died and bounding what is left.
// The caller holds m.mu.
func (m *Manager) addFlow(p *pending) {
	m.sweepFlows()
	if m.flows == nil {
		m.flows = map[string]*pending{}
	}
	m.flows[p.id] = p
	m.order = append(m.order, p.id)
	// The oldest goes first: the newest code is the one on a screen.
	for len(m.order) > maxFlows {
		delete(m.flows, m.order[0])
		m.order = m.order[1:]
	}
}

// sweepFlows drops flows whose code has aged out. The caller holds m.mu.
func (m *Manager) sweepFlows() {
	if len(m.order) == 0 {
		return
	}
	now := m.now()
	kept := m.order[:0]
	for _, id := range m.order {
		f, ok := m.flows[id]
		if !ok {
			continue
		}
		if f.expired(now) {
			delete(m.flows, id)
			continue
		}
		kept = append(kept, id)
	}
	m.order = kept
}

// resolveFlow finds the flow a poll means. The caller holds m.mu.
//
// An explicit id is exact and never falls back: a client that named a flow and
// got someone else's would be the bug this table exists to fix.
func (m *Manager) resolveFlow(id string, conn uint64) *pending {
	m.sweepFlows()
	if id != "" {
		return m.flows[id]
	}
	if conn != 0 {
		for i := len(m.order) - 1; i >= 0; i-- {
			if f := m.flows[m.order[i]]; f != nil && f.conn == conn {
				return f
			}
		}
	}
	if len(m.order) == 0 {
		return nil
	}
	return m.flows[m.order[len(m.order)-1]]
}

// dropFlow forgets one flow by id. The caller holds m.mu.
func (m *Manager) dropFlow(id string) {
	if _, ok := m.flows[id]; !ok {
		return
	}
	delete(m.flows, id)
	for i, have := range m.order {
		if have == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
}

// newest is the most recently started flow, or nil. The caller holds m.mu.
func (m *Manager) newest() *pending {
	m.sweepFlows()
	if len(m.order) == 0 {
		return nil
	}
	return m.flows[m.order[len(m.order)-1]]
}

// CancelConn forgets every flow a connection started. The daemon calls it when
// a client disconnects: an abandoned terminal should not leave a code on the
// relay being polled by nobody, and it must not be what a later poll with no
// flow id falls back onto.
func (m *Manager) CancelConn(conn uint64) {
	if conn == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range append([]string(nil), m.order...) {
		if f := m.flows[id]; f != nil && f.conn == conn {
			m.dropFlow(id)
		}
	}
}
