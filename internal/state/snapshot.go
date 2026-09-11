package state

// Snapshot is the full published state at one sequence number. Contract §5
// fixes the five collections and the top-level SharesActive counter; the
// remote-hosts design adds a sixth, `hosts`, which always carries at least the
// daemon's own machine.
type Snapshot struct {
	Seq           uint64 `json:"seq"`
	At            string `json:"at"`
	DaemonVersion string `json:"daemon_version"`
	SharesActive  int    `json:"shares_active"`
	// ExposuresActive is retired: nothing sets it, so it always marshals as 0
	// and a client built against the old schema still finds the key.
	// Deprecated 2026-09-11 in favour of SharesActive; delete it in the release
	// after the one that ships this comment.
	ExposuresActive int     `json:"exposures_active"`
	Ports           []Port  `json:"ports"`
	Groups          []Group `json:"groups"`
	Shares          []Share `json:"shares"`
	// Tunnels is retired: it always marshals as [], because a desktop built
	// against the old schema indexes `snapshot.tunnels` without a guard.
	// Deprecated 2026-09-11 in favour of Shares; delete it in the release
	// after the one that ships this comment. Delta has no counterpart: that
	// client already treats an absent delta collection as unchanged.
	Tunnels  []Share         `json:"tunnels"`
	Proxies  []Proxy         `json:"proxies"`
	Sessions []SessionRecord `json:"sessions"`
	Hosts    []Host          `json:"hosts"`
}
