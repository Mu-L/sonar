package state

import (
	"encoding/json"
	"testing"
)

// The share rename retired three published keys rather than dropping them, so
// a client built against the previous schema still finds them: `tunnels` and
// `exposures_active` on the snapshot and `exposed_urls` on a port row. They
// must marshal as an empty array or zero, never null or absent, until they are
// deleted in the release after the one that retired them (2026-09-11).
func TestRetiredKeysStillMarshal(t *testing.T) {
	snap := Rows{Ports: []Port{{Port: 3000, ExposedURLs: []string{}}}}.Tag(LocalhostName).Into(Snapshot{})
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"tunnels", "shares"} {
		if v, ok := m[key].([]any); !ok || v == nil {
			t.Errorf("snapshot %q = %v, want []", key, m[key])
		}
	}
	for _, key := range []string{"exposures_active", "shares_active"} {
		if v, ok := m[key].(float64); !ok || v != 0 {
			t.Errorf("snapshot %q = %v, want 0", key, m[key])
		}
	}

	port := m["ports"].([]any)[0].(map[string]any)
	for _, key := range []string{"exposed_urls", "shares"} {
		if v, ok := port[key].([]any); !ok || v == nil {
			t.Errorf("port %q = %v, want []", key, port[key])
		}
	}

	d, err := json.Marshal(Diff(Snapshot{}, snap))
	if err != nil {
		t.Fatal(err)
	}
	var dm map[string]any
	if err := json.Unmarshal(d, &dm); err != nil {
		t.Fatal(err)
	}
	if v, ok := dm["exposures_active"].(float64); !ok || v != 0 {
		t.Errorf("delta exposures_active = %v, want 0", dm["exposures_active"])
	}
	if _, ok := dm["shares"].(map[string]any); !ok {
		t.Errorf("delta has no shares change: %v", dm["shares"])
	}
}
