package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveRelayPrefersTheEnvironmentThenTheConfig(t *testing.T) {
	if got, warn := ResolveRelay("https://relay.env", "https://relay.config"); got != "https://relay.env" || warn != "" {
		t.Errorf("ResolveRelay(env, config) = %q, %q", got, warn)
	}
	if got, warn := ResolveRelay("", "https://relay.config"); got != "https://relay.config" || warn != "" {
		t.Errorf("ResolveRelay(\"\", config) = %q, %q", got, warn)
	}
	if got, warn := ResolveRelay("", ""); got != DefaultRelay || warn != "" {
		t.Errorf("ResolveRelay(\"\", \"\") = %q, %q, want %q", got, warn, DefaultRelay)
	}
}

// The relay is an origin: a path on it would end up doubled in front of every
// route, and a trailing slash would give `//v1/device/code`.
func TestResolveRelayKeepsOnlyTheOrigin(t *testing.T) {
	for _, raw := range []string{
		"https://relay.example/",
		"https://relay.example/v1",
		"https://relay.example/?x=1",
	} {
		if got, _ := ResolveRelay("", raw); got != "https://relay.example" {
			t.Errorf("ResolveRelay(%q) = %q", raw, got)
		}
	}
	if got, _ := ResolveRelay("", "http://127.0.0.1:8080"); got != "http://127.0.0.1:8080" {
		t.Errorf("a local http relay was rewritten: %q", got)
	}
}

// A mistyped relay must not take the daemon down: it falls back and says what
// it ignored.
func TestResolveRelayWarnsAboutWhatItIgnores(t *testing.T) {
	for _, raw := range []string{"relay.example", "ftp://relay.example", "https://"} {
		got, warn := ResolveRelay("", raw)
		if got != DefaultRelay {
			t.Errorf("ResolveRelay(%q) = %q, want the default", raw, got)
		}
		if warn == "" || !strings.Contains(warn, raw) {
			t.Errorf("ResolveRelay(%q) warned %q, which does not name the value", raw, warn)
		}
	}
}

// The setting is read from the file the rest of the config comes from, and a
// bad one is dropped with a warning rather than kept.
func TestTheRelaySettingLoadsFromTheConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("share:\n  relay: https://relay.example/v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, warnings := LoadFrom(path)
	if len(warnings) != 0 {
		t.Errorf("warnings = %v", warnings)
	}
	if got := cfg.Relay(); got != "https://relay.example" {
		t.Errorf("cfg.Relay() = %q", got)
	}

	if err := os.WriteFile(path, []byte("share:\n  relay: nonsense\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, warnings = LoadFrom(path)
	if len(warnings) == 0 {
		t.Error("a nonsense relay loaded with no warning")
	}
	if got := cfg.Relay(); got != DefaultRelay {
		t.Errorf("cfg.Relay() = %q, want the default", got)
	}
}

// `sonar config set share.relay …` goes through the map store, and a value the
// loader would only warn about is refused there instead of being written.
func TestTheConfigStoreRefusesABadRelay(t *testing.T) {
	if err := validateMap(map[string]any{"share": map[string]any{"relay": "nonsense"}}); err == nil {
		t.Error("the config store accepted a relay that is not a URL")
	}
	if err := validateMap(map[string]any{"share": map[string]any{"relay": "https://relay.example"}}); err != nil {
		t.Errorf("the config store refused a good relay: %v", err)
	}
}
