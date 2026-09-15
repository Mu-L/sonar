package share

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The per-machine install id.
//
// It exists for one thing: the fallback share key. A project with no
// `sonar.yaml` has no service to name, so there is nothing in the repository to
// key a share on, and the relay keys those on
// `(account_id, install_id, project_root, port)` instead — this machine, this
// directory, this port. Moving the project gets a new URL, and both clients
// must say so out loud rather than let someone discover it.
//
// It is not an identifier of a person and is never sent anywhere but the share
// control plane, on a request that already carries the account's session. It is
// a stable random string, created once and read thereafter.

// InstallFileName is where the id rests, beside the config and the credentials.
const InstallFileName = "install_id"

var (
	installOnce sync.Once
	installID   string
)

// InstallID returns this machine's install id, creating one on first use.
//
// A machine that cannot write the file still gets an id — a fresh one, for this
// daemon's lifetime. That is the right failure: a share published from such a
// machine works and simply does not survive a daemon restart under the same
// URL, which is strictly better than refusing to share at all. The alternative,
// a fixed fallback string, would make two unwritable machines look like one
// machine to the relay and hand them each other's slug.
func InstallID() string {
	installOnce.Do(func() { installID = loadInstallID(installPath()) })
	return installID
}

func installPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "sonar", InstallFileName)
}

func loadInstallID(path string) string {
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			if id := sanitizeInstallID(string(b)); id != "" {
				return id
			}
		}
	}
	id := newInstallID()
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
			// 0600 like the credentials file next to it. It is not a secret,
			// but it is this machine's identity to the relay and there is no
			// reason for anyone else on a shared box to read it.
			_ = os.WriteFile(path, []byte(id+"\n"), 0o600)
		}
	}
	return id
}

func newInstallID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// sanitizeInstallID accepts only what this package writes: hex, one line. A
// file someone has edited into something else is treated as absent rather than
// sent to the relay.
func sanitizeInstallID(raw string) string {
	id := strings.TrimSpace(raw)
	if len(id) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(id); err != nil {
		return ""
	}
	return id
}
