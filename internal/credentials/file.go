package credentials

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// maxFileBytes caps what load will read. A real record is ~400 bytes.
const maxFileBytes = 64 << 10

// InsecureFileError is a credentials file load refused to read.
//
// Refusing rather than warning, the way ssh refuses a private key others can
// read: a token that group or world could read may already be copied, and a
// warning in a daemon log nobody reads protects no one. Refusing makes the
// daemon treat the machine as signed out, and the sign-in that follows
// replaces the file atomically at 0600, so it heals itself.
type InsecureFileError struct {
	Path   string
	Reason string
}

func (e *InsecureFileError) Error() string {
	return fmt.Sprintf("refusing to read %s: %s", e.Path, e.Reason)
}

type fileBackend struct{ path string }

// load reads the file. A missing file is (zero, false, nil).
func (f fileBackend) load() (Session, bool, error) {
	file, err := openPrivate(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return Session{}, false, fmt.Errorf("reading %s: %w", f.path, err)
	}
	if len(data) > maxFileBytes {
		return Session{}, false, fmt.Errorf("%s is over %d bytes; it is not a credentials file", f.path, maxFileBytes)
	}
	sess, err := decode(data)
	if err != nil {
		return Session{}, false, fmt.Errorf("%s is unreadable: %w", f.path, err)
	}
	return sess, true, nil
}

// save replaces the file atomically: a temporary file in the same directory,
// created 0600 (os.CreateTemp's mode, which no umask can widen), synced and
// renamed over the old one. A crash leaves the old file or the new one, never
// half of one, and never a moment when the token is on disk with looser
// permissions.
func (f fileBackend) save(blob []byte) error {
	dir := filepath.Dir(f.path)
	// 0700 only when the directory has to be created; an existing
	// ~/.config/sonar keeps its mode, and the file's own 0600 is what counts.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*.json")
	if err != nil {
		return fmt.Errorf("writing %s: %w", f.path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", f.path, err)
	}
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", f.path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", f.path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", f.path, err)
	}
	if err := os.Rename(tmpName, f.path); err != nil {
		return fmt.Errorf("replacing %s: %w", f.path, err)
	}
	tmpName = ""
	syncDir(dir)
	return nil
}

// remove deletes the file. A missing file is success.
func (f fileBackend) remove() error {
	if err := os.Remove(f.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
