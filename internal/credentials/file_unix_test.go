//go:build !windows

package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestTheFileIsWrittenOwnerOnly(t *testing.T) {
	f := newFile(t)
	blob, _ := encode(testSession())
	if err := f.save(blob); err != nil {
		t.Fatal(err)
	}
	if m := modeOf(t, f.path); m != 0o600 {
		t.Fatalf("mode %04o, want 0600", m)
	}
	// A directory the store had to create is private too.
	if m := modeOf(t, filepath.Dir(f.path)); m != 0o700 {
		t.Fatalf("created directory mode %04o, want 0700", m)
	}
}

// umask can only take permissions away; with a umask of 0 the file must
// still come out 0600, not 0666.
func TestTheFileIsOwnerOnlyWhateverTheUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	f := newFile(t)
	blob, _ := encode(testSession())
	if err := f.save(blob); err != nil {
		t.Fatal(err)
	}
	if m := modeOf(t, f.path); m != 0o600 {
		t.Fatalf("mode %04o under umask 0, want 0600", m)
	}
}

func TestSavingOverALooseFileTightensIt(t *testing.T) {
	f := newFile(t)
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.path, 0o644); err != nil {
		t.Fatal(err)
	}
	blob, _ := encode(testSession())
	if err := f.save(blob); err != nil {
		t.Fatal(err)
	}
	if m := modeOf(t, f.path); m != 0o600 {
		t.Fatalf("mode %04o after save, want 0600", m)
	}
}

func TestALooseFileIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o620, 0o602, 0o666, 0o700} {
		s, _ := newTestStore(t, nil)
		mustSave(t, s, testSession(), InFile)
		if err := os.Chmod(s.Path(), mode); err != nil {
			t.Fatal(err)
		}
		_, _, err := s.Load()
		if mode&0o077 == 0 {
			// 0700 is owner-only; the execute bit is odd but not exposure.
			if err != nil {
				t.Fatalf("mode %04o refused: %v", mode, err)
			}
			continue
		}
		var insecure *InsecureFileError
		if !errors.As(err, &insecure) || !errors.Is(err, ErrNotSignedIn) {
			t.Fatalf("mode %04o: Load = %v; want an InsecureFileError that is not-signed-in", mode, err)
		}
		if !strings.Contains(err.Error(), "0600") {
			t.Fatalf("the error does not say what mode is wanted: %v", err)
		}
		if strings.Contains(err.Error(), testToken) {
			t.Fatal("the refusal carries the token")
		}
		// And a fresh sign-in heals it.
		mustSave(t, s, testSession(), InFile)
		if m := modeOf(t, s.Path()); m != 0o600 {
			t.Fatalf("healed mode %04o", m)
		}
		if _, _, err := s.Load(); err != nil {
			t.Fatalf("Load after healing: %v", err)
		}
	}
}

func TestASymlinkIsRefusedEvenToAPrivateFile(t *testing.T) {
	dir := t.TempDir()
	real := fileBackend{path: filepath.Join(dir, "elsewhere.json")}
	blob, _ := encode(testSession())
	if err := real.save(blob); err != nil {
		t.Fatal(err)
	}
	link := fileBackend{path: filepath.Join(dir, FileName)}
	if err := os.Symlink(real.path, link.path); err != nil {
		t.Fatal(err)
	}
	_, _, err := link.load()
	var insecure *InsecureFileError
	if !errors.As(err, &insecure) || !strings.Contains(insecure.Reason, "symbolic link") {
		t.Fatalf("load through a symlink = %v", err)
	}
	// Saving replaces the link itself, not its target.
	if err := link.save(blob); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link.path); fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("save wrote through the symlink")
	}
}

// A FIFO planted at the path must be refused, not block the daemon in open.
func TestAFIFOIsRefusedWithoutHanging(t *testing.T) {
	f := newFile(t)
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(f.path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := f.load(); done <- err }()
	select {
	case err := <-done:
		var insecure *InsecureFileError
		if !errors.As(err, &insecure) {
			t.Fatalf("load of a FIFO = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("load of a FIFO hung")
	}
}
