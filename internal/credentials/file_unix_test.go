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

// A perfectly good 0600 file is still not private when the directory holding
// it can be written by someone else: they can rename it away and leave their
// own in its place, and every check on the file itself would pass.
func TestAFineFileInALooseDirectoryIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o777, 0o775, 0o707, 0o702, 0o770} {
		s, _ := newTestStore(t, nil)
		mustSave(t, s, testSession(), InFile)
		dir := filepath.Dir(s.Path())
		if m := modeOf(t, s.Path()); m != 0o600 {
			t.Fatalf("the file itself is %04o, so this would test the wrong thing", m)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}

		_, _, err := s.Load()
		var insecure *InsecureFileError
		if !errors.As(err, &insecure) || !errors.Is(err, ErrNotSignedIn) {
			t.Fatalf("directory mode %04o: Load = %v; want an InsecureFileError that is not-signed-in", mode, err)
		}
		if insecure.Path != dir {
			t.Fatalf("the error names %s, not the directory %s", insecure.Path, dir)
		}
		if !strings.Contains(err.Error(), "chmod 700") {
			t.Fatalf("the error does not say how to fix it: %v", err)
		}
		if strings.Contains(err.Error(), testToken) {
			t.Fatal("the refusal carries the token")
		}

		// Self-healing, as with a loose file: signing in again tightens the
		// directory and the session is readable once more.
		mustSave(t, s, testSession(), InFile)
		if m := modeOf(t, dir); m&0o022 != 0 {
			t.Fatalf("directory left at %04o after a save", m)
		}
		if _, _, err := s.Load(); err != nil {
			t.Fatalf("Load after healing: %v", err)
		}
	}
}

// Others being able to list the directory is not exposure: the file in it is
// 0600. Only write permission lets them swap it.
func TestAReadableButUnwritableDirectoryIsFine(t *testing.T) {
	s, _ := newTestStore(t, nil)
	mustSave(t, s, testSession(), InFile)
	dir := filepath.Dir(s.Path())
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); err != nil {
		t.Fatalf("Load from a 0755 directory = %v", err)
	}
	// And a save leaves that mode alone rather than surprising the user.
	mustSave(t, s, testSession(), InFile)
	if m := modeOf(t, dir); m != 0o755 {
		t.Fatalf("save changed a 0755 directory to %04o", m)
	}
}

func TestSavingIntoALooseDirectoryTightensItFirst(t *testing.T) {
	s, _ := newTestStore(t, nil)
	dir := filepath.Dir(s.Path())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}

	mustSave(t, s, testSession(), InFile)

	m := modeOf(t, dir)
	if m&0o022 != 0 {
		t.Fatalf("a token was written into a directory left at %04o", m)
	}
	if m != 0o755 {
		t.Fatalf("mode %04o: only the write bits should have gone from 0777", m)
	}
	if _, _, err := s.Load(); err != nil {
		t.Fatalf("Load = %v", err)
	}
}

// The keychain still wins over a file that cannot be trusted — and when
// neither store yields a session, the reason survives for doctor to show.
func TestALooseDirectoryDoesNotHideAGoodKeychainSession(t *testing.T) {
	kc := &fakeKeychain{}
	s, clock := newTestStore(t, kc)
	mustSave(t, s, testSession(), InKeychain)

	// A file left by an earlier fallback, in a directory others can write.
	*clock = clock.Add(time.Hour)
	blob, _ := encode(Session{Token: "planted", SavedAt: *clock})
	if err := s.file.save(blob); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(s.Path()), 0o777); err != nil {
		t.Fatal(err)
	}

	got, loc, err := s.Load()
	if err != nil || loc != InKeychain || got.Token.Reveal() != testToken {
		t.Fatalf("Load = %s, %v; want the keychain's session", loc, err)
	}

	// With no keychain session, that same refusal is what doctor gets to show.
	kc.secret = nil
	_, _, err = s.Load()
	var insecure *InsecureFileError
	if !errors.As(err, &insecure) || !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("Load = %v; want the directory's refusal preserved", err)
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
