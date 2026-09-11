package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newFile(t *testing.T) fileBackend {
	t.Helper()
	return fileBackend{path: filepath.Join(t.TempDir(), "nested", "sonar", FileName)}
}

func TestTheFileRoundTripsAndCreatesItsDirectory(t *testing.T) {
	f := newFile(t)
	blob, _ := encode(testSession())
	if err := f.save(blob); err != nil {
		t.Fatal(err)
	}
	got, ok, err := f.load()
	if err != nil || !ok || got.Token.Reveal() != testToken || got.Account.ID != "acc_1" {
		t.Fatalf("load = %v, %v", ok, err)
	}
}

func TestAMissingFileIsNotAnError(t *testing.T) {
	f := newFile(t)
	if _, ok, err := f.load(); ok || err != nil {
		t.Fatalf("load of nothing = %v, %v", ok, err)
	}
	if err := f.remove(); err != nil {
		t.Fatalf("remove of nothing = %v", err)
	}
}

func TestSaveLeavesNoTemporaryFilesBehind(t *testing.T) {
	f := newFile(t)
	blob, _ := encode(testSession())
	for i := 0; i < 3; i++ {
		if err := f.save(blob); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(f.path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != FileName {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v", names)
	}
}

func TestSaveReplacesTheOldContent(t *testing.T) {
	f := newFile(t)
	a, _ := encode(Session{Token: "first"})
	b, _ := encode(Session{Token: "second"})
	_ = f.save(a)
	if err := f.save(b); err != nil {
		t.Fatal(err)
	}
	got, _, _ := f.load()
	if got.Token.Reveal() != "second" {
		t.Fatalf("got %q", got.Token.Reveal())
	}
}

func TestCorruptOrForeignFilesAreRefusedAsNotSignedIn(t *testing.T) {
	for name, body := range map[string]string{
		"garbage":   "{{{",
		"no token":  `{"version":1,"token":""}`,
		"newer":     `{"version":9,"token":"x"}`,
		"oversized": `{"version":1,"token":"` + strings.Repeat("x", maxFileBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := newTestStore(t, nil)
			if err := s.file.save([]byte(body)); err != nil {
				t.Fatal(err)
			}
			_, _, err := s.Load()
			if !errors.Is(err, ErrNotSignedIn) {
				t.Fatalf("Load = %v; want not signed in", err)
			}
			if !strings.Contains(err.Error(), s.Path()) {
				t.Fatalf("the error does not name the file: %v", err)
			}
			// A fresh sign-in heals it.
			mustSave(t, s, testSession(), InFile)
			if _, _, err := s.Load(); err != nil {
				t.Fatalf("Load after re-saving = %v", err)
			}
		})
	}
}

func TestTheFileIsNeverReadWhenItIsADirectory(t *testing.T) {
	f := newFile(t)
	if err := os.MkdirAll(f.path, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err := f.load()
	var insecure *InsecureFileError
	if !errors.As(err, &insecure) {
		t.Fatalf("load of a directory = %v", err)
	}
}
