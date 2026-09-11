package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// fakeKeychain is a keychain that is a variable, with injectable failures.
type fakeKeychain struct {
	mu                     sync.Mutex
	secret                 *string
	getErr, setErr, delErr error
	gets, sets, dels       int
}

func (k *fakeKeychain) Get() (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gets++
	if k.getErr != nil {
		return "", k.getErr
	}
	if k.secret == nil {
		return "", ErrNotFound
	}
	return *k.secret, nil
}

func (k *fakeKeychain) Set(s string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sets++
	if k.setErr != nil {
		return k.setErr
	}
	k.secret = &s
	return nil
}

func (k *fakeKeychain) Delete() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dels++
	if k.delErr != nil {
		return k.delErr
	}
	if k.secret == nil {
		return ErrNotFound
	}
	k.secret = nil
	return nil
}

const testToken = "tok_4f9a1c2e8b7d6a5f3e2d1c0b9a8f7e6d5c4b3a2"

func testSession() Session {
	return Session{
		Token:   Token(testToken),
		Relay:   "https://relay.trysonar.dev",
		Account: Account{ID: "acc_1", DisplayName: "Ada", Email: "ada@example.com", Provider: "github"},
	}
}

// newTestStore returns a store in a temp dir with a clock the test moves.
func newTestStore(t *testing.T, kc Keychain) (*Store, *time.Time) {
	t.Helper()
	s := New(filepath.Join(t.TempDir(), "sonar", FileName), kc)
	clock := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	return s, &clock
}

func mustSave(t *testing.T, s *Store, sess Session, want Location) {
	t.Helper()
	got, err := s.Save(sess)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got != want {
		t.Fatalf("Save went to %q, want %q", got, want)
	}
}

func fileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	return err == nil
}

func TestSaveGoesToTheKeychainAndLeavesNoFile(t *testing.T) {
	kc := &fakeKeychain{}
	s, _ := newTestStore(t, kc)
	// A file from an earlier fallback must not survive a keychain save.
	if err := s.file.save([]byte(`{"version":1,"token":"old"}`)); err != nil {
		t.Fatal(err)
	}

	mustSave(t, s, testSession(), InKeychain)

	if fileExists(t, s.Path()) {
		t.Fatal("the fallback file is still there after a keychain save")
	}
	got, loc, err := s.Load()
	if err != nil || loc != InKeychain {
		t.Fatalf("Load = %v, %v", loc, err)
	}
	if got.Token.Reveal() != testToken || got.Account.Email != "ada@example.com" || got.Relay != "https://relay.trysonar.dev" {
		t.Fatalf("round trip lost data: %+v", got.Account)
	}
}

func TestWithNoKeychainTheSessionGoesToTheFile(t *testing.T) {
	s, _ := newTestStore(t, nil)
	mustSave(t, s, testSession(), InFile)
	got, loc, err := s.Load()
	if err != nil || loc != InFile || got.Token.Reveal() != testToken {
		t.Fatalf("Load = %v, %v", loc, err)
	}
}

func TestAnUnavailableKeychainFallsBackToTheFileQuietly(t *testing.T) {
	kc := &fakeKeychain{getErr: ErrUnavailable, setErr: ErrUnavailable, delErr: ErrUnavailable}
	s, _ := newTestStore(t, kc)
	mustSave(t, s, testSession(), InFile)
	if kc.dels != 0 {
		t.Fatal("Save asked an unavailable keychain to delete")
	}
	if _, loc, err := s.Load(); err != nil || loc != InFile {
		t.Fatalf("Load = %v, %v", loc, err)
	}
	if err := s.Clear(); err != nil {
		t.Fatalf("Clear with no keychain: %v", err)
	}
}

// A keychain that is there but refuses a write (locked, denied, timed out)
// may still hold an older session. The newer file must win.
func TestARefusingKeychainCannotBringBackAnOlderSession(t *testing.T) {
	kc := &fakeKeychain{}
	s, clock := newTestStore(t, kc)
	old := testSession()
	old.Token = "old-token"
	mustSave(t, s, old, InKeychain)

	*clock = clock.Add(time.Hour)
	kc.setErr = errors.New("User interaction is not allowed.")
	kc.delErr = errors.New("User interaction is not allowed.")
	mustSave(t, s, testSession(), InFile)
	if kc.dels != 1 {
		t.Fatalf("expected one best-effort delete of the older item, got %d", kc.dels)
	}

	// The keychain unlocks later and still has the old item.
	kc.setErr, kc.delErr = nil, nil
	got, loc, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loc != InFile || got.Token.Reveal() != testToken {
		t.Fatalf("Load returned the %s copy with the older token", loc)
	}
}

func TestTheNewerCopyWins(t *testing.T) {
	kc := &fakeKeychain{}
	s, clock := newTestStore(t, kc)

	// keychain older, file newer
	mustSave(t, s, Session{Token: "k1"}, InKeychain)
	*clock = clock.Add(time.Minute)
	blob, _ := encode(Session{Token: "f1", SavedAt: *clock})
	if err := s.file.save(blob); err != nil {
		t.Fatal(err)
	}
	if got, loc, _ := s.Load(); loc != InFile || got.Token.Reveal() != "f1" {
		t.Fatalf("newer file lost: %s %s", loc, got.Token.Reveal())
	}

	// keychain newer
	*clock = clock.Add(time.Minute)
	blob, _ = encode(Session{Token: "k2", SavedAt: *clock})
	_ = kc.Set(string(blob))
	if got, loc, _ := s.Load(); loc != InKeychain || got.Token.Reveal() != "k2" {
		t.Fatalf("newer keychain item lost: %s %s", loc, got.Token.Reveal())
	}
}

func TestNothingStoredIsNotSignedIn(t *testing.T) {
	s, _ := newTestStore(t, &fakeKeychain{})
	_, loc, err := s.Load()
	if !errors.Is(err, ErrNotSignedIn) || loc != "" {
		t.Fatalf("Load = %q, %v; want not signed in", loc, err)
	}
	if err != ErrNotSignedIn {
		t.Fatalf("with nothing wrong there should be no cause attached: %v", err)
	}
}

func TestAKeychainThatCannotBeReadIsNotSignedInWithTheReason(t *testing.T) {
	s, _ := newTestStore(t, &fakeKeychain{getErr: ErrTimeout})
	_, _, err := s.Load()
	if !errors.Is(err, ErrNotSignedIn) || !errors.Is(err, ErrTimeout) {
		t.Fatalf("Load = %v; want not signed in, caused by the timeout", err)
	}
	if !strings.Contains(err.Error(), "keychain") {
		t.Fatalf("the reason does not name the keychain: %v", err)
	}
}

func TestACorruptKeychainItemFallsBackToTheFile(t *testing.T) {
	garbage := "not json"
	kc := &fakeKeychain{secret: &garbage}
	s, _ := newTestStore(t, kc)
	blob, _ := encode(testSession())
	if err := s.file.save(blob); err != nil {
		t.Fatal(err)
	}
	if _, loc, err := s.Load(); err != nil || loc != InFile {
		t.Fatalf("Load = %v, %v", loc, err)
	}
	_ = s.file.remove()
	if _, _, err := s.Load(); !errors.Is(err, ErrNotSignedIn) || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("Load = %v", err)
	}
}

func TestClearRemovesBothCopies(t *testing.T) {
	kc := &fakeKeychain{}
	s, _ := newTestStore(t, kc)
	mustSave(t, s, testSession(), InKeychain)
	blob, _ := encode(testSession())
	_ = s.file.save(blob)

	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if kc.secret != nil || fileExists(t, s.Path()) {
		t.Fatal("a copy survived Clear")
	}
	// Clearing nothing is success.
	if err := s.Clear(); err != nil {
		t.Fatalf("second Clear: %v", err)
	}
	if _, _, err := s.Load(); !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("Load after Clear = %v", err)
	}
}

func TestClearDeletesTheFileEvenWhenTheKeychainRefuses(t *testing.T) {
	kc := &fakeKeychain{delErr: errors.New("locked")}
	s, _ := newTestStore(t, kc)
	blob, _ := encode(testSession())
	_ = s.file.save(blob)

	err := s.Clear()
	if err == nil || !strings.Contains(err.Error(), "keychain") {
		t.Fatalf("Clear = %v; want the keychain's refusal reported", err)
	}
	if fileExists(t, s.Path()) {
		t.Fatal("the file survived because the keychain refused")
	}
}

func TestSaveRefusesAnEmptyToken(t *testing.T) {
	kc := &fakeKeychain{}
	s, _ := newTestStore(t, kc)
	if _, err := s.Save(Session{Account: Account{ID: "a"}}); err == nil {
		t.Fatal("stored a session with no token")
	}
	if kc.sets != 0 || fileExists(t, s.Path()) {
		t.Fatal("something was written")
	}
}

func TestARecordTooBigForTheKeychainGoesToTheFile(t *testing.T) {
	kc := &fakeKeychain{}
	s, _ := newTestStore(t, kc)
	big := testSession()
	big.Account.AvatarURL = "https://example.com/" + strings.Repeat("a", 3000)
	mustSave(t, s, big, InFile)
	if kc.sets != 0 {
		t.Fatal("an oversized record was sent to the keychain")
	}
	if got, _, err := s.Load(); err != nil || got.Account.AvatarURL != big.Account.AvatarURL {
		t.Fatalf("Load = %v", err)
	}
}

func TestSaveStampsSavedAt(t *testing.T) {
	s, clock := newTestStore(t, nil)
	sess := testSession()
	sess.SavedAt = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC) // ignored
	mustSave(t, s, sess, InFile)
	got, _, _ := s.Load()
	if !got.SavedAt.Equal(*clock) {
		t.Fatalf("SavedAt = %v, want %v", got.SavedAt, *clock)
	}
}

func TestARecordFromANewerSonarIsRefused(t *testing.T) {
	if _, err := decode([]byte(`{"version":2,"token":"x"}`)); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("decode = %v", err)
	}
	if _, err := decode([]byte(`{"token":"x"}`)); err == nil {
		t.Fatal("a record with no version was accepted")
	}
	if _, err := decode([]byte(`{"version":1,"token":""}`)); err == nil {
		t.Fatal("a record with no token was accepted")
	}
}

// The token must not come out of any printing path a careless log line or
// RPC response could take.
func TestTheTokenIsNeverPrinted(t *testing.T) {
	sess := testSession()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		for _, arg := range []any{sess, &sess, sess.Token} {
			if out := fmt.Sprintf(verb, arg); strings.Contains(out, testToken) || strings.Contains(out, fmt.Sprintf("%x", testToken)) {
				t.Fatalf("%s of %T printed the token: %s", verb, arg, out)
			}
		}
	}
	if out := fmt.Sprint(sess); !strings.Contains(out, redacted) {
		t.Fatalf("expected the redaction marker in %s", out)
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("signed in", "token", sess.Token, "session", sess)
	if strings.Contains(buf.String(), testToken) {
		t.Fatalf("slog printed the token: %s", buf.String())
	}

	if b, err := json.Marshal(sess); err == nil {
		t.Fatalf("a Session marshalled to JSON: %s", b)
	}
	if b, err := yaml.Marshal(sess); err == nil && strings.Contains(string(b), testToken) {
		t.Fatalf("a Session marshalled to YAML with the token: %s", b)
	}
	// The account alone is safe to hand over.
	if _, err := json.Marshal(sess.Account); err != nil {
		t.Fatal(err)
	}
}

func TestErrorsNeverCarryTheToken(t *testing.T) {
	s, _ := newTestStore(t, &fakeKeychain{setErr: errors.New("refused"), delErr: errors.New("refused")})
	// Make the file write fail too: its directory is a file.
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(s.Path())), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Dir(s.Path()), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Save(testSession())
	if err == nil {
		t.Fatal("Save succeeded with nowhere to write")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("the error carries the token: %v", err)
	}
}

func TestDefaultHonoursTheFileOnlySwitch(t *testing.T) {
	t.Setenv(StoreEnv, "file")
	if Default().keychain != nil {
		t.Fatalf("%s=file still uses the keychain", StoreEnv)
	}
	t.Setenv(StoreEnv, "")
	if Default().keychain == nil {
		t.Fatal("the default store has no keychain")
	}
}

func TestDefaultPathIsBesideTheConfig(t *testing.T) {
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".config", "sonar", "credentials.json")
	if got := DefaultPath(); got != want {
		t.Fatalf("DefaultPath = %s, want %s", got, want)
	}
}
