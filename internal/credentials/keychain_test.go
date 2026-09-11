package credentials

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

func TestBoundedGivesUpOnAKeychainThatDoesNotAnswer(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	_, err := bounded(50*time.Millisecond, func() (string, error) {
		<-release
		return "late", nil
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("bounded waited far past its timeout")
	}
}

func TestBoundedPassesAnswersThrough(t *testing.T) {
	v, err := bounded(time.Second, func() (string, error) { return "v", nil })
	if v != "v" || err != nil {
		t.Fatalf("bounded = %q, %v", v, err)
	}
	boom := errors.New("boom")
	if _, err := bounded(time.Second, func() (int, error) { return 0, boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

func TestClassifyMapsGoKeyringOntoThreeErrors(t *testing.T) {
	cases := []struct {
		in   error
		want error
	}{
		{keyring.ErrNotFound, ErrNotFound},
		{keyring.ErrUnsupportedPlatform, ErrUnavailable},
		// Observed verbatim in ubuntu:22.04 with dbus-x11 and no keyring.
		{errors.New("The name org.freedesktop.secrets was not provided by any .service files"), ErrUnavailable},
		// Observed verbatim in ubuntu:22.04 with no dbus at all.
		{&exec.Error{Name: "dbus-launch", Err: exec.ErrNotFound}, ErrUnavailable},
		{ErrTimeout, ErrTimeout},
	}
	for _, c := range cases {
		if got := classify(c.in); !errors.Is(got, c.want) {
			t.Errorf("classify(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	// A locked collection is not "unavailable": a session may be in there.
	locked := errors.New("failed to unlock correct collection '/org/freedesktop/secrets/aliases/default'")
	got := classify(locked)
	if errors.Is(got, ErrUnavailable) || errors.Is(got, ErrNotFound) || !errors.Is(got, locked) {
		t.Fatalf("classify(locked) = %v", got)
	}
	if classify(nil) != nil {
		t.Fatal("classify(nil) is not nil")
	}
}

func TestTheSessionBusIsOnlyUsedWhenItIsAlreadyThere(t *testing.T) {
	none := func(string) (os.FileInfo, error) { return nil, fs.ErrNotExist }
	only := func(want string) func(string) (os.FileInfo, error) {
		return func(p string) (os.FileInfo, error) {
			if p == want {
				return nil, nil
			}
			return nil, fs.ErrNotExist
		}
	}
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "DBUS_SESSION_BUS_ADDRESS" {
				return v
			}
			return ""
		}
	}
	cases := []struct {
		name string
		env  string
		stat func(string) (os.FileInfo, error)
		want bool
	}{
		{"headless: nothing at all", "", none, false},
		{"address in the environment", "unix:path=/run/user/1000/bus", none, true},
		{"autolaunch is not an address", "autolaunch:", none, false},
		{"systemd user bus socket", "", only("/run/user/1000/bus"), true},
		{"dbus-session file", "", only("/run/user/1000/dbus-session"), true},
		{"another user's bus", "", only("/run/user/1001/bus"), false},
	}
	for _, c := range cases {
		if got := sessionBusKnown(env(c.env), c.stat, 1000); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestTheRealKeychainRoundTrips exercises the OS keychain through the whole
// store. Off by default — on macOS it writes a login-keychain item, and on a
// headless box there is nothing to talk to. Run it by hand with
//
//	SONAR_TEST_REAL_KEYCHAIN=1 SONAR_TEST_REAL_HOME=$HOME \
//	  go test ./internal/credentials -run RealKeychain -v
//
// SONAR_TEST_REAL_HOME is needed because macOS resolves the login keychain
// through HOME and TestMain moves HOME into a sandbox; without it every
// operation fails and the store falls back to the file, which is a real
// behaviour worth knowing (a daemon launched with a different HOME stores its
// session in the file) but not what this test is for.
//
// It uses a test-named service and deletes its item.
func TestTheRealKeychainRoundTrips(t *testing.T) {
	if os.Getenv("SONAR_TEST_REAL_KEYCHAIN") != "1" {
		t.Skip("set SONAR_TEST_REAL_KEYCHAIN=1 to touch the OS keychain")
	}
	if home := os.Getenv("SONAR_TEST_REAL_HOME"); home != "" {
		t.Setenv("HOME", home)
	}
	kc := OSKeychain("dev.sonar.TEST-credentials", "store-test", 10*time.Second)

	// Ask the backend directly first, so a fallback further down is never
	// mistaken for a passing keychain.
	if err := kc.Set(`{"version":1,"token":"probe"}`); err != nil {
		t.Skipf("no usable keychain here: %v", err)
	}
	raw, rerr := kc.Get()
	t.Logf("direct keychain read: %q (err %v)", raw, rerr)
	if rerr != nil {
		t.Fatalf("wrote to the keychain but could not read back: %v", rerr)
	}
	if err := kc.Delete(); err != nil {
		t.Fatalf("could not delete the probe item: %v", err)
	}
	if _, err := kc.Get(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after deleting, Get = %v; want ErrNotFound", err)
	}

	s := New(filepath.Join(t.TempDir(), FileName), kc)
	t.Cleanup(func() { _ = s.Clear() })

	start := time.Now()
	loc, err := s.Save(testSession())
	t.Logf("Save -> %s in %s (err %v)", loc, time.Since(start).Round(time.Millisecond), err)
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	got, loc, err := s.Load()
	t.Logf("Load <- %s in %s (err %v)", loc, time.Since(start).Round(time.Millisecond), err)
	if err != nil || got.Token.Reveal() != testToken {
		t.Fatalf("Load = %v", err)
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("Load after Clear = %v", err)
	}
	fmt.Fprintf(os.Stderr, "real keychain backend answered from %s\n", loc)
}
