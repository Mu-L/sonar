// Package credentials is where the daemon keeps its relay session: the token
// the relay issued at the end of a device-flow sign-in, and the account that
// token belongs to (sonar-relay/docs/AUTH.md, "Who holds the session").
//
// The daemon is the authority. The desktop app hands the local daemon its
// token rather than keeping a copy of its own, and signing out anywhere clears
// this store.
//
// # Where the session rests
//
// Keychain first, file second:
//
//   - The OS keychain where there is one: the login keychain on macOS, the
//     Credential Manager on Windows, the Secret Service on a Linux desktop.
//   - ~/.config/sonar/credentials.json at mode 0600 where there is not, which
//     is a headless Linux box — the machine class sign-in was designed for,
//     so the file is not the lesser path, it is the one that works there.
//
// Save writes to the keychain when it can and then deletes the file, so there
// is one copy. When the keychain refuses, the file is written instead. Load
// reads both and returns the newer (by SavedAt), so a keychain that refused
// one write cannot bring back an older session later.
//
// # What the keychain does and does not buy on macOS
//
// The keychain backend is github.com/zalando/go-keyring, which needs no cgo
// and talks to /usr/bin/security. The secret goes to `security -i` over stdin,
// never on argv (checked against v0.2.8's source and with a wrapper that
// recorded the exact argv). The item's decrypt ACL trusts /usr/bin/security,
// so the daemon reading back its own item never prompts, however often an
// unsigned binary is rebuilt. The same ACL means any process running as this
// user can read the item through `security` without a prompt: on macOS the
// keychain gives encryption at rest and the keychain's lock, not isolation
// from the user's other processes. That is the same boundary as a 0600 file.
//
// # Never printed
//
// The token is a [Token], which formats as "[redacted]" under every fmt verb
// and slog, and refuses to marshal to JSON or text. The only way to the bytes
// is [Token.Reveal], for the Authorization header. The file is not the config
// file: `sonar config` never reads it.
package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

const (
	// KeychainService and KeychainAccount name the daemon's keychain item.
	// Deliberately not the desktop app's (dev.sonar.desktop / relay-session):
	// an item another binary created prompts when read through
	// /usr/bin/security, so the app hands its token over instead.
	KeychainService = "dev.sonar.daemon"
	KeychainAccount = "relay-session"

	// FileName is the fallback store, beside config.yaml in ~/.config/sonar.
	FileName = "credentials.json"

	// StoreEnv set to "file" skips the keychain entirely: for tests, and for a
	// Mac reached only over SSH, where the login keychain is locked.
	StoreEnv = "SONAR_CREDENTIALS_STORE"

	// DefaultTimeout bounds one keychain operation. They take ~15 ms on macOS
	// and fail in single-digit milliseconds on Linux; ten seconds is for an
	// unlock dialog someone is actually typing into.
	DefaultTimeout = 10 * time.Second

	recordVersion = 1

	// maxKeychainSecret keeps a record inside every backend's limit: Windows
	// caps a credential blob at 2560 bytes, and go-keyring's macOS command
	// line (the record base64-encoded) at 4096. A real record is ~400 bytes.
	maxKeychainSecret = 2048
)

// ErrNotSignedIn is what Load returns when there is no usable session. A
// store that could not be read — a file with loose permissions, a corrupt
// record, a keychain that timed out — also matches it, with the reason
// wrapped alongside: the daemon's answer is the same (sign in again, and the
// new Save replaces the bad copy), and `sonar doctor` can still name why.
var ErrNotSignedIn = errors.New("not signed in")

// Account is who a session belongs to, as the relay's GET /v1/me and the
// device-token 200 both answer it. Nothing in it is a secret.
type Account struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
	Provider    string `json:"provider,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// Token is a relay session token. It cannot be printed, logged or marshalled
// by accident; Reveal is the one way to its value.
type Token string

const redacted = "[redacted]"

var errMarshalToken = errors.New("credentials: a session token is never marshalled")

// Reveal returns the token, for the Authorization header and nothing else.
func (t Token) Reveal() string { return string(t) }

func (Token) String() string               { return redacted }
func (Token) GoString() string             { return redacted }
func (Token) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redacted) }
func (Token) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Token) MarshalJSON() ([]byte, error) { return nil, errMarshalToken }
func (Token) MarshalText() ([]byte, error) { return nil, errMarshalToken }
func (Token) MarshalYAML() (any, error)    { return nil, errMarshalToken }

// Session is one signed-in session.
type Session struct {
	Token   Token
	Account Account
	// Relay is the origin that issued the token, e.g. https://relay.trysonar.dev.
	Relay string
	// SavedAt is stamped by Save and decides which copy wins when both
	// backends hold one.
	SavedAt time.Time
}

// Location says which backend holds the session.
type Location string

const (
	InKeychain Location = "keychain"
	InFile     Location = "file"
)

// record is the stored form, identical in both backends.
type record struct {
	Version int       `json:"version"`
	Relay   string    `json:"relay,omitempty"`
	Token   string    `json:"token"`
	Account Account   `json:"account"`
	SavedAt time.Time `json:"saved_at"`
}

func encode(s Session) ([]byte, error) {
	return json.Marshal(record{
		Version: recordVersion,
		Relay:   s.Relay,
		Token:   string(s.Token),
		Account: s.Account,
		SavedAt: s.SavedAt,
	})
}

func decode(b []byte) (Session, error) {
	var r record
	if err := json.Unmarshal(b, &r); err != nil {
		return Session{}, errors.New("not a credentials record")
	}
	if r.Version > recordVersion {
		return Session{}, fmt.Errorf("written by a newer sonar (record version %d)", r.Version)
	}
	if r.Version < 1 {
		return Session{}, errors.New("not a credentials record")
	}
	if r.Token == "" {
		return Session{}, errors.New("the record holds no token")
	}
	return Session{Token: Token(r.Token), Account: r.Account, Relay: r.Relay, SavedAt: r.SavedAt}, nil
}

// Store is the daemon's session store. It is not safe for concurrent use; the
// daemon owns one and serialises access to it.
type Store struct {
	keychain Keychain
	file     fileBackend
	now      func() time.Time
}

// New returns a store over the file at path and the given keychain. A nil
// keychain means file only.
func New(path string, kc Keychain) *Store {
	return &Store{keychain: kc, file: fileBackend{path: path}, now: time.Now}
}

// Default is the store the daemon uses: the OS keychain (unless StoreEnv is
// "file") and DefaultPath.
func Default() *Store {
	var kc Keychain
	if os.Getenv(StoreEnv) != "file" {
		kc = OSKeychain(KeychainService, KeychainAccount, DefaultTimeout)
	}
	return New(DefaultPath(), kc)
}

// DefaultPath is ~/.config/sonar/credentials.json, resolved the way
// config.Path and daemon.ConfigDir resolve the directory.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return filepath.Join(home, ".config", "sonar", FileName)
}

// Path is the fallback file this store reads and writes.
func (s *Store) Path() string { return s.file.path }

// Load returns the stored session and where it was found. With nothing usable
// stored it returns an error matching ErrNotSignedIn.
func (s *Store) Load() (Session, Location, error) {
	var (
		kcSess Session
		kcOK   bool
		kcErr  error
	)
	if s.keychain != nil {
		secret, err := s.keychain.Get()
		switch {
		case err == nil:
			if sess, derr := decode([]byte(secret)); derr != nil {
				kcErr = fmt.Errorf("the keychain item is unreadable: %w", derr)
			} else {
				kcSess, kcOK = sess, true
			}
		case errors.Is(err, ErrNotFound), errors.Is(err, ErrUnavailable):
		default:
			kcErr = err
		}
	}

	fileSess, fileOK, fileErr := s.file.load()

	switch {
	case kcOK && fileOK:
		if fileSess.SavedAt.After(kcSess.SavedAt) {
			return fileSess, InFile, nil
		}
		return kcSess, InKeychain, nil
	case kcOK:
		// A file that could not be trusted is ignored when the keychain has
		// a session; the next Save deletes it.
		return kcSess, InKeychain, nil
	case fileOK:
		return fileSess, InFile, nil
	}

	var causes []error
	if fileErr != nil {
		causes = append(causes, fileErr)
	}
	if kcErr != nil {
		causes = append(causes, fmt.Errorf("the keychain could not be read: %w", kcErr))
	}
	if len(causes) == 0 {
		return Session{}, "", ErrNotSignedIn
	}
	return Session{}, "", fmt.Errorf("%w: %w", ErrNotSignedIn, errors.Join(causes...))
}

// Save stores sess, stamping SavedAt, and says where it went.
func (s *Store) Save(sess Session) (Location, error) {
	if sess.Token == "" {
		return "", errors.New("credentials: refusing to store a session with no token")
	}
	sess.SavedAt = s.now().UTC()
	blob, err := encode(sess)
	if err != nil {
		return "", fmt.Errorf("credentials: encoding the session: %w", err)
	}

	var kcErr error
	if s.keychain != nil {
		if len(blob) > maxKeychainSecret {
			kcErr = fmt.Errorf("the record is %d bytes, over the keychain limit of %d", len(blob), maxKeychainSecret)
		} else {
			kcErr = s.keychain.Set(string(blob))
		}
		if kcErr == nil {
			// One copy: a file from an earlier fallback would otherwise
			// outlive a later sign-out done while the file was unreadable.
			if err := s.file.remove(); err != nil {
				return InKeychain, fmt.Errorf("credentials: the session is in the keychain, but the older %s could not be removed: %w", s.file.path, err)
			}
			return InKeychain, nil
		}
	}

	if err := s.file.save(blob); err != nil {
		if kcErr != nil && !errors.Is(kcErr, ErrUnavailable) {
			return "", fmt.Errorf("credentials: the keychain refused the session (%v), and so did the file: %w", kcErr, err)
		}
		return "", err
	}
	if kcErr != nil && !errors.Is(kcErr, ErrUnavailable) {
		// The keychain is there but refused this write, so it may still hold
		// an older session. Load would prefer the newer file anyway; deleting
		// is still better. Best effort: it is probably refusing this too.
		_ = s.keychain.Delete()
	}
	return InFile, nil
}

// Clear removes the session from both backends. Nothing stored is success.
// The file is removed even when the keychain refuses; the error then says a
// session may still be in the keychain.
func (s *Store) Clear() error {
	var errs []error
	if s.keychain != nil {
		if err := s.keychain.Delete(); err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrUnavailable) {
			errs = append(errs, fmt.Errorf("credentials: the keychain would not forget the session: %w", err))
		}
	}
	if err := s.file.remove(); err != nil {
		errs = append(errs, fmt.Errorf("credentials: removing %s: %w", s.file.path, err))
	}
	return errors.Join(errs...)
}
