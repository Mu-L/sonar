package credentials

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

var (
	// ErrNotFound: the keychain answered, and holds no session.
	ErrNotFound = errors.New("no session in the keychain")
	// ErrUnavailable: there is no keychain to ask on this machine — no
	// Secret Service on the session bus, no session bus at all, or a
	// platform go-keyring does not support.
	ErrUnavailable = errors.New("no keychain on this machine")
	// ErrTimeout: the keychain did not answer within the store's timeout.
	ErrTimeout = errors.New("the keychain did not answer in time")
)

// Keychain is the platform credential store, reduced to the one item the
// daemon keeps. An interface so tests never touch a real keychain: on macOS
// that can be a prompt on somebody's screen, and on CI a hang.
type Keychain interface {
	// Get returns the stored secret, or an error matching ErrNotFound.
	Get() (string, error)
	Set(secret string) error
	// Delete removes the item, or returns an error matching ErrNotFound.
	Delete() error
}

// OSKeychain is the real keychain, through go-keyring, with every operation
// bounded by timeout.
//
// A timed-out operation is abandoned, not killed: go-keyring offers no
// cancellation, so its goroutine (and on macOS its /usr/bin/security child)
// runs to completion in the background. That is acceptable for a daemon that
// asks once and caches the answer, and it is why the daemon must not ask on
// every request.
func OSKeychain(service, account string, timeout time.Duration) Keychain {
	return osKeychain{service: service, account: account, timeout: timeout}
}

type osKeychain struct {
	service, account string
	timeout          time.Duration
}

func (k osKeychain) Get() (string, error) {
	if !keychainReachable() {
		return "", ErrUnavailable
	}
	v, err := bounded(k.timeout, func() (string, error) { return keyring.Get(k.service, k.account) })
	return v, classify(err)
}

func (k osKeychain) Set(secret string) error {
	if !keychainReachable() {
		return ErrUnavailable
	}
	_, err := bounded(k.timeout, func() (struct{}, error) {
		return struct{}{}, keyring.Set(k.service, k.account, secret)
	})
	return classify(err)
}

func (k osKeychain) Delete() error {
	if !keychainReachable() {
		return ErrUnavailable
	}
	_, err := bounded(k.timeout, func() (struct{}, error) {
		return struct{}{}, keyring.Delete(k.service, k.account)
	})
	return classify(err)
}

// bounded runs op and gives up after d. See OSKeychain for what giving up
// means.
func bounded[T any](d time.Duration, op func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1) // buffered: an abandoned op must not block forever on send
	go func() {
		v, err := op()
		ch <- result{v, err}
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-t.C:
		var zero T
		return zero, ErrTimeout
	}
}

// classify maps go-keyring's errors onto this package's three.
func classify(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrTimeout):
		return err
	case errors.Is(err, keyring.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, keyring.ErrUnsupportedPlatform), noSecretService(err):
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return fmt.Errorf("keychain: %w", err)
}

// noSecretService recognises "there is a bus but nothing on it keeps secrets"
// and "there is no dbus-launch to start a bus with". Both were observed in an
// ubuntu:22.04 container; godbus reports them only as text.
func noSecretService(err error) bool {
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "org.freedesktop.secrets was not provided") ||
		strings.Contains(msg, "org.freedesktop.DBus.Error.ServiceUnknown")
}

// sessionBusKnown reports whether godbus would find a session bus WITHOUT
// autolaunching one: DBUS_SESSION_BUS_ADDRESS, or the per-user bus socket
// under /run/user. Anything else sends godbus to `dbus-launch`, which on a
// headless box starts a fresh dbus-daemon that outlives the caller and sets
// DBUS_SESSION_BUS_ADDRESS in this process's environment — which every
// service the daemon later spawns would inherit. Observed in a container: one
// leaked dbus-daemon per process that asked. So on those platforms the
// keychain is simply unavailable unless a bus is already there.
func sessionBusKnown(getenv func(string) string, stat func(string) (os.FileInfo, error), uid int) bool {
	if a := getenv("DBUS_SESSION_BUS_ADDRESS"); a != "" && a != "autolaunch:" {
		return true
	}
	for _, name := range []string{"bus", "dbus-session"} {
		if _, err := stat(fmt.Sprintf("/run/user/%d/%s", uid, name)); err == nil {
			return true
		}
	}
	return false
}
