//go:build !((dragonfly && cgo) || (freebsd && cgo) || linux || netbsd || openbsd)

package credentials

// keychainReachable: macOS and Windows always have their keychain, and on any
// other platform go-keyring answers ErrUnsupportedPlatform at once.
func keychainReachable() bool { return true }
