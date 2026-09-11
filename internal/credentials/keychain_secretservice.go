//go:build (dragonfly && cgo) || (freebsd && cgo) || linux || netbsd || openbsd

package credentials

import "os"

// keychainReachable: the platforms where go-keyring uses the Secret Service
// over D-Bus (its keyring_unix.go build tag, mirrored). See sessionBusKnown.
func keychainReachable() bool { return sessionBusKnown(os.Getenv, os.Stat, os.Getuid()) }
