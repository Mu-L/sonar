//go:build !windows

package credentials

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openPrivate opens path for reading only if it is a regular file, owned by
// this user, that no one else can read or write.
//
// O_NOFOLLOW refuses a symlink outright, and the checks run on the open
// descriptor rather than a prior Lstat, so nothing can be swapped in between.
// O_NONBLOCK keeps a FIFO planted at the path from hanging the daemon in
// open(2); it has no effect on a regular file.
func openPrivate(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, &InsecureFileError{Path: path, Reason: "it is a symbolic link"}
		}
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, &InsecureFileError{Path: path, Reason: "it is not a regular file"}
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		_ = f.Close()
		return nil, &InsecureFileError{Path: path, Reason: fmt.Sprintf(
			"its mode is %04o and others can read or write it; it must be 0600 (sign in again to rewrite it, or chmod 600 %s)", perm, path)}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		_ = f.Close()
		return nil, &InsecureFileError{Path: path, Reason: fmt.Sprintf(
			"it is owned by uid %d, not by this user (%d)", st.Uid, os.Getuid())}
	}
	return f, nil
}

// syncDir makes a rename durable. Best effort: some filesystems refuse fsync
// on a directory, and the rename itself has already happened.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
