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

// openDir opens a directory for inspection. O_DIRECTORY refuses anything that
// is not one and O_NOFOLLOW refuses a symlink, so mode and owner are read from
// the same object by descriptor rather than from a path that could be swapped
// between the check and the use — the discipline openPrivate applies to the
// file, applied to the directory holding it.
func openDir(dir string) (*os.File, os.FileInfo, error) {
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := d.Stat()
	if err != nil {
		_ = d.Close()
		return nil, nil, err
	}
	return d, fi, nil
}

// checkDirPrivate refuses a directory another user could write, or has
// substituted wholesale.
//
// Only the immediate parent is checked. A loose grandparent lets someone
// replace this directory entirely, but the replacement is then owned by them,
// which the owner check catches; walking every ancestor to the root would
// also have to reason about the sticky bit on /tmp-like directories, which is
// a different problem from the one this store has.
func checkDirPrivate(dir string) error {
	d, fi, err := openDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return &InsecureFileError{Path: dir, Reason: fmt.Sprintf(
			"the directory holding it has mode %04o, so others can replace the file inside it; it must not be group- or world-writable (chmod 700 %s)", perm, dir)}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return &InsecureFileError{Path: dir, Reason: fmt.Sprintf(
			"the directory holding it is owned by uid %d, not by this user (%d)", st.Uid, os.Getuid())}
	}
	return nil
}

// secureDir makes the directory private before a token is written into it.
//
// It tightens rather than refuses. ~/.config/sonar is sonar's own directory —
// its config, its log, its lock, its database — not somewhere a person
// deliberately shares with other users, so a group-writable one is an
// accident (a stray umask, a careless chmod, a restored backup) and quietly
// fixing it is less surprising than refusing to sign in. Only the write bits
// go: a 0755 directory stays 0755, because listing a directory does not
// reveal the contents of a 0600 file in it. A directory belonging to someone
// else is refused instead — chmod would fail there in any case.
func secureDir(dir string) error {
	d, fi, err := openDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return &InsecureFileError{Path: dir, Reason: fmt.Sprintf(
			"refusing to write a session into a directory owned by uid %d, not by this user (%d)", st.Uid, os.Getuid())}
	}
	perm := fi.Mode().Perm()
	if perm&0o022 == 0 {
		return nil
	}
	if err := d.Chmod(perm &^ 0o022); err != nil {
		return fmt.Errorf("making %s private (its mode is %04o and others can write it): %w", dir, perm, err)
	}
	return nil
}

// syncDir makes a rename durable. Best effort: some filesystems refuse fsync
// on a directory, and the rename itself has already happened.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
