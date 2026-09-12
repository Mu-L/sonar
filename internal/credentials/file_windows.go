//go:build windows

package credentials

import (
	"os"
)

// openPrivate on Windows refuses links and anything but a regular file. There
// is no mode to check: Unix permission bits do not exist there, and the file
// lives under %USERPROFILE%, whose ACL already admits only this user and
// administrators. The Credential Manager is the primary store on Windows in
// any case; this file is only written when it refuses.
func openPrivate(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, &InsecureFileError{Path: path, Reason: "it is a symbolic link"}
	}
	if !fi.Mode().IsRegular() {
		return nil, &InsecureFileError{Path: path, Reason: "it is not a regular file"}
	}
	return os.Open(path)
}

// checkDirPrivate and secureDir are no-ops on Windows, for the same reason
// openPrivate checks no mode there: Unix permission bits do not exist, the
// directory sits under %USERPROFILE% whose ACL already admits only this user
// and administrators, and the Credential Manager is the primary store anyway.
func checkDirPrivate(string) error { return nil }
func secureDir(string) error       { return nil }

func syncDir(string) {}
