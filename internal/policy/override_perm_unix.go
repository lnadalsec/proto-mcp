//go:build unix

package policy

import (
	"fmt"
	"os"
	"syscall"
)

// checkOverrideOwner refuses an override another user could have
// written: it must belong to us and not be group- or world-writable.
func checkOverrideOwner(fi os.FileInfo) error {
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("override is group- or world-writable (%v); chmod 600 it", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("override is owned by uid %d, not by the current user", st.Uid)
	}
	return nil
}
