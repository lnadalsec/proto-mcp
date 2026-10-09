//go:build darwin

package mcptools

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// setQuarantine marks f — a file mail_save_attachment is writing to
// ~/Downloads — with com.apple.quarantine, the attribute browsers and
// Mail set on downloads. Without it, a .app / .command / .pkg saved
// from an email opens with no Gatekeeper check and no "downloaded
// from the Internet" warning. Set on the open descriptor before any
// content is written, so the file never exists on disk unmarked.
func setQuarantine(f *os.File, value string) error {
	if err := unix.Fsetxattr(int(f.Fd()), quarantineXattr, []byte(value), 0); err != nil {
		return fmt.Errorf("set %s: %w", quarantineXattr, err)
	}
	return nil
}
