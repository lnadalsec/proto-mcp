//go:build !darwin

package mcptools

import "os"

// setQuarantine is a no-op off macOS: com.apple.quarantine and
// Gatekeeper are macOS mechanisms, and the daemon only ships there.
// Kept so the package builds (and its tests run) elsewhere.
func setQuarantine(*os.File, string) error { return nil }
