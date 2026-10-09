//go:build !unix

package policy

import "os"

func checkOverrideOwner(os.FileInfo) error { return nil }
