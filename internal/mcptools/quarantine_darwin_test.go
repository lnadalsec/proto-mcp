//go:build darwin

package mcptools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/lnadalsec/proto-mcp/internal/mcp"
)

// A file saved from an email must carry com.apple.quarantine, or a
// .app / .command opens without any Gatekeeper check.
func TestMailSaveAttachment_SetsQuarantine(t *testing.T) {
	st, tmp := saveTestStore(t, "run.command")
	res, err := mailSaveAttachment(Deps{Store: st}).Handler(mcp.Context{Std: context.Background()},
		json.RawMessage(`{"message_id":"msg-1","attachment_id":"att-A"}`))
	if err != nil || res.IsError {
		t.Fatalf("handler: %v / %+v", err, res)
	}
	path := filepath.Join(tmp, "Downloads", "run.command")
	buf := make([]byte, 256)
	n, err := unix.Getxattr(path, quarantineXattr, buf)
	if err != nil {
		t.Fatalf("no %s on the saved file: %v", quarantineXattr, err)
	}
	if v := string(buf[:n]); !strings.HasPrefix(v, "0081;") || !strings.Contains(v, ";proto-mcp;") {
		t.Errorf("quarantine value = %q", v)
	}
}
