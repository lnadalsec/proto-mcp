package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lnadalsec/proto-mcp/internal/mcp"
	"github.com/lnadalsec/proto-mcp/internal/store"
)

// saveTestStore is a store with one message and one cached attachment
// named filename, HOME pointed at a temp dir.
func saveTestStore(t *testing.T, filename string) (*store.Store, string) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.DB.ExecContext(ctx,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json) VALUES (?, ?, ?, ?, ?, '[]', '[]', 0, 0, 0, 1, 'inbox', 0, '{}')`,
		"msg-1", "msg-1", "Your invoice", "x@y", "X",
	); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAttachmentCache(ctx, store.AttachmentCacheRow{
		MessageID: "msg-1", AttachmentID: "att-A",
		Filename: filename, MIMEType: "application/octet-stream",
		SizeBytes: 5, Content: []byte("#!/bin/sh"),
	}); err != nil {
		t.Fatal(err)
	}
	return st, tmp
}

// With no filename argument the dialog used to say "(name from
// message)": the user approved a file whose name they never saw.
func TestMailSaveAttachment_DialogShowsResolvedNameAndWarns(t *testing.T) {
	st, _ := saveTestStore(t, "invoice.pdf.command")
	tl := mailSaveAttachment(Deps{Store: st})

	_, body, snap, err := tl.PromptSnapshot(context.Background(),
		json.RawMessage(`{"message_id":"msg-1","attachment_id":"att-A"}`))
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	for _, want := range []string{
		"as invoice.pdf.command to ~/Downloads",
		"WARNING: .command files run code",
		"WARNING: double extension: this is a .command file, not a .pdf",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dialog missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "name from message") {
		t.Errorf("dialog still hides the name:\n%s", body)
	}
	if s, ok := snap.(saveSnapshot); !ok || s.Filename != "invoice.pdf.command" {
		t.Errorf("snapshot = %#v", snap)
	}
}

// The handler writes the name the dialog showed.
func TestMailSaveAttachment_WritesApprovedName(t *testing.T) {
	st, tmp := saveTestStore(t, "report.pdf")
	tl := mailSaveAttachment(Deps{Store: st})
	res, err := tl.Handler(mcp.Context{Std: context.Background(), Snapshot: saveSnapshot{Filename: "approved.txt"}},
		json.RawMessage(`{"message_id":"msg-1","attachment_id":"att-A"}`))
	if err != nil || res.IsError {
		t.Fatalf("handler: %v / %+v", err, res)
	}
	if _, err := os.Stat(filepath.Join(tmp, "Downloads", "approved.txt")); err != nil {
		t.Errorf("approved name not used: %v", err)
	}
}

func TestDangerousFileWarning(t *testing.T) {
	cases := map[string][]string{
		"report.pdf":          nil,
		"archive.tar.gz":      nil,
		"notes.v2.txt":        nil,
		"README":              nil,
		"Setup.app":           {".app files run code"},
		"run.SH":              {".sh files run code"},
		"Installer.pkg":       {".pkg files"},
		"disk.dmg":            {".dmg files"},
		"script.scpt":         {".scpt files"},
		"photo.jpg.app":       {".app files", "double extension: this is a .app file, not a .jpg"},
		"invoice.pdf   .zip":  {"not a .pdf"},
		"invoice.pdf.  html":  {"not a .pdf"},
		"statement.docx.webp": {"not a .docx"},
	}
	for name, want := range cases {
		got := dangerousFileWarning(name)
		if len(want) == 0 && got != "" {
			t.Errorf("%q: unexpected warning %q", name, got)
		}
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%q: warning %q missing %q", name, got, w)
			}
		}
	}
}

func TestQuarantineValueFormat(t *testing.T) {
	v := quarantineValue(time.Unix(0x65000000, 0))
	re := regexp.MustCompile(`^0081;65000000;proto-mcp;[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$`)
	if !re.MatchString(v) {
		t.Errorf("quarantine value %q has the wrong format", v)
	}
	if quarantineValue(time.Now()) == quarantineValue(time.Now()) {
		t.Error("event UUID not random")
	}
}
