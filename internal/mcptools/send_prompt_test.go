package mcptools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeField_CollapsesLineBreaks(t *testing.T) {
	got := sanitizeField("real@y.com\nBCC: evil@x.com\r\tx To: a To: b\u0085To: c")
	if strings.ContainsAny(got, "\r\n\t  \u0085") {
		t.Errorf("sanitizeField left a line break / tab in %q", got)
	}
}

// PROTO-126 — a recipient value carrying an embedded newline must NOT be
// able to inject a second framework line (e.g. a fake "BCC:") into the
// approval dialog. SanitizePromptText keeps newlines, so the defense is
// per-field sanitization before assembly.
func TestSendPromptBody_NoNewlineInjection(t *testing.T) {
	snap := sendPromptSnapshot(Deps{}, "mail_send")
	_, body, _, err := snap(context.Background(), json.RawMessage(`{"to":["real@y.com\nBCC: evil@x.com"],"subject":"hi"}`))
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// The only BCC framework line is the legitimate (empty) one we add.
	if strings.Contains(body, "\nBCC: evil@x.com") {
		t.Errorf("newline injection produced a fake BCC line:\n%s", body)
	}
	// The evil address still appears — inline on the To line, as data.
	if !strings.Contains(body, "evil@x.com") {
		t.Errorf("expected the smuggled address to show inline as data:\n%s", body)
	}
	// Exactly one BCC *line* (the framework's empty one); the smuggled
	// "BCC:" text is inline on the To line (space-separated), not a line.
	if strings.Count(body, "\nBCC:") != 1 {
		t.Errorf("expected exactly one framework BCC line, body was:\n%s", body)
	}
}

// The dialog must show the address that will be sent to, not a
// normalized look-alike: fullwidth "ａlice" used to be displayed as
// "alice" (NFKC) while the raw address went out. Now the raw address is
// shown and a warning line names the suspect code points.
func TestSendDialog_FlagsNonASCIIRecipients(t *testing.T) {
	args, _ := json.Marshal(map[string]any{
		"subject": "hi",
		"to":      []string{"\uff41lice@example.com", "bob@example.com"},
		"cc":      []string{"carol\u200b@example.com"},
		"bcc":     []string{"dave@xn--exmple-cua.com"},
	})
	_, body, _, err := sendPromptSnapshot(Deps{}, "mail_send")(context.Background(), args)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	checkDialog(t, body, "\uff41lice@example.com", "bob@example.com", "dave@xn--exmple-cua.com")
	if strings.Contains(body, "To: alice@") {
		t.Errorf("fullwidth address displayed as ASCII:\n%s", body)
	}
	var warn string
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "WARNING:") {
			warn = l
		}
	}
	if warn == "" {
		t.Fatalf("no warning line:\n%s", body)
	}
	for _, want := range []string{"U+FF41", "U+200B", "punycode domain"} {
		if !strings.Contains(warn, want) {
			t.Errorf("warning missing %q: %s", want, warn)
		}
	}
	if strings.Contains(warn, "bob@example.com") {
		t.Errorf("plain ASCII address flagged: %s", warn)
	}
	// The warning sits with the recipients, before Subject.
	if strings.Index(body, "WARNING:") > strings.Index(body, "\nSubject:") {
		t.Errorf("warning comes after Subject:\n%s", body)
	}
}

func TestSendDialog_NoWarningForASCII(t *testing.T) {
	_, body, _, err := sendPromptSnapshot(Deps{}, "mail_send")(context.Background(),
		json.RawMessage(`{"to":["alice@example.com"],"subject":"h\u00e9llo"}`))
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if strings.Contains(body, "WARNING") {
		t.Errorf("unexpected warning for ASCII recipients:\n%s", body)
	}
}

func TestAddressNote_CapsCodePoints(t *testing.T) {
	note := addressNote("\u0430\u0431\u0432\u0433\u0434\u0435\u0436\u0437\u0438\u0439@x.com")
	if !strings.HasSuffix(note, "...") || strings.Count(note, "U+") != maxFlaggedRunes {
		t.Errorf("addressNote = %q", note)
	}
}
