package mcptools

import (
	"context"
	"encoding/json"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/gluon/rfc822"
	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	"github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

// --- helpers ---

// policyWithOverride returns the shipped policy with override applied
// on top (a tightening, so no loosening gate is involved).
func policyWithOverride(t *testing.T, override string) *policy.Engine {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(override), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := policy.New(context.Background(), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func messageCount(t *testing.T, c *gpa.Client) int {
	t.Helper()
	ids, err := c.GetMessageIDs(context.Background(), "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	return len(ids)
}

func snapshotCall(t *testing.T, tool mcp.Tool, args string) (body string, snap any, err error) {
	t.Helper()
	if tool.PromptSnapshot == nil {
		t.Fatalf("%s has no PromptSnapshot", tool.Name)
	}
	_, body, snap, err = tool.PromptSnapshot(context.Background(), json.RawMessage(args))
	return body, snap, err
}

// --- 1. mail_draft_update needs approval and shows recipient changes ---

func TestDraftUpdate_ShippedPolicyPrompts(t *testing.T) {
	e, err := policy.New(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	d, pol := e.Decide("mail_draft_update", nil, policy.Caller{})
	if d != policy.DecisionPrompt || pol == nil || !pol.Confirm || pol.TTLDuration() != 0 {
		t.Fatalf("mail_draft_update policy = %s %+v, want prompt + confirm + ttl 0", d, pol)
	}
}

func TestDraftUpdate_DialogShowsAddedBCC(t *testing.T) {
	deps, _, _ := fakeProtonEnv(t)
	id := createDraft(t, deps, `{"subject":"Contract","to":["alice@x.com"],"body_text":"signed copy attached"}`)

	body, snap, err := snapshotCall(t, mailDraftUpdate(deps), `{"draft_id":"`+id+`","bcc":["evil@attacker.com"]}`)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if d, ok := snap.(gpa.Message); !ok || d.ID != id {
		t.Fatalf("snapshot = %#v, want the fetched draft", snap)
	}
	for _, want := range []string{
		"To: alice@x.com\n",
		"BCC: evil@attacker.com\n",
		"Recipient changes: added to BCC: evil@attacker.com",
		"Subject: Contract\n",
		"Body: unchanged",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dialog missing %q:\n%s", want, body)
		}
	}

	// A body-only edit shows the new body and no recipient change.
	body, _, err = snapshotCall(t, mailDraftUpdate(deps), `{"draft_id":"`+id+`","body_text":"wire the money to IBAN X"}`)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	for _, want := range []string{"Recipient changes: none", "New Body (24 chars): wire the money to IBAN X"} {
		if !strings.Contains(body, want) {
			t.Errorf("dialog missing %q:\n%s", want, body)
		}
	}
}

// The handler acts on the draft the dialog showed (issue #116 design).
func TestDraftUpdate_RefusesIfDraftChangedAfterDialog(t *testing.T) {
	deps, c, _ := fakeProtonEnv(t)
	id := createDraft(t, deps, `{"subject":"s","to":["alice@x.com"],"body_text":"hello"}`)
	tool := mailDraftUpdate(deps)
	_, snap, err := snapshotCall(t, tool, `{"draft_id":"`+id+`","subject":"approved"}`)
	if err != nil {
		t.Fatal(err)
	}
	// Someone else edits the draft while the dialog is up.
	callOK(t, tool, `{"draft_id":"`+id+`","bcc":["evil@attacker.com"]}`)

	res, err := tool.Handler(mcp.Context{Std: context.Background(), Snapshot: snap},
		json.RawMessage(`{"draft_id":"`+id+`","subject":"approved"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "changed after the approval dialog") {
		t.Fatalf("want refusal, got %+v", res)
	}
	m, _ := c.GetMessage(context.Background(), id)
	if m.Subject == "approved" {
		t.Error("update applied despite the draft changing after approval")
	}
}

func TestDraftUpdate_InvalidRecipientIsAnError(t *testing.T) {
	deps, c, _ := fakeProtonEnv(t)
	id := createDraft(t, deps, `{"subject":"s","to":["alice@x.com"],"body_text":"hello"}`)
	_, err := mailDraftUpdate(deps).Handler(mcp.Context{Std: context.Background()},
		json.RawMessage(`{"draft_id":"`+id+`","to":["not an address"]}`))
	if err == nil {
		t.Fatal("invalid recipient accepted")
	}
	m, _ := c.GetMessage(context.Background(), id)
	if len(m.ToList) != 1 || m.ToList[0].Address != "alice@x.com" {
		t.Errorf("recipients changed to %v; an invalid address used to clear the list", m.ToList)
	}
}

// An edit that doesn't touch the body must keep a rich HTML body (a
// draft composed in Proton's editor) byte for byte: re-running it
// through sanitize.Outbound stripped links, images, styles and tables.
// The draft's sender is kept too, not reset to the primary address.
func TestDraftUpdate_KeepsStoredHTMLBodyAndSender(t *testing.T) {
	deps, c, kr := fakeProtonEnv(t)
	const rich = `<style>p{color:red}</style><p style="color:blue">See <a href="https://example.com/doc">the doc</a></p>` +
		`<img src="https://example.com/logo.png"><table><tr><td>cell</td></tr></table>`
	primary := deps.Session.Addresses[0]
	sender := &mail.Address{Name: "Signing Desk", Address: primary.Email}
	d, err := c.CreateDraft(context.Background(), kr, gpa.CreateDraftReq{Message: gpa.DraftTemplate{
		Subject:  "s",
		Sender:   sender,
		ToList:   []*mail.Address{{Address: "alice@x.com"}},
		Body:     rich,
		MIMEType: rfc822.TextHTML,
	}})
	if err != nil {
		t.Fatal(err)
	}

	callOK(t, mailDraftUpdate(deps), `{"draft_id":"`+d.ID+`","subject":"new subject"}`)

	m, err := c.GetMessage(context.Background(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decryptDraftBody(kr, m.Body)
	if err != nil {
		t.Fatal(err)
	}
	if plain != rich {
		t.Errorf("stored HTML body altered by a subject-only edit:\n got  %q\n want %q", plain, rich)
	}
	if m.Sender == nil || m.Sender.Name != "Signing Desk" || !strings.EqualFold(m.Sender.Address, primary.Email) {
		t.Errorf("sender = %v, want the draft's own %v", m.Sender, sender)
	}
	if m.Subject != "new subject" {
		t.Errorf("subject = %q", m.Subject)
	}
}

// A NEW body_html is still sanitized.
func TestDraftUpdate_NewHTMLBodyIsSanitized(t *testing.T) {
	deps, c, kr := fakeProtonEnv(t)
	id := createDraft(t, deps, `{"subject":"s","to":["alice@x.com"],"body_text":"hello"}`)
	callOK(t, mailDraftUpdate(deps), `{"draft_id":"`+id+`","body_html":"<p>hi</p><script>alert(1)</script>"}`)
	m, _ := c.GetMessage(context.Background(), id)
	plain, err := decryptDraftBody(kr, m.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, "script") || !strings.Contains(plain, "hi") {
		t.Errorf("new body_html not sanitized: %q", plain)
	}
}

// --- 2. send-family dialogs show the body ---

func TestBodyExcerptLine(t *testing.T) {
	long := strings.Repeat("x", 400) + "SECRET-TAIL"
	cases := []struct {
		body, mime string
		want       []string
		notWant    []string
	}{
		{"", "text/plain", []string{"Body: (empty)"}, nil},
		{"here are the API keys: sk-123", "text/plain", []string{"Body (29 chars): here are the API keys: sk-123"}, nil},
		// Quoted lines are shown, not dropped: exfiltrated data can't
		// hide behind "> ".
		{"hi\n> password: hunter2", "text/plain", []string{"hunter2"}, nil},
		{long, "text/plain", []string{"Body (411 chars, first 300 shown): xxx", "..."}, []string{"SECRET-TAIL"}},
		{`<style>p{}</style><p>Hello <b>Bob</b> &amp; co</p><script>evil()</script>`, "text/html",
			[]string{"Hello Bob & co"}, []string{"<b>", "evil", "p{}"}},
		// Line breaks of every kind are flattened: no fake dialog line.
		{"ok\nBCC: evil@x.com\u2028To: fake@x", "text/plain", []string{"ok BCC: evil@x.com To: fake@x"}, nil},
	}
	for _, tc := range cases {
		got := bodyExcerptLine(tc.body, tc.mime)
		if strings.ContainsAny(got, "\n\r\u2028\u2029\u0085") {
			t.Errorf("excerpt has a line break: %q", got)
		}
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("bodyExcerptLine(%.40q) = %q, missing %q", tc.body, got, w)
			}
		}
		for _, w := range tc.notWant {
			if strings.Contains(got, w) {
				t.Errorf("bodyExcerptLine(%.40q) = %q, should not contain %q", tc.body, got, w)
			}
		}
	}
}

func TestSendFamilyDialogs_ShowBody(t *testing.T) {
	const secret = "the Q3 board deck password is hunter2"

	// mail_send
	body, _, err := snapshotCall(t, mailSend(Deps{}),
		`{"subject":"hi","to":["a@x.com"],"body_text":"`+secret+`"}`)
	if err != nil || !strings.Contains(body, "Body (37 chars): "+secret) {
		t.Errorf("mail_send dialog lacks body (err %v):\n%s", err, body)
	}
	checkDialog(t, body, "a@x.com")

	// mail_reply / mail_reply_all
	var parent gpa.Message
	parent.ID = "p1"
	parent.Subject = "hello"
	parent.Sender = &mail.Address{Address: "attacker@evil.com"}
	deps := Deps{Session: &proton.Session{Addresses: []gpa.Address{{Email: "me@proton.me"}}}}
	for _, all := range []bool{false, true} {
		body := replyPromptBody(deps, parent, all, replyInput{InReplyTo: "p1", BodyText: secret})
		if !strings.Contains(body, secret) {
			t.Errorf("reply (all=%v) dialog lacks body:\n%s", all, body)
		}
	}

	// mail_forward (HTML body: excerpt of the sanitized text)
	body = forwardPromptBody(Deps{}, parent, forwardInput{ForwardOf: "p1", To: []string{"b@x.com"},
		BodyHTML: "<p>" + secret + "</p><script>x()</script>"})
	if !strings.Contains(body, "Body (37 chars): "+secret) {
		t.Errorf("forward dialog lacks body:\n%s", body)
	}
}

// mail_send_draft's dialog shows the draft's decrypted body, from the
// same fetch the send is checked against.
func TestSendDraftDialog_ShowsDecryptedBody(t *testing.T) {
	deps, _, _ := fakeProtonEnv(t)
	id := createDraft(t, deps, `{"subject":"s","to":["alice@x.com"],"body_text":"exfil: 4111 1111 1111 1111"}`)
	body, snap, err := snapshotCall(t, mailSendDraft(deps), `{"draft_id":"`+id+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "Body (26 chars): exfil: 4111 1111 1111 1111") {
		t.Errorf("send_draft dialog lacks body:\n%s", body)
	}
	if strings.Contains(body, "PGP") {
		t.Errorf("dialog shows ciphertext:\n%s", body)
	}
	if _, ok := snap.(gpa.Message); !ok {
		t.Errorf("snapshot = %T, want gpa.Message", snap)
	}
}

// --- 4. recipient checks ---

func TestForwardRecipients_Normalized(t *testing.T) {
	got := mailForward(Deps{}).Recipients(json.RawMessage(
		`{"forward_of":"p","to":["Alice <alice@good.com>"],"cc":["b@good.com, c@evil.com"]}`))
	if strings.Join(got, ",") != "alice@good.com,b@good.com,c@evil.com" {
		t.Fatalf("Recipients = %v", got)
	}
	if bad := firstDisallowedRecipient(got[:1], []string{"@good.com"}); bad != "" {
		t.Errorf("display-name entry denied by a domain allowlist: %q", bad)
	}
	if bad := firstDisallowedRecipient(got, []string{"@good.com"}); bad != "c@evil.com" {
		t.Errorf("smuggled second address not caught: %q", bad)
	}
}

func TestReplyRecipients_HonorReplyTo(t *testing.T) {
	var parent gpa.Message
	parent.Sender = &mail.Address{Address: "newsletter@x.com"}
	parent.ReplyTos = []*mail.Address{{Address: "support@x.com"}}
	parent.ToList = []*mail.Address{{Address: "me@proton.me"}, {Address: "team@x.com"}}
	deps := Deps{Session: &proton.Session{Addresses: []gpa.Address{{Email: "me@proton.me"}}}}

	to, cc := replyRecipients(deps, parent, false)
	if strings.Join(to, ",") != "support@x.com" || len(cc) != 0 {
		t.Errorf("reply: to=%v cc=%v, want Reply-To", to, cc)
	}
	to, cc = replyRecipients(deps, parent, true)
	if strings.Join(to, ",") != "support@x.com" || strings.Join(cc, ",") != "team@x.com" {
		t.Errorf("reply-all: to=%v cc=%v", to, cc)
	}

	body := replyPromptBody(deps, parent, false, replyInput{InReplyTo: "p"})
	if !strings.Contains(body, "To: support@x.com\n") ||
		!strings.Contains(body, "sent by newsletter@x.com but asks for replies to go to its Reply-To address support@x.com") {
		t.Errorf("dialog doesn't show the Reply-To redirect:\n%s", body)
	}
	// No note when Reply-To is the sender.
	parent.ReplyTos = []*mail.Address{{Address: "Newsletter@x.com"}}
	if body := replyPromptBody(deps, parent, false, replyInput{InReplyTo: "p"}); strings.Contains(body, "Reply-To address") {
		t.Errorf("redundant Reply-To note:\n%s", body)
	}
}

const replyAllowlistOverride = `tools:
  mail_reply:
    decision: prompt
    confirm: true
    ttl: 0
    allowed_recipients: ["@good.com"]
  mail_send_draft:
    decision: prompt
    confirm: true
    ttl: 0
    allowed_recipients: ["@good.com"]
`

// A reply whose recipients the allowlist rejects is refused before the
// Touch ID dialog (PromptSnapshot), and — when no dialog runs — before
// any draft is created, so nothing is left behind in Drafts.
func TestReply_AllowlistCheckedBeforePromptAndDraft(t *testing.T) {
	deps, c, _ := fakeProtonEnv(t)
	deps.Policy = policyWithOverride(t, replyAllowlistOverride)
	// The parent's sender is our own (fake) address, not @good.com.
	parentID := createDraft(t, deps, `{"subject":"s","to":["alice@good.com"],"body_text":"hi"}`)
	before := messageCount(t, c)

	tool := mailReply(deps)
	_, _, err := snapshotCall(t, tool, `{"in_reply_to":"`+parentID+`","body_text":"x"}`)
	if err == nil || !strings.Contains(err.Error(), "not on allowlist") {
		t.Fatalf("PromptSnapshot err = %v, want allowlist refusal before the dialog", err)
	}

	res, err := tool.Handler(mcp.Context{Std: context.Background()},
		json.RawMessage(`{"in_reply_to":"`+parentID+`","body_text":"x"}`))
	if err != nil || !res.IsError || !strings.Contains(res.Content[0].Text, "not on allowlist") {
		t.Fatalf("handler = %+v / %v, want allowlist denial", res, err)
	}
	if after := messageCount(t, c); after != before {
		t.Errorf("denied reply left %d new message(s) (orphan draft)", after-before)
	}
}

func TestSendDraft_AllowlistCheckedBeforePrompt(t *testing.T) {
	deps, _, _ := fakeProtonEnv(t)
	deps.Policy = policyWithOverride(t, replyAllowlistOverride)
	id := createDraft(t, deps, `{"subject":"s","to":["alice@good.com"],"bcc":["evil@attacker.com"],"body_text":"hi"}`)
	_, _, err := snapshotCall(t, mailSendDraft(deps), `{"draft_id":"`+id+`"}`)
	if err == nil || !strings.Contains(err.Error(), "evil@attacker.com not on allowlist") {
		t.Fatalf("PromptSnapshot err = %v, want allowlist refusal before the dialog", err)
	}
}

// A failure between CreateDraft and SendDraft discards the draft the
// call created; a draft the call didn't create (discard nil) is kept.
func TestFinalizeSend_DiscardsOwnDraftOnFailure(t *testing.T) {
	deps, c, kr := fakeProtonEnv(t)
	deps.Policy = policyWithOverride(t, replyAllowlistOverride)
	for _, own := range []bool{true, false} {
		tpl := gpa.DraftTemplate{Subject: "s", Sender: &mail.Address{Address: deps.Session.Addresses[0].Email}, ToList: []*mail.Address{{Address: "x@evil.com"}}, Body: "b", MIMEType: rfc822.TextPlain}
		d, err := c.CreateDraft(context.Background(), kr, gpa.CreateDraftReq{Message: tpl})
		if err != nil {
			t.Fatal(err)
		}
		var discard func()
		if own {
			discard = func() { discardDraft(context.Background(), deps, d.ID) }
		}
		res, err := finalizeSend(mcp.Context{Std: context.Background()}, deps, "mail_reply", kr, d, tpl,
			"text/plain", []string{"x@evil.com"}, nil, discard)
		if err != nil || !res.IsError {
			t.Fatalf("finalizeSend = %+v / %v, want denial", res, err)
		}
		_, gerr := c.GetMessage(context.Background(), d.ID)
		if own && gerr == nil {
			t.Error("draft created by the call survived a failed send")
		}
		if !own && gerr != nil {
			t.Errorf("caller's own draft was deleted: %v", gerr)
		}
	}
}
