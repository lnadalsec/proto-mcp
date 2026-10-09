package sanitize

import (
	"strings"
	"testing"
)

func TestHTMLStripsScripts(t *testing.T) {
	in := `<p>Hello</p><script>alert("xss")</script>`
	got := HTML(in)
	if strings.Contains(got, "<script") || strings.Contains(got, "alert") {
		t.Errorf("script not stripped: %q", got)
	}
	if !strings.Contains(got, "<p>Hello</p>") {
		t.Errorf("paragraph lost: %q", got)
	}
}

func TestHTMLStripsIframes(t *testing.T) {
	in := `<p>Body</p><iframe src="https://evil/"></iframe>`
	got := HTML(in)
	if strings.Contains(got, "iframe") {
		t.Errorf("iframe not stripped: %q", got)
	}
}

func TestHTMLDropsAnchorsKeepsText(t *testing.T) {
	// bluemonday strips the whole <a> element when no attrs are
	// allowed on it, but the link TEXT survives as the surrounding
	// content. The LLM sees "Click here to reset." with no URL
	// anywhere — exactly the prompt-injection-via-href mitigation
	// we want. (Allowing href would just give the LLM a string to
	// be tricked by; better to drop it entirely.)
	in := `<p>Click <a href="https://reset.example/?id=123">here</a> to reset.</p>`
	got := HTML(in)
	if strings.Contains(got, "href") || strings.Contains(got, "reset.example") {
		t.Errorf("href survived: %q", got)
	}
	if !strings.Contains(got, "here") {
		t.Errorf("link text lost: %q", got)
	}
	if !strings.Contains(got, "Click") {
		t.Errorf("surrounding text lost: %q", got)
	}
}

func TestHTMLStripsRemoteImages(t *testing.T) {
	in := `<p>Hi</p><img src="https://tracker/pixel.gif">`
	got := HTML(in)
	if strings.Contains(got, "img") || strings.Contains(got, "tracker") {
		t.Errorf("remote image survived: %q", got)
	}
}

func TestHTMLKeepsAllowlist(t *testing.T) {
	in := "<p>Para</p>" +
		"<h1>H1</h1><h2>H2</h2>" +
		"<ul><li>one</li><li>two</li></ul>" +
		"<blockquote>quoted</blockquote>" +
		"<b>bold</b> <strong>strong</strong> <i>italic</i> <em>em</em>"
	got := HTML(in)
	for _, want := range []string{"<p>", "<h1>", "<h2>", "<ul>", "<li>",
		"<blockquote>", "<b>", "<strong>", "<i>", "<em>"} {
		if !strings.Contains(got, want) {
			t.Errorf("allowlist tag %s lost: %q", want, got)
		}
	}
}

func TestHTMLStripsUnknownTags(t *testing.T) {
	// Anything outside the allowlist (style, form, object, embed, ...)
	// is stripped wholesale.
	in := `<style>body{display:none}</style><form><input name="creds"></form>`
	got := HTML(in)
	for _, bad := range []string{"<style", "<form", "<input", "display:none", "creds"} {
		if strings.Contains(got, bad) {
			t.Errorf("disallowed content %q survived: %q", bad, got)
		}
	}
}

func TestHTMLEmpty(t *testing.T) {
	if got := HTML(""); got != "" {
		t.Errorf("HTML(\"\") = %q, want \"\"", got)
	}
}

func TestTextStripsHTML(t *testing.T) {
	in := `<p>Hello <b>world</b></p>`
	got := Text(in)
	if got != "Hello world" {
		t.Errorf("Text = %q, want \"Hello world\"", got)
	}
}

// D42: <style> and <script> element contents must be dropped
// wholesale, not just have their tag delimiters stripped. Marketing
// HTML emails ship multi-KB <style> blocks (@font-face, @media)
// that would otherwise pollute the plaintext returned by mail_read
// body_format="text" and the FTS5 index.
func TestTextStripsStyleAndScriptContent(t *testing.T) {
	in := `<html><head>
<style>.lhfix{display:block} @font-face{font-family:'X';src:url(...)}</style>
<script>var t = 'tracker'; doStuff();</script>
</head>
<body><p>Hello, real content here.</p></body></html>`
	got := Text(in)
	for _, leak := range []string{"@font-face", ".lhfix", "tracker", "doStuff"} {
		if strings.Contains(got, leak) {
			t.Errorf("D42 regression: %q leaked into plaintext: %q", leak, got)
		}
	}
	if !strings.Contains(got, "real content here") {
		t.Errorf("real body content lost: %q", got)
	}
}

// D42 edge: mixed-case tags + spaces in closing tag must also be
// caught.
func TestTextStripsCaseAndSpacedClosingTags(t *testing.T) {
	in := `<STYLE>p{color:red}</ Style >hello<Script>x()</  SCRIPT>world`
	got := Text(in)
	if strings.Contains(got, "color:red") || strings.Contains(got, "x()") {
		t.Errorf("D42 case/space variant leaked: %q", got)
	}
	if !strings.Contains(got, "hello") || !strings.Contains(got, "world") {
		t.Errorf("real content lost: %q", got)
	}
}

// Quoted-reply lines are content too: dropping them hid part of the
// message from mail_read and from the FTS index.
func TestTextKeepsQuotedReplies(t *testing.T) {
	in := "On Tuesday Alice wrote:\n> Original message\n> > Nested\nMy actual reply"
	got := Text(in)
	for _, want := range []string{"Original message", "Nested", "actual reply"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q lost: %q", want, got)
		}
	}
}

// A text/plain body has no markup: "<" and ">" are content, and so are
// quoted lines. Line structure is kept.
func TestPlainTextKeepsAngleBracketsAndQuotes(t *testing.T) {
	in := "if a < b > c then\r\n> quoted line\r\n> > nested <tag>\r\nreply"
	want := "if a < b > c then\n> quoted line\n> > nested <tag>\nreply"
	if got := PlainText(in); got != want {
		t.Errorf("PlainText = %q, want %q", got, want)
	}
}

func TestPlainTextCollapsesBlankRuns(t *testing.T) {
	in := "\n\npara one   \n\n \n\t\n\npara two\n\n"
	want := "para one\n\npara two"
	if got := PlainText(in); got != want {
		t.Errorf("PlainText = %q, want %q", got, want)
	}
	if PlainText("") != "" {
		t.Error("PlainText(\"\") should be empty")
	}
}

func TestPlainTextStripsControlAndInvisible(t *testing.T) {
	in := "pay\x1b[31m to \u202eexe.txt\u200b ok\U000E0041\U000E0042 done"
	got := PlainText(in)
	for _, bad := range []rune{0x1b, 0x202e, 0x200b, 0xe0041, 0xe0042} {
		if strings.ContainsRune(got, bad) {
			t.Errorf("%U not stripped: %q", bad, got)
		}
	}
	if got != "pay[31m to exe.txt ok done" {
		t.Errorf("PlainText = %q", got)
	}
}

// ZWJ / ZWNJ carry meaning in emoji and several scripts; body text
// keeps them.
func TestTextKeepsJoiners(t *testing.T) {
	in := "family \U0001F468\u200d\U0001F469 \u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645"
	if got := PlainText(in); got != in {
		t.Errorf("PlainText changed joiners: %q", got)
	}
}

// bluemonday passes bidi / control / tag characters through; HTML()
// strips them afterwards.
func TestHTMLStripsControlAndBidi(t *testing.T) {
	in := "<p>invoice\u202efdp.exe\x07 \u2066x\u2069\U000E0049</p>"
	got := HTML(in)
	for _, bad := range []rune{0x202e, 0x07, 0x2066, 0x2069, 0xe0049} {
		if strings.ContainsRune(got, bad) {
			t.Errorf("%U survived HTML(): %q", bad, got)
		}
	}
	if got != "<p>invoicefdp.exe x</p>" {
		t.Errorf("HTML = %q", got)
	}
}

// Outbound keeps the bare policy (no extra character pass): this
// change is inbound-only.
func TestOutboundUnchangedByInboundStrip(t *testing.T) {
	in := "<p>a\u202eb</p>"
	if got := Outbound(in); got != in {
		t.Errorf("Outbound = %q, want %q", got, in)
	}
}

func TestHeaderValueFlattensUnicodeLineBreaks(t *testing.T) {
	got := HeaderValue("a\u2028b\u2029c\u202ed")
	if got != "a b cd" {
		t.Errorf("HeaderValue = %q", got)
	}
}

func TestTextCollapsesWhitespace(t *testing.T) {
	in := "Hello\n\n\n   world\t\tagain"
	got := Text(in)
	if got != "Hello world again" {
		t.Errorf("Text = %q, want \"Hello world again\"", got)
	}
}

func TestSnippetTruncates(t *testing.T) {
	long := strings.Repeat("abc ", 100) // 400 chars
	s := Snippet(long, 50)
	// 50 runes + ellipsis
	if !strings.HasSuffix(s, "…") {
		t.Errorf("missing ellipsis: %q", s)
	}
	// Count runes, not bytes — the ellipsis is a multibyte rune.
	if got := len([]rune(s)); got != 51 {
		t.Errorf("Snippet rune len = %d, want 51 (50 + …)", got)
	}
}

func TestSnippetShortInputUnchanged(t *testing.T) {
	in := "short"
	if got := Snippet(in, 100); got != "short" {
		t.Errorf("Snippet = %q, want \"short\"", got)
	}
}

func TestSnippetDefaultMaxRunes(t *testing.T) {
	// maxRunes <= 0 → 200
	long := strings.Repeat("x", 500)
	got := Snippet(long, 0)
	if r := []rune(got); len(r) != 201 { // 200 + ellipsis
		t.Errorf("default snippet rune len = %d, want 201", len(r))
	}
}

func TestSnippetUnicodeSafe(t *testing.T) {
	// Verify we don't slice a multibyte rune in half.
	in := strings.Repeat("✓ ", 100)
	got := Snippet(in, 10)
	if len([]rune(got)) != 11 {
		t.Errorf("unicode snippet rune len = %d, want 11", len([]rune(got)))
	}
}

// Phase 5/C — outbound HTML sanitization for LLM-supplied drafts.
// Same allowlist as HTML(); script tags, iframes, and remote-resource
// refs must be stripped before the body is encrypted and sent.

func TestOutboundStripsScript(t *testing.T) {
	got := Outbound(`<p>hello</p><script>alert(1)</script>`)
	if strings.Contains(got, "<script>") || strings.Contains(got, "alert") {
		t.Errorf("script not stripped: %q", got)
	}
	if !strings.Contains(got, "<p>hello</p>") {
		t.Errorf("legitimate <p> markup lost: %q", got)
	}
}

func TestOutboundKeepsBasicMarkup(t *testing.T) {
	cases := []string{
		`<p><b>bold</b> and <em>emphasis</em></p>`,
		`<ul><li>one</li><li>two</li></ul>`,
		`<blockquote>quoted text</blockquote>`,
		`<h2>heading</h2>`,
	}
	for _, in := range cases {
		got := Outbound(in)
		if got == "" {
			t.Errorf("Outbound(%q) returned empty", in)
		}
	}
}

func TestOutboundStripsRemoteImageAndIframe(t *testing.T) {
	in := `<p>hi</p><img src="https://attacker.example/track.gif"><iframe src="evil"></iframe>`
	got := Outbound(in)
	if strings.Contains(got, "<img") || strings.Contains(got, "<iframe") {
		t.Errorf("img/iframe not stripped: %q", got)
	}
	if strings.Contains(got, "attacker.example") {
		t.Errorf("remote URL survived: %q", got)
	}
}

// Phase 5/C — C-2 fold. sanitize.Text now strips C0 control chars
// (except \n / \t) and the C1 range. Hardens the LLM-output path
// against terminal-escape injection in mail bodies.

func TestTextStripsC0ControlChars(t *testing.T) {
	in := "hi\x07world\x1bextra"
	got := Text(in)
	if strings.ContainsAny(got, "\x07\x1b") {
		t.Errorf("control chars not stripped: %q", got)
	}
	if !strings.Contains(got, "hiworldextra") {
		t.Errorf("visible content lost: %q", got)
	}
}

func TestTextPreservesNewlineAndTab(t *testing.T) {
	// Whitespace collapse turns \n/\t into single spaces in the
	// final output (whitespaceRun), but the strip pass before
	// that must not eat them. Verify the result still contains
	// the words separated.
	in := "line one\nline two\tcol b"
	got := Text(in)
	for _, want := range []string{"line one", "line two", "col b"} {
		if !strings.Contains(got, want) {
			t.Errorf("piece %q lost: %q", want, got)
		}
	}
}

func TestTextStripsC1ControlChars(t *testing.T) {
	// 0x80-0x9f is the C1 range.  is NEL (next line) — a
	// common one in adversarial payloads.
	in := "hiworldextra"
	got := Text(in)
	if strings.Contains(got, "") || strings.Contains(got, "") {
		t.Errorf("C1 control chars not stripped: %q", got)
	}
}
