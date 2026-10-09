// Package sanitize is the single audited surface for turning
// Proton-Mail message bodies into LLM-safe payloads.
//
// Two outputs:
//
//   - HTML(input) — minimal-allowlist HTML stripped of scripts,
//     iframes, remote-image refs, and any markup not on the
//     allowlist below. Designed for an LLM prompt: rich enough to
//     preserve sentence structure / links / lists, narrow enough
//     that prompt-injection embedded in exotic markup has nowhere
//     to hide.
//
//   - Text(input) — pure text extraction from an HTML (or HTML-ish)
//     body with whitespace collapsed. Source for snippets and for the
//     FTS5 body_text column.
//
//   - PlainText(input) — the same for a text/plain body: no tag
//     stripping (a plain-text body has no markup, so "a < b > c" is
//     content), line structure kept.
//
// Every output has C0/C1 control characters and invisible bidi /
// zero-width formatting characters removed (stripControlChars).
//
// SECURITY Foundational #7 + Phase-2 plan Q1 (strict policy).
package sanitize

import (
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

// AllowedHTMLTags is the closed allowlist used by HTML(). Anything not
// in this list gets stripped (content kept, surrounding tags removed
// by bluemonday). Kept narrow on purpose — every additional tag is a
// new place for exotic HTML to hide a prompt-injection vector.
//
// Block-level structure (p, br, headings, lists, blockquote) preserves
// the visual rhythm of an email so the LLM can tell paragraphs apart.
// Inline emphasis (b, strong, i, em) carries semantic weight. Anchors
// are allowed but their href is stripped — the LLM sees the link text
// and never the underlying URL, which neutralizes the "click here for
// reset" embed-attack class.
var AllowedHTMLTags = []string{
	"p", "br",
	"b", "strong", "i", "em",
	"ul", "ol", "li",
	"h1", "h2", "h3", "h4",
	"blockquote",
}

// Note: <a> is intentionally NOT on the allowlist. bluemonday strips
// the element when no attrs are allowed on it but preserves the link
// text as surrounding content — so the LLM sees "click here" with no
// surrounding URL. Letting href through would give an attacker a free
// string the LLM can be tricked by; dropping it is the right safety.

// htmlPolicy is built once and reused. bluemonday.Policy is safe for
// concurrent use, so a single package-level value is fine.
var htmlPolicy = buildHTMLPolicy()

func buildHTMLPolicy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements(AllowedHTMLTags...)
	// Anchors are on the allowlist but their href is NOT — we keep
	// the visible link text and drop the URL the LLM would otherwise
	// see. This is the deliberate "prompt-injection via crafted href"
	// mitigation; the user can always re-fetch the message via the
	// Proton web UI if they want the actual link.
	//
	// Note: not calling AllowAttrs(...) at all = strip everything.
	return p
}

// HTML returns a sanitized copy of input. Always safe to call;
// returns "" for empty input.
//
// bluemonday passes control and bidi characters through untouched, so
// the result is run through stripControlChars like Text: an RLO or a
// Unicode tag character in an HTML body would otherwise reach the LLM
// (and any terminal the body is printed to) as-is. Removing those
// runes cannot create markup, so the policy's guarantees still hold.
func HTML(input string) string {
	if input == "" {
		return ""
	}
	return stripControlChars(htmlPolicy.Sanitize(input))
}

// Outbound sanitizes LLM-supplied HTML before it's encrypted and
// shipped to recipients. Same allowlist as HTML() — every reason
// that policy was the right answer for INBOUND mail (scripts /
// tracking pixels / remote-image refs hidden in exotic markup) is
// equally a reason to enforce it OUTBOUND. The LLM should not be
// able to send what we wouldn't accept from a stranger.
//
// Why an alias: the inbound and outbound use cases are different
// enough that a future tightening on one shouldn't surprise the
// other. Today Outbound is HTML(); if outbound ever needs different
// rules (e.g. allow <a href> for explicit hyperlinks the LLM was
// told to include), this is the seam.
//
// Outbound deliberately does NOT take HTML()'s inbound
// control/bidi-character pass: it keeps the bare policy so this
// change to the read path leaves what is sent untouched.
func Outbound(input string) string {
	if input == "" {
		return ""
	}
	return htmlPolicy.Sanitize(input)
}

// htmlTagStripper removes any remaining tags after the HTML policy
// has done its work. The policy keeps allowlist tags; this pass
// converts them to plain text. We DON'T use bluemonday.StripTagsPolicy
// because it doesn't handle entities the way Text() needs (it
// decodes &amp; → & which can re-introduce noise).
var htmlTagStripper = regexp.MustCompile(`(?s)<[^>]+>`)

// styleContentStripper / scriptContentStripper remove <style>…</style>
// and <script>…</script> element CONTENT (not just the delimiters)
// before the tag-stripper runs. D42: marketing HTML emails commonly
// carry multi-KB <style> blocks (font-face, media queries) that
// would otherwise survive htmlTagStripper and land in the plaintext
// / FTS index.
//
// RE2 (Go's regexp engine) doesn't support backreferences, so we
// use a separate regex per tag rather than one with \1. Case-
// insensitive + dot-matches-newline so each regex catches the
// element regardless of formatting / mixed case.
var (
	styleContentStripper  = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</\s*style\s*>`)
	scriptContentStripper = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</\s*script\s*>`)
)

// whitespaceRun matches any run of two-or-more whitespace chars
// (including newlines) so Text() can collapse them to one space.
var whitespaceRun = regexp.MustCompile(`\s+`)

// Text extracts plain text from an HTML or text input, suitable for
// snippet generation and FTS5 indexing.
//
// Steps:
//
//  1. Strip <style>…</style> and <script>…</script> element content
//     wholesale (D42 — otherwise CSS / JS leaks into the plaintext).
//  2. Strip every remaining tag (including allowlist tags — for text
//     output we want pure content).
//  3. Strip control and invisible formatting characters.
//  4. Collapse whitespace runs to a single space.
//  5. Trim leading/trailing space.
//
// Quoted-reply lines ("> ...") are kept. Dropping them hid part of the
// message from mail_read and from the FTS index, and the quoted text is
// as much sender-controlled content as the rest. Use PlainText for a
// text/plain body: the tag pass here would eat "a < b > c".
//
// Note: HTML entities like &amp; are NOT decoded. Decoding adds a
// dependency on html.UnescapeString and lets clever encodings hide
// content from the FTS index — which is the inverse of what we want.
// A literal "&amp;" in the index won't match "&" in a search query,
// but that's a reasonable trade-off for an index built specifically
// to find prompt-injection-like content via key terms.
func Text(input string) string {
	if input == "" {
		return ""
	}
	out := styleContentStripper.ReplaceAllString(input, " ")
	out = scriptContentStripper.ReplaceAllString(out, " ")
	out = htmlTagStripper.ReplaceAllString(out, " ")
	out = stripControlChars(out)
	out = whitespaceRun.ReplaceAllString(out, " ")
	return strings.TrimSpace(out)
}

// blankLineRun matches three or more line breaks (with any horizontal
// whitespace between them) so PlainText can cap blank runs at one
// empty line.
var blankLineRun = regexp.MustCompile(`\n[ \t]*(?:\n[ \t]*){2,}`)

// PlainText cleans a text/plain body for the LLM. Unlike Text it does
// no tag stripping (there is no markup; "<" and ">" are content) and
// keeps the line structure, quoted-reply lines included: CRLF becomes
// LF, trailing spaces are trimmed, runs of blank lines collapse to
// one, and control / invisible formatting characters are stripped.
func PlainText(input string) string {
	if input == "" {
		return ""
	}
	out := strings.ReplaceAll(input, "\r\n", "\n")
	out = strings.ReplaceAll(out, "\r", "\n")
	out = stripControlChars(out)
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	out = blankLineRun.ReplaceAllString(strings.Join(lines, "\n"), "\n\n")
	return strings.TrimSpace(out)
}

// HeaderValue flattens a raw, sender-controlled header value to a
// single line: CR / LF / TAB (folding whitespace) become spaces and
// every other C0 / DEL / C1 control byte is dropped, then the result
// is trimmed. It does no length capping; callers bound it themselves.
func HeaderValue(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t', 0x2028, 0x2029:
			// U+2028 / U+2029 render as line breaks too.
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(stripControlChars(s))
}

// stripControlChars drops C0 (< 0x20, excluding \n and \t) and C1
// (0x80–0x9F) control bytes from s, plus the invisible formatting
// characters listed in isInvisibleFormat. SECURITY C-2: terminal escape
// sequences and zero-width control bytes embedded in mail bodies
// can corrupt LLM output, hide content from human reviewers, or
// break terminal rendering when the body is dumped to stdout via
// CLI tools. The few control chars we keep (\n, \t) carry real
// structure; everything else is at best invisible and at worst
// adversarial.
func stripControlChars(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20:
			// C0 control char — drop.
		case r >= 0x7f && r <= 0x9f:
			// DEL (0x7f) and C1 control range — drop.
		case isInvisibleFormat(r):
			// Bidi controls, zero-width characters, tag characters.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isInvisibleFormat reports whether r is an invisible formatting
// character that sender-controlled text has no business carrying into
// an LLM prompt: bidi marks / embeddings / overrides / isolates (they
// reorder what a human reviewer sees), zero-width space, word joiner
// and invisible operators, BOM, and Unicode tag characters (U+E0000
// block, which encode hidden ASCII the model can read but a person
// can't — "ASCII smuggling").
//
// ZWJ / ZWNJ (U+200C, U+200D) are kept: emoji sequences and several
// scripts (Persian, Indic) need them in body text. The approval dialog
// (internal/mcp SanitizePromptText) drops them too; that path is
// stricter on purpose.
func isInvisibleFormat(r rune) bool {
	switch {
	case r == 0x200e || r == 0x200f || r == 0x061c: // LRM, RLM, ALM
		return true
	case r >= 0x202a && r <= 0x202e: // bidi embeddings / overrides
		return true
	case r >= 0x2066 && r <= 0x2069: // bidi isolates
		return true
	case r == 0x200b || r == 0xfeff: // ZWSP, BOM
		return true
	case r >= 0x2060 && r <= 0x2064: // word joiner, invisible operators
		return true
	case r >= 0xe0000 && r <= 0xe007f: // tag characters
		return true
	}
	return false
}

// Snippet returns up to maxRunes runes from Text(input), suitable for
// the message-list preview. maxRunes <= 0 falls back to 200.
//
// Runes (not bytes) so a snippet doesn't slice a multibyte character
// in half — important for emoji-heavy email and any non-ASCII content.
func Snippet(input string, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = 200
	}
	text := Text(input)
	r := []rune(text)
	if len(r) <= maxRunes {
		return text
	}
	return string(r[:maxRunes]) + "…"
}
