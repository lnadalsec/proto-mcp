package mcptools

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lnadalsec/proto-mcp/internal/mcp"
	"github.com/lnadalsec/proto-mcp/internal/sanitize"
	"github.com/lnadalsec/proto-mcp/internal/store"
)

// Phase 8/C — mail_save_attachment. Decrypted attachment bytes
// land in ~/Downloads with a sanitized + collision-safe filename.
// Defense-in-depth path traversal: filename runs through
// sanitize.Filename, filepath.Base, then filepath.Clean; the final
// parent directory must equal the resolved ~/Downloads or we
// refuse.
//
// XDG_DOWNLOAD_DIR support deferred — hardcoded ~/Downloads is the
// v1 contract, documented in the tool description and policy stub.

func mailSaveAttachment(deps Deps) mcp.Tool {
	type input struct {
		MessageID    string `json:"message_id"`
		AttachmentID string `json:"attachment_id"`
		Filename     string `json:"filename,omitempty"`
	}
	type result struct {
		SavedPath string `json:"saved_path"`
		Filename  string `json:"filename"`
		SizeBytes int64  `json:"size_bytes"`
	}

	return mcp.Tool{
		Name: "mail_save_attachment",
		Description: "Save a decrypted attachment to ~/Downloads. " +
			"Filename is sanitized (RTL spoofing, control chars, path separators, leading dots stripped). " +
			"Refuses paths outside ~/Downloads. Existing files get a (2), (3), ... suffix rather than " +
			"overwriting. On cache miss, fetches + caches first (same path as mail_download_attachment). " +
			"The saved file carries the macOS quarantine attribute, so Gatekeeper checks it like any download. " +
			"Touch ID prompt shows the literal filename (resolved from the message when not given) + target " +
			"directory, and warns about executable / installer types and double extensions.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"message_id":    {"type": "string"},
				"attachment_id": {"type": "string"},
				"filename":      {"type": "string"}
			},
			"required": ["message_id", "attachment_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"saved_path": {"type": "string"},
				"filename":   {"type": "string"},
				"size_bytes": {"type": "integer"}
			},
			"required": ["saved_path", "filename", "size_bytes"]
		}`),
		// The dialog names the file that will actually be written: when
		// no filename is passed, the attachment's own name is resolved
		// (cache, else one server fetch) and handed to the handler as the
		// snapshot, so the approved name is the saved name.
		PromptSnapshot: func(ctx context.Context, raw json.RawMessage) (string, string, any, error) {
			var in input
			_ = json.Unmarshal(raw, &in)
			name := in.Filename
			if name == "" {
				var err error
				if name, err = attachmentNameForPrompt(ctx, deps, in.MessageID, in.AttachmentID); err != nil {
					return "", "", nil, fmt.Errorf("resolve attachment name: %w", err)
				}
			}
			fname, err := saveFilename(name)
			if err != nil {
				return "", "", nil, err
			}
			subj := lookupSubject(deps, in.MessageID)
			body := "save attachment from " + subj + " as " + capField(fname, promptNameMaxRunes) + " to ~/Downloads"
			if warn := dangerousFileWarning(fname); warn != "" {
				body += "\n" + warn
			}
			title := mcp.SanitizePromptText("Approve mail_save_attachment?", 120)
			return title, mcp.SanitizePromptText(body, 4000), saveSnapshot{Filename: fname}, nil
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_save_attachment: "+err.Error())
			}
			if in.MessageID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_save_attachment: message_id is required")
			}
			if in.AttachmentID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_save_attachment: attachment_id is required")
			}
			if deps.Store == nil {
				return nil, errors.New("mail_save_attachment: store not available")
			}

			// 1. Get bytes: cache hit first, else fetch + cache.
			row, content, err := loadOrFetchAttachment(ctx.Std, deps, in.MessageID, in.AttachmentID)
			if err != nil {
				return mcp.ErrorResult("mail_save_attachment: %v", err), nil
			}

			// 2. Pick filename: the one the approval dialog showed;
			// without a dialog, caller override, else the cached name.
			name := row.Filename
			if in.Filename != "" {
				name = in.Filename
			}
			if snap, ok := ctx.Snapshot.(saveSnapshot); ok && snap.Filename != "" {
				name = snap.Filename
			}
			fname, err := saveFilename(name)
			if err != nil {
				return mcp.ErrorResult("mail_save_attachment: %v", err), nil
			}

			// 3. Resolve target directory + verify containment.
			home, err := os.UserHomeDir()
			if err != nil {
				return mcp.ErrorResult("mail_save_attachment: home dir: %v", err), nil
			}
			rootDir := filepath.Clean(filepath.Join(home, "Downloads"))
			if err := os.MkdirAll(rootDir, 0o700); err != nil {
				return mcp.ErrorResult("mail_save_attachment: mkdir ~/Downloads: %v", err), nil
			}
			cleanedDest := filepath.Clean(filepath.Join(rootDir, fname))
			// Parent of cleanedDest must equal rootDir. If
			// filepath.Clean expanded any "..", the parent diverges
			// and we refuse. (sanitize.Filename should have
			// substituted slashes already; this is belt + suspenders.)
			if filepath.Dir(cleanedDest) != rootDir {
				return mcp.ErrorResult(
					"mail_save_attachment: refusing path outside ~/Downloads (resolved to %q)",
					cleanedDest,
				), nil
			}

			// 4. Open with O_EXCL; on conflict, append (N) suffix.
			finalPath, f, err := openExclusiveWithSuffix(cleanedDest)
			if err != nil {
				return mcp.ErrorResult("mail_save_attachment: open: %v", err), nil
			}
			defer f.Close()

			// 5. Quarantine before the first byte lands. Fail closed: a
			// file from an email that Gatekeeper won't check is the
			// hazard this tool must not create, so if the attribute
			// can't be set (a ~/Downloads on a filesystem without
			// xattrs), the empty file is removed and nothing is saved.
			if err := setQuarantine(f, quarantineValue(time.Now())); err != nil {
				_ = f.Close()
				_ = os.Remove(finalPath)
				return mcp.ErrorResult("mail_save_attachment: refusing to save without the macOS quarantine attribute (%v); nothing was saved", err), nil
			}
			if _, err := f.Write(content); err != nil {
				_ = os.Remove(finalPath)
				return mcp.ErrorResult("mail_save_attachment: write: %v", err), nil
			}

			return mcp.StructuredResult(result{
				SavedPath: finalPath,
				Filename:  filepath.Base(finalPath),
				SizeBytes: int64(len(content)),
			})
		},
	}
}

// saveSnapshot is mail_save_attachment's PromptSnapshot state: the
// sanitized filename the dialog showed.
type saveSnapshot struct {
	Filename string
}

// saveFilename sanitizes an attachment name for writing into
// ~/Downloads: sanitize.Filename, then filepath.Base + Clean as
// defense in depth even though sanitize.Filename already substituted
// separators.
func saveFilename(name string) (string, error) {
	fname := filepath.Base(filepath.Clean(sanitize.Filename(name)))
	if fname == "" || fname == "." || fname == "/" || fname == "\\" {
		return "", fmt.Errorf("refusing empty / invalid filename %q after sanitization", fname)
	}
	return fname, nil
}

// attachmentNameForPrompt resolves an attachment's own filename for
// the approval dialog: from the local cache when present, else from
// one fetch of the message envelope. An attachment that can't be
// found can't be shown, so the call is refused.
func attachmentNameForPrompt(ctx context.Context, deps Deps, messageID, attachmentID string) (string, error) {
	if messageID == "" || attachmentID == "" {
		return "", errors.New("message_id and attachment_id are required")
	}
	if deps.Store != nil {
		lctx, cancel := context.WithTimeout(ctx, promptLookupTimeout)
		row, err := deps.Store.GetCachedAttachment(lctx, messageID, attachmentID)
		cancel()
		if err == nil && row.Filename != "" {
			return row.Filename, nil
		}
	}
	m, err := fetchForPrompt(ctx, deps, messageID)
	if err != nil {
		return "", err
	}
	for _, a := range m.Attachments {
		if a.ID == attachmentID {
			return a.Name, nil
		}
	}
	return "", fmt.Errorf("attachment %s not found on message %s", attachmentID, messageID)
}

// quarantineXattr is the extended attribute Gatekeeper reads.
const quarantineXattr = "com.apple.quarantine"

// quarantineValue formats a com.apple.quarantine value:
// "<flags>;<hex unix time>;<agent>;<event UUID>". 0081 is the flag
// set a downloading app writes (download + Gatekeeper check required).
func quarantineValue(now time.Time) string {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = u[6]&0x0f | 0x40 // version 4
	u[8] = u[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("0081;%08x;proto-mcp;%X-%X-%X-%X-%X", now.Unix(), u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// dangerousExtensions are file types that run code (or install it)
// when opened from Finder.
var dangerousExtensions = map[string]bool{
	"app": true, "command": true, "tool": true, "terminal": true,
	"pkg": true, "mpkg": true, "dmg": true, "iso": true, "img": true,
	"sh": true, "bash": true, "zsh": true, "csh": true, "ksh": true,
	"py": true, "pl": true, "rb": true, "jar": true,
	"scpt": true, "scptd": true, "applescript": true, "workflow": true, "action": true,
	"webloc": true, "inetloc": true, "fileloc": true,
	"prefpane": true, "kext": true, "dylib": true, "plugin": true,
}

// decoyExtensions are document types a dangerous file pretends to be
// in "invoice.pdf.app".
var decoyExtensions = map[string]bool{
	"pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true,
	"txt": true, "rtf": true, "csv": true, "pages": true, "numbers": true, "key": true,
	"jpg": true, "jpeg": true, "png": true, "gif": true, "heic": true,
	"mp3": true, "mp4": true, "mov": true, "zip": true, "html": true,
}

// dangerousFileWarning returns a dialog line warning about a filename
// that runs code when opened, or that hides its real type behind a
// second extension; "" when neither applies.
func dangerousFileWarning(name string) string {
	parts := strings.Split(strings.ToLower(name), ".")
	if len(parts) < 2 {
		return ""
	}
	ext := strings.TrimSpace(parts[len(parts)-1])
	var warns []string
	if dangerousExtensions[ext] {
		warns = append(warns, "WARNING: ."+ext+" files run code or install software when opened")
	}
	if len(parts) >= 3 {
		if prev := strings.TrimSpace(parts[len(parts)-2]); decoyExtensions[prev] && prev != ext {
			warns = append(warns, "WARNING: double extension: this is a ."+ext+" file, not a ."+prev)
		}
	}
	return strings.Join(warns, "\n")
}

// loadOrFetchAttachment returns the cached row + its plaintext
// bytes if cached, else fetches from Proton (decrypting via the
// address keyring) and caches before returning. Mirrors the
// mail_download_attachment cache-hit-or-fetch contract.
func loadOrFetchAttachment(ctx context.Context, deps Deps, messageID, attachmentID string) (store.AttachmentCacheRow, []byte, error) {
	if row, err := deps.Store.GetCachedAttachment(ctx, messageID, attachmentID); err == nil {
		return row, row.Content, nil
	} else if !errors.Is(err, store.ErrAttachmentNotCached) {
		return store.AttachmentCacheRow{}, nil, fmt.Errorf("cache lookup: %w", err)
	}
	if deps.Session == nil {
		return store.AttachmentCacheRow{}, nil, errors.New("session not available")
	}
	cap := maxAttachmentBytes(deps)

	// Pre-fetch size check.
	m, err := deps.Session.Client.GetMessage(ctx, messageID)
	if err != nil {
		return store.AttachmentCacheRow{}, nil, fmt.Errorf("fetch envelope: %w", err)
	}
	for _, a := range m.Attachments {
		if a.ID == attachmentID && a.Size > cap {
			return store.AttachmentCacheRow{}, nil, fmt.Errorf(
				"attachment is %d bytes; exceeds max_attachment_bytes (%d)",
				a.Size, cap,
			)
		}
	}

	payload, err := deps.Session.FetchAndDecryptAttachment(ctx, messageID, attachmentID)
	if err != nil {
		return store.AttachmentCacheRow{}, nil, err
	}
	if payload.SizeBytes > cap {
		return store.AttachmentCacheRow{}, nil, fmt.Errorf(
			"decrypted size %d exceeds max_attachment_bytes (%d)",
			payload.SizeBytes, cap,
		)
	}
	row := store.AttachmentCacheRow{
		MessageID:    payload.MessageID,
		AttachmentID: payload.AttachmentID,
		Filename:     payload.Filename,
		MIMEType:     payload.MIMEType,
		SizeBytes:    payload.SizeBytes,
		Content:      payload.Content,
	}
	_ = deps.Store.SetAttachmentCache(ctx, row)
	_, _ = deps.Store.EvictAttachmentsToFit(ctx, attachmentCacheCeilingBytes)
	return row, payload.Content, nil
}

// openExclusiveWithSuffix opens `path` for write with O_EXCL, and
// on EEXIST appends a "(2)", "(3)", ... suffix before the extension
// until it finds a free name. Caps at 999 tries — refuses rather
// than spinning if the directory is somehow saturated with
// collisions.
func openExclusiveWithSuffix(path string) (string, *os.File, error) {
	ext := filepath.Ext(path)
	stem := strings.TrimSuffix(path, ext)
	for i := 0; i < 1000; i++ {
		candidate := path
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, i+1, ext)
		}
		f, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return candidate, f, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, fmt.Errorf("could not find free filename after 999 attempts at %s", path)
}
