// Package sync drives the event-cursor poll loop that keeps the local
// SQLite mirror in lockstep with the Proton server.
//
// RunOnce is the unit of work: read the stored cursor, call
// client.GetEvent in a loop until the server says it has nothing
// more, apply each diff to the store, and advance the cursor as we
// go (so a crash mid-loop doesn't re-process events on the next run).
//
// Phase 2/C ships RunOnce. Phase 6's daemon will call into this on a
// 30s/5m active/idle cadence from a goroutine; the CLI exposes a
// `protonmcp sync` one-shot for testing and manual nudges.
package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	protonclient "github.com/lnadalsec/proto-mcp/internal/proton"
	"github.com/lnadalsec/proto-mcp/internal/store"
)

// cursorKey is the sync_state row name that holds the latest applied
// event ID. Matches what cmd/protonmcp/backfill.go writes after the
// initial cold drain.
const cursorKey = "event_cursor"

// RunResult summarizes a RunOnce call so callers (CLI / daemon /
// future audit log) can print or persist meaningful numbers.
type RunResult struct {
	StartCursor      string
	EndCursor        string
	Pages            int // event pages drained
	MessagesUpserted int
	MessagesDeleted  int
	LabelsUpserted   int
	LabelsDeleted    int
	RefreshRequested bool // server asked for a full backfill
	Elapsed          time.Duration
}

// ErrRefreshRequested is returned when the server signals the cursor
// is too old to replay events. The caller must drop the mirror and
// re-run `protonmcp backfill`. We don't auto-drop the SQLite store —
// that would silently delete cached bodies + audit log; the user
// should decide.
var ErrRefreshRequested = errors.New("sync: server requested a full refresh — run `protonmcp backfill` again")

// ErrConcurrentSync is returned when another sync — in practice a
// different process, e.g. `protonmcp sync` while the daemon runs —
// advanced the cursor while this run was draining. This run stops
// without applying the event it was holding; everything up to the
// stored cursor is already in the mirror, and the next run resumes
// from there.
var ErrConcurrentSync = errors.New("sync: event cursor moved by a concurrent sync; retry later")

// mailSyncSem serializes RunOnce within the process. The background
// ticker, the mail_sync tool and the CLI all call RunOnce; two
// interleaved drains from the same cursor would each apply the same
// events, and the slower one would replay a stale event after the
// faster one applied a later one (a create after its delete). A
// one-slot channel rather than a sync.Mutex so a waiting caller still
// honors its context. Cross-process races are handled by the
// compare-and-set cursor write (store.AdvanceSyncCursor).
var mailSyncSem = make(chan struct{}, 1)

// acquire takes a one-slot semaphore, or returns ctx's error.
func acquire(ctx context.Context, sem chan struct{}) (release func(), err error) {
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// eventSource is the part of the Proton session RunOnce needs. It
// exists so the drain loop can be tested with scripted event pages.
type eventSource interface {
	LatestEventID(ctx context.Context) (string, error)
	GetEvent(ctx context.Context, eventID string) ([]gpa.Event, bool, error)
}

// sessionEvents adapts *protonclient.Session to eventSource.
type sessionEvents struct{ sess *protonclient.Session }

func (s sessionEvents) LatestEventID(ctx context.Context) (string, error) {
	return s.sess.LatestEventID(ctx)
}

func (s sessionEvents) GetEvent(ctx context.Context, eventID string) ([]gpa.Event, bool, error) {
	return s.sess.Client.GetEvent(ctx, eventID)
}

// RunOnce drains all pending events from the saved cursor and
// returns. Idempotent: re-running after a successful run is a no-op
// (no events past the cursor → returns immediately).
//
// Errors during page application abort the loop. Each event is
// applied in the same transaction as the cursor move past it, so a
// re-run picks up exactly from the failure point.
//
// Calls are serialized within the process (see mailSyncSem); a call
// made while another is draining waits for it, then drains whatever
// is left.
func RunOnce(ctx context.Context, sess *protonclient.Session, st *store.Store) (*RunResult, error) {
	return runOnce(ctx, sessionEvents{sess}, st)
}

// runOnce is RunOnce over any eventSource.
func runOnce(ctx context.Context, src eventSource, st *store.Store) (*RunResult, error) {
	release, err := acquire(ctx, mailSyncSem)
	if err != nil {
		return &RunResult{}, err
	}
	defer release()
	return drain(ctx, src, st)
}

// drain is RunOnce without the in-process lock.
func drain(ctx context.Context, src eventSource, st *store.Store) (*RunResult, error) {
	start := time.Now()
	res := &RunResult{}

	cursor, err := st.GetSyncState(ctx, cursorKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// No cursor → caller hasn't run backfill yet. Capture the
			// latest event ID and store it; equivalent to "start
			// listening from now". SeedSyncState keeps a cursor a
			// concurrent run stored first.
			latest, lerr := src.LatestEventID(ctx)
			if lerr != nil {
				return res, fmt.Errorf("seed cursor: %w", lerr)
			}
			seeded, serr := st.SeedSyncState(ctx, cursorKey, latest)
			if serr != nil {
				return res, fmt.Errorf("save seeded cursor: %w", serr)
			}
			res.StartCursor = seeded
			res.EndCursor = seeded
			res.Elapsed = time.Since(start)
			slog.Info("sync seeded cursor",
				"cursor", seeded, "note", "no prior backfill — listening from now")
			return res, nil
		}
		return res, fmt.Errorf("read cursor: %w", err)
	}
	res.StartCursor = cursor

	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		events, more, err := src.GetEvent(ctx, cursor)
		if err != nil {
			return res, fmt.Errorf("get event %s: %w", cursor, err)
		}
		if len(events) == 0 {
			break
		}
		for _, e := range events {
			res.Pages++
			if e.Refresh != 0 {
				res.RefreshRequested = true
				return res, ErrRefreshRequested
			}
			// Counts go to a scratch result and are only added once
			// the transaction commits, so a rolled-back event isn't
			// reported as applied.
			var delta RunResult
			err := st.AdvanceSyncCursor(ctx, cursorKey, cursor, e.EventID, func(tx *store.Tx) error {
				return applyEvent(ctx, tx, e, &delta)
			})
			if errors.Is(err, store.ErrCursorConflict) {
				res.EndCursor = cursor
				return res, ErrConcurrentSync
			}
			if err != nil {
				return res, fmt.Errorf("apply event %s: %w", e.EventID, err)
			}
			res.MessagesUpserted += delta.MessagesUpserted
			res.MessagesDeleted += delta.MessagesDeleted
			res.LabelsUpserted += delta.LabelsUpserted
			res.LabelsDeleted += delta.LabelsDeleted
			cursor = e.EventID
		}
		// SECURITY D17 / C-5: respect the SDK's `more` bool rather
		// than guessing via len(events). The previous heuristic
		// `len(events) < 2` exited after legitimate 1-event pages,
		// leaving the next-cursor-state-vs-server-state question
		// implicit. `more == true` means the server has at least
		// one more event past this batch; keep polling. `more ==
		// false` means we're caught up; stop.
		if !more {
			break
		}
	}

	res.EndCursor = cursor
	res.Elapsed = time.Since(start)
	slog.Info("sync drained",
		"pages", res.Pages,
		"messages_upserted", res.MessagesUpserted,
		"messages_deleted", res.MessagesDeleted,
		"elapsed_ms", res.Elapsed.Milliseconds(),
	)
	return res, nil
}

// mirrorWriter is the set of store mutations applyEvent makes. Both
// *store.Store and *store.Tx (the cursor transaction) implement it.
type mirrorWriter interface {
	UpsertMessage(ctx context.Context, m store.Message) error
	SetMessageLabels(ctx context.Context, messageID string, labelIDs []string) error
	DeleteMessage(ctx context.Context, messageID string) error
	InvalidateBodyCache(ctx context.Context, messageID string) error
	UpsertLabel(ctx context.Context, l store.Label) error
	DeleteLabel(ctx context.Context, labelID string) error
}

// applyEvent walks a single Event and applies every diff to the
// store. Message bodies are NOT re-fetched here — Update events
// (not flag-only UpdateFlags) invalidate the cached body, clearing it,
// so the next `protonmcp read` triggers a fresh decrypt.
func applyEvent(ctx context.Context, st mirrorWriter, e gpa.Event, res *RunResult) error {
	for _, m := range e.Messages {
		switch m.Action {
		case gpa.EventDelete:
			if err := st.DeleteMessage(ctx, m.ID); err != nil {
				return err
			}
			res.MessagesDeleted++
		case gpa.EventCreate, gpa.EventUpdate, gpa.EventUpdateFlags:
			row, err := protonclient.ToStoreMessage(m.Message)
			if err != nil {
				return err
			}
			if err := st.UpsertMessage(ctx, row); err != nil {
				return err
			}
			if err := st.SetMessageLabels(ctx, m.ID, m.Message.LabelIDs); err != nil {
				return err
			}
			// Update events potentially mean the body changed (drafts
			// in particular). Invalidate the body cache so the next
			// read fetches fresh. UpdateFlags (read/unread, star,
			// labels) can't change the body, and reading a message
			// emits one, so it must not throw the cached body away.
			if m.Action == gpa.EventUpdate {
				if err := st.InvalidateBodyCache(ctx, m.ID); err != nil {
					return err
				}
			}
			res.MessagesUpserted++
		}
	}

	for _, l := range e.Labels {
		switch l.Action {
		case gpa.EventDelete:
			if err := st.DeleteLabel(ctx, l.ID); err != nil {
				return err
			}
			res.LabelsDeleted++
		case gpa.EventCreate, gpa.EventUpdate, gpa.EventUpdateFlags:
			if err := st.UpsertLabel(ctx, store.Label{
				ID:    l.Label.ID,
				Name:  l.Label.Name,
				Color: l.Label.Color,
				Type:  int(l.Label.Type),
			}); err != nil {
				return err
			}
			res.LabelsUpserted++
		}
	}

	return nil
}
