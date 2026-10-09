package sync

import (
	"context"
	"errors"
	"net/mail"
	"path/filepath"
	gosync "sync"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// scriptedSource serves one event per cursor from a fixed script:
// c0 → c1 creates m1, c1 → c2 deletes it. hook, if set, runs at the
// start of every GetEvent and may block or fail it.
type scriptedSource struct {
	hook func(cursor string) error
}

func scriptedEvent(cursor string) (gpa.Event, bool) {
	switch cursor {
	case "c0":
		return gpa.Event{EventID: "c1", Messages: []gpa.MessageEvent{{
			EventItem: gpa.EventItem{ID: "m1", Action: gpa.EventCreate},
			Message: gpa.MessageMetadata{ID: "m1", AddressID: "a", LabelIDs: []string{"0"},
				Subject: "hello", Sender: &mail.Address{Address: "a@example.com"}, Time: 1},
		}}}, true
	case "c1":
		return gpa.Event{EventID: "c2", Messages: []gpa.MessageEvent{{
			EventItem: gpa.EventItem{ID: "m1", Action: gpa.EventDelete},
		}}}, true
	}
	return gpa.Event{}, false
}

func (s scriptedSource) LatestEventID(context.Context) (string, error) { return "c0", nil }

func (s scriptedSource) GetEvent(_ context.Context, cursor string) ([]gpa.Event, bool, error) {
	if s.hook != nil {
		if err := s.hook(cursor); err != nil {
			return nil, false, err
		}
	}
	e, ok := scriptedEvent(cursor)
	if !ok {
		return nil, false, nil
	}
	_, more := scriptedEvent(e.EventID)
	return []gpa.Event{e}, more, nil
}

// openFileStore opens a file-backed store: concurrent goroutines need a
// shared database, which :memory: (one per connection) doesn't give.
func openFileStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func assertDrained(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	cur, err := st.GetSyncState(ctx, cursorKey)
	if err != nil || cur != "c2" {
		t.Errorf("cursor = %q (%v), want c2", cur, err)
	}
	if _, err := st.GetMessage(ctx, "m1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("m1 should stay deleted, GetMessage err = %v", err)
	}
}

// In-process: RunOnce calls from the ticker, mail_sync and the CLI may
// overlap. They must run one after another — no error, no replay, and
// the cursor ends at the last event.
func TestRunOnce_ConcurrentCallsSerialize(t *testing.T) {
	st := openFileStore(t, filepath.Join(t.TempDir(), "s.db"))
	ctx := context.Background()
	if err := st.SetSyncState(ctx, cursorKey, "c0"); err != nil {
		t.Fatal(err)
	}
	src := scriptedSource{hook: func(string) error {
		time.Sleep(2 * time.Millisecond) // widen the race window
		return nil
	}}

	var wg gosync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := runOnce(ctx, src, st); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent runOnce: %v", err)
	}
	assertDrained(t, st)
}

// Cross-process: a slow run (think CLI `protonmcp sync`) fetched the
// c0 page, then the daemon drained c0 → c2 (create, then delete m1).
// When the slow run resumes it must not apply its stale create nor
// move the cursor back to c1 — it stops with ErrConcurrentSync. The
// two drains use separate Store handles on the same file and bypass
// the in-process lock, as two processes would.
func TestDrain_StaleRunCannotRewindCursor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	daemon := openFileStore(t, path)
	cli := openFileStore(t, path)
	ctx := context.Background()
	if err := daemon.SetSyncState(ctx, cursorKey, "c0"); err != nil {
		t.Fatal(err)
	}

	fetched := make(chan struct{})
	resume := make(chan struct{})
	slow := scriptedSource{hook: func(cursor string) error {
		if cursor == "c0" {
			close(fetched)
			<-resume
			return nil
		}
		// The slow run dies before its next page (timeout, ^C).
		return errors.New("slow run stopped")
	}}

	done := make(chan error, 1)
	go func() {
		_, err := drain(ctx, slow, cli)
		done <- err
	}()
	<-fetched
	if _, err := drain(ctx, scriptedSource{}, daemon); err != nil {
		t.Fatalf("daemon drain: %v", err)
	}
	close(resume)
	if err := <-done; !errors.Is(err, ErrConcurrentSync) {
		t.Errorf("slow drain err = %v, want ErrConcurrentSync", err)
	}
	assertDrained(t, daemon)
}

// A context cancelled while waiting for another RunOnce returns the
// context error rather than blocking.
func TestRunOnce_WaitHonorsContext(t *testing.T) {
	mailSyncSem <- struct{}{}
	defer func() { <-mailSyncSem }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := RunOnce(ctx, nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
}

func TestRunCalendarOnce_Serialized(t *testing.T) {
	calendarSyncSem <- struct{}{}
	defer func() { <-calendarSyncSem }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := RunCalendarOnce(ctx, nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RunCalendarOnce err = %v, want DeadlineExceeded (waits for the running sync)", err)
	}
	if _, err := RunCalendarBackfill(ctx, nil, nil, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RunCalendarBackfill err = %v, want DeadlineExceeded", err)
	}
}

// A calendar event removed locally by a stale run (it reconciled
// against a listing taken before the event existed) is mirrored again
// on the next pass even though it sits below the high-water mark.
func TestApplyCalendarEvents_RemirrorsMissingEvent(t *testing.T) {
	ctx := context.Background()
	st := mustOpen(t)
	seedCal(t, st, "cal-1")
	events := []gpa.CalendarEvent{calEvent("ev-1", "cal-1", 100), calEvent("ev-2", "cal-1", 200)}
	if _, _, _, err := applyCalendarEvents(ctx, st, "cal-1", events, 0); err != nil {
		t.Fatal(err)
	}
	// Stale run: its listing predates ev-2, so reconcile drops it.
	if _, err := st.ReconcileCalendarEvents(ctx, "cal-1", []string{"ev-1"}); err != nil {
		t.Fatal(err)
	}
	_, up, _, err := applyCalendarEvents(ctx, st, "cal-1", events, 200)
	if err != nil {
		t.Fatal(err)
	}
	if up != 1 {
		t.Errorf("upserted = %d, want 1 (ev-2 re-mirrored)", up)
	}
	if _, err := st.GetCalendarEvent(ctx, "ev-2"); err != nil {
		t.Errorf("ev-2 missing after re-poll: %v", err)
	}
}

// The calendar high-water mark never moves backwards.
func TestSyncCalendarEvents_HighWaterMonotonic(t *testing.T) {
	ctx := context.Background()
	st := mustOpen(t)
	seedCal(t, st, "cal-1")
	if err := st.SetSyncState(ctx, calendarMaxEditPrefix+"cal-1", "500"); err != nil {
		t.Fatal(err)
	}
	// A run that read the mark before it reached 500 (stale storedMax).
	if err := st.RaiseSyncStateInt(ctx, calendarMaxEditPrefix+"cal-1", 300); err != nil {
		t.Fatal(err)
	}
	if got := readMaxEdit(ctx, st, "cal-1"); got != 500 {
		t.Errorf("high-water = %d, want 500", got)
	}
}
