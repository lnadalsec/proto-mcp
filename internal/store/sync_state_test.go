package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSeedSyncStateKeepsExisting(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	got, err := s.SeedSyncState(ctx, "k", "first")
	if err != nil || got != "first" {
		t.Fatalf("seed empty: %q, %v", got, err)
	}
	got, err = s.SeedSyncState(ctx, "k", "second")
	if err != nil || got != "first" {
		t.Errorf("seed existing: %q, %v; want first kept", got, err)
	}
}

func TestAdvanceSyncCursor(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	if err := s.SetSyncState(ctx, "cur", "c1"); err != nil {
		t.Fatal(err)
	}

	// Wrong `from`: conflict, apply never runs.
	err := s.AdvanceSyncCursor(ctx, "cur", "c0", "c9", func(*Tx) error {
		t.Error("apply ran despite conflict")
		return nil
	})
	if !errors.Is(err, ErrCursorConflict) {
		t.Errorf("stale from: err = %v, want ErrCursorConflict", err)
	}

	// apply fails: cursor and mirror writes roll back together.
	boom := errors.New("boom")
	err = s.AdvanceSyncCursor(ctx, "cur", "c1", "c2", func(tx *Tx) error {
		if err := tx.UpsertMessage(ctx, Message{ID: "m1", ThreadID: "m1", Date: time.Unix(1, 0)}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want boom", err)
	}
	if v, _ := s.GetSyncState(ctx, "cur"); v != "c1" {
		t.Errorf("cursor = %q after failed apply, want c1", v)
	}
	if _, err := s.GetMessage(ctx, "m1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("message written by failed apply: %v", err)
	}

	// Success: both land.
	if err := s.AdvanceSyncCursor(ctx, "cur", "c1", "c2", func(tx *Tx) error {
		return tx.UpsertMessage(ctx, Message{ID: "m1", ThreadID: "m1", Date: time.Unix(1, 0)})
	}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GetSyncState(ctx, "cur"); v != "c2" {
		t.Errorf("cursor = %q, want c2", v)
	}
	if _, err := s.GetMessage(ctx, "m1"); err != nil {
		t.Errorf("message not written: %v", err)
	}
}

// Two Store handles on one file stand in for two processes (CLI sync
// and the daemon). Racing to move the cursor from the same value,
// exactly one wins; the others see ErrCursorConflict, never a rewind.
func TestAdvanceSyncCursor_CrossHandleRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.db")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	ctx := context.Background()
	if err := a.SetSyncState(ctx, "cur", "c0"); err != nil {
		t.Fatal(err)
	}

	var (
		wg      sync.WaitGroup
		wins    atomic.Int32
		applied atomic.Int32
	)
	for i := 0; i < 8; i++ {
		st := a
		if i%2 == 1 {
			st = b
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := st.AdvanceSyncCursor(ctx, "cur", "c0", fmt.Sprintf("w%d", i), func(*Tx) error {
				applied.Add(1)
				return nil
			})
			switch {
			case err == nil:
				wins.Add(1)
			case !errors.Is(err, ErrCursorConflict):
				t.Errorf("worker %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 || applied.Load() != 1 {
		t.Errorf("wins = %d, applied = %d, want 1/1", wins.Load(), applied.Load())
	}
}

func TestRaiseSyncStateInt(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	for _, v := range []int64{100, 300, 200} {
		if err := s.RaiseSyncStateInt(ctx, "hw", v); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := s.GetSyncState(ctx, "hw"); v != "300" {
		t.Errorf("high-water = %q, want 300", v)
	}
}

// An envelope older than the mirrored row (a stale concurrent sync)
// must not roll it back.
func TestUpsertCalendarEventEnvelopeIgnoresOlder(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	if err := s.UpsertCalendar(ctx, Calendar{ID: "cal", Name: "c", Active: true}); err != nil {
		t.Fatal(err)
	}
	newer := CalendarEventEnvelope{ID: "e1", CalendarID: "cal", UID: "u", StartUnix: 2000, EndUnix: 2100, LastEdit: 20}
	older := newer
	older.StartUnix, older.EndUnix, older.LastEdit = 1000, 1100, 10
	if err := s.UpsertCalendarEventEnvelope(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertCalendarEventEnvelope(ctx, older); err != nil {
		t.Fatal(err)
	}
	have, err := s.CalendarEventEditTimes(ctx, "cal")
	if err != nil {
		t.Fatal(err)
	}
	if have["e1"] != 20 {
		t.Errorf("last_edit = %d, want 20 (older envelope ignored)", have["e1"])
	}
}
