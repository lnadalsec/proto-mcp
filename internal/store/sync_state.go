package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// execer is the subset of *sql.DB / *sql.Tx the write helpers need, so
// the same SQL runs standalone (Store methods) or inside a cursor
// transaction (Tx methods).
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// ErrCursorConflict is returned by AdvanceSyncCursor when the stored
// cursor is no longer the one the caller started from: another sync —
// typically a different process (CLI `sync` vs the daemon) — moved it in
// the meantime. Nothing was written; the caller should stop and let the
// next run resume from the stored cursor.
var ErrCursorConflict = errors.New("store: sync cursor moved concurrently")

// Tx is a mirror write transaction opened by AdvanceSyncCursor. It
// exposes the mutations the event-sync loop applies, all committed
// atomically with the cursor move.
type Tx struct {
	tx *sql.Tx
}

// UpsertMessage is Store.UpsertMessage inside the transaction.
func (t *Tx) UpsertMessage(ctx context.Context, m Message) error {
	return upsertMessage(ctx, t.tx, m)
}

// SetMessageLabels is Store.SetMessageLabels inside the transaction.
func (t *Tx) SetMessageLabels(ctx context.Context, messageID string, labelIDs []string) error {
	return setMessageLabels(ctx, t.tx, messageID, labelIDs)
}

// DeleteMessage is Store.DeleteMessage inside the transaction.
func (t *Tx) DeleteMessage(ctx context.Context, messageID string) error {
	return deleteMessage(ctx, t.tx, messageID)
}

// InvalidateBodyCache is Store.InvalidateBodyCache inside the transaction.
func (t *Tx) InvalidateBodyCache(ctx context.Context, messageID string) error {
	return invalidateBodyCache(ctx, t.tx, messageID)
}

// UpsertLabel is Store.UpsertLabel inside the transaction.
func (t *Tx) UpsertLabel(ctx context.Context, l Label) error {
	return upsertLabel(ctx, t.tx, l)
}

// DeleteLabel is Store.DeleteLabel inside the transaction.
func (t *Tx) DeleteLabel(ctx context.Context, labelID string) error {
	return deleteLabel(ctx, t.tx, labelID)
}

// SeedSyncState stores value under key only if the key is absent, and
// returns whatever value the key holds afterwards. Two syncs seeding
// the cursor at the same time therefore agree on one value instead of
// the later one overwriting a cursor the earlier one already advanced.
func (s *Store) SeedSyncState(ctx context.Context, key, value string) (string, error) {
	if _, err := s.DB.ExecContext(ctx, `
INSERT INTO sync_state(key, value, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO NOTHING
`, key, value, time.Now().Unix()); err != nil {
		return "", fmt.Errorf("seed sync_state %s: %w", key, err)
	}
	return s.GetSyncState(ctx, key)
}

// AdvanceSyncCursor moves the cursor stored under key from `from` to
// `to` and runs apply in the same transaction. The move is a
// compare-and-set: if the stored value isn't `from` any more, nothing
// is applied and ErrCursorConflict is returned. Because the cursor
// UPDATE is the transaction's first statement it takes SQLite's write
// lock up front, so a concurrent sync in another process waits
// (busy_timeout) and then sees the new cursor — a slower run can
// neither rewind the cursor nor replay an event the faster run already
// applied (e.g. resurrect a message after its delete).
func (s *Store) AdvanceSyncCursor(ctx context.Context, key, from, to string, apply func(*Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cursor tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE sync_state SET value = ?, updated_at = ? WHERE key = ? AND value = ?`,
		to, time.Now().Unix(), key, from)
	if err != nil {
		return fmt.Errorf("advance sync_state %s: %w", key, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("advance sync_state %s rows-affected: %w", key, err)
	}
	if n != 1 {
		return ErrCursorConflict
	}
	if err := apply(&Tx{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cursor tx: %w", err)
	}
	return nil
}

// RaiseSyncStateInt stores v under key unless the key already holds an
// integer >= v, so a numeric high-water mark only ever moves forward
// even when two syncs race. Used for the per-calendar max LastEditTime.
func (s *Store) RaiseSyncStateInt(ctx context.Context, key string, v int64) error {
	if _, err := s.DB.ExecContext(ctx, `
INSERT INTO sync_state(key, value, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
 WHERE CAST(sync_state.value AS INTEGER) < CAST(excluded.value AS INTEGER)
`, key, strconv.FormatInt(v, 10), time.Now().Unix()); err != nil {
		return fmt.Errorf("raise sync_state %s: %w", key, err)
	}
	return nil
}
