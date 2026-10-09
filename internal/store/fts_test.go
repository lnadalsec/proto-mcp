package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

// Search with bare terms must order by FTS5 relevance, not by date. m-old
// mentions the term in its subject and repeatedly in its body; m-new only
// once in a long body. Date-only ordering (the pre-0008 behavior, where
// rank was read outside the MATCH and was always NULL) puts m-new first.
func TestSearchOrdersByRelevance(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()

	if err := s.UpsertMessage(ctx, Message{ID: "m-old", ThreadID: "m-old",
		Subject: "kayak trip", Date: time.Unix(1_000, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCachedBody(ctx, "m-old", CachedBody{
		Text: "kayak kayak kayak paddles", CachedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertMessage(ctx, Message{ID: "m-new", ThreadID: "m-new",
		Subject: "weekly newsletter", Date: time.Unix(2_000, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCachedBody(ctx, "m-new", CachedBody{
		Text: strings.Repeat("filler words about nothing ", 50) + "kayak", CachedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	if ids := searchIDs(t, s, "kayak"); len(ids) != 2 || ids[0] != "m-old" {
		t.Errorf("kayak → %v, want m-old ranked first", ids)
	}
	// Without bare terms the order stays date descending.
	if ids := searchIDs(t, s, "after:1970-01-01"); len(ids) != 2 || ids[0] != "m-new" {
		t.Errorf("date-only query → %v, want m-new first", ids)
	}
}

// from: matches the display name as well as the address.
func TestSearchFromMatchesDisplayName(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	if err := s.UpsertMessage(ctx, Message{ID: "m1", ThreadID: "m1",
		FromAddress: "a.smith@example.com", FromName: "Alice Smith", Date: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertMessage(ctx, Message{ID: "m2", ThreadID: "m2",
		FromAddress: "bob@example.com", FromName: "Bob", Date: time.Unix(2, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if ids := searchIDs(t, s, "from:alice"); len(ids) != 1 || ids[0] != "m1" {
		t.Errorf("from:alice → %v, want [m1] (display-name match)", ids)
	}
	if ids := searchIDs(t, s, "from:bob@example"); len(ids) != 1 || ids[0] != "m2" {
		t.Errorf("from:bob@example → %v, want [m2]", ids)
	}
}

// LIKE metacharacters in a DSL value match literally.
func TestSearchLikeEscapesWildcards(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	for i, subj := range []string{"100% done", "1000 things", "a_b", "axb", `back\slash`, "backslash"} {
		id := fmt.Sprintf("m%d", i)
		if err := s.UpsertMessage(ctx, Message{ID: id, ThreadID: id, Subject: subj,
			Date: time.Unix(int64(i), 0).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		query string
		want  string
	}{
		{"subject:100%", "m0"},
		{"subject:a_b", "m2"},
		{`subject:back\slash`, "m4"},
	} {
		if ids := searchIDs(t, s, tc.query); len(ids) != 1 || ids[0] != tc.want {
			t.Errorf("%s → %v, want [%s]", tc.query, ids, tc.want)
		}
	}
	if ids := searchIDs(t, s, "subject:%"); len(ids) != 1 {
		t.Errorf("subject:%% → %v, want only the subject containing %%", ids)
	}
}

// The FTS triggers fire on every insert/update/delete of a message; each
// statement they run must reach messages_fts by rowid (or by an index),
// never by scanning it. Before 0008 they did `DELETE FROM messages_fts
// WHERE message_id = OLD.id` on an UNINDEXED column — a full scan per
// row, O(N²) over a backfill. The trigger bodies are read back from the
// schema and each statement is checked with EXPLAIN QUERY PLAN.
func TestFTSTriggersDoNotScan(t *testing.T) {
	s := mustOpen(t)
	assertFTSTriggersIndexed(t, s.DB)
}

func assertFTSTriggersIndexed(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'messages' AND name LIKE 'messages_fts_%'`)
	if err != nil {
		t.Fatal(err)
	}
	type trig struct{ name, sql string }
	var trigs []trig
	for rows.Next() {
		var tr trig
		if err := rows.Scan(&tr.name, &tr.sql); err != nil {
			t.Fatal(err)
		}
		trigs = append(trigs, tr)
	}
	_ = rows.Close()
	if len(trigs) != 3 {
		t.Fatalf("found %d FTS triggers, want 3", len(trigs))
	}

	oldNew := regexp.MustCompile(`\b(?:OLD|NEW)\.\w+`)
	for _, tr := range trigs {
		body := tr.sql[strings.Index(tr.sql, "BEGIN")+len("BEGIN") : strings.LastIndex(tr.sql, "END")]
		for _, stmt := range strings.Split(body, ";") {
			stmt = strings.TrimSpace(oldNew.ReplaceAllString(stmt, "'x'"))
			if stmt == "" {
				continue
			}
			plan, err := db.Query("EXPLAIN QUERY PLAN " + stmt)
			if err != nil {
				t.Fatalf("%s: explain %q: %v", tr.name, stmt, err)
			}
			for plan.Next() {
				var id, parent, unused int
				var detail string
				if err := plan.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				// "VIRTUAL TABLE INDEX 0:" with an empty idxStr is an
				// FTS5 full scan; "0:=" is a rowid lookup. A plain
				// "SCAN <table>" is a full scan of a regular table.
				if strings.HasSuffix(detail, "VIRTUAL TABLE INDEX 0:") ||
					(strings.HasPrefix(detail, "SCAN ") && !strings.Contains(detail, "VIRTUAL TABLE")) {
					t.Errorf("%s: %q scans: %s", tr.name, stmt, detail)
				}
			}
			_ = plan.Close()
		}
	}
}

// A flag-only update (read/unread) must not touch the FTS index, and an
// update of an indexed column must replace the old tokens.
func TestFTSUpdateTrigger(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	if err := s.UpsertMessage(ctx, Message{ID: "m1", ThreadID: "m1", Subject: "alpha", Date: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE messages SET unread = 1 WHERE id = 'm1'`); err != nil {
		t.Fatal(err)
	}
	if ids := searchIDs(t, s, "alpha"); len(ids) != 1 {
		t.Fatalf("alpha → %v after flag update", ids)
	}
	if err := s.UpsertMessage(ctx, Message{ID: "m1", ThreadID: "m1", Subject: "beta", Date: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if ids := searchIDs(t, s, "alpha"); len(ids) != 0 {
		t.Errorf("old subject still indexed: %v", ids)
	}
	if ids := searchIDs(t, s, "beta"); len(ids) != 1 {
		t.Errorf("new subject not indexed: %v", ids)
	}
	if err := s.DeleteMessage(ctx, "m1"); err != nil {
		t.Fatal(err)
	}
	var nFTS, nMap int
	if err := s.DB.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM messages_fts), (SELECT COUNT(*) FROM messages_fts_map)`).Scan(&nFTS, &nMap); err != nil {
		t.Fatal(err)
	}
	if nFTS != 0 || nMap != 0 {
		t.Errorf("after delete: fts rows %d, map rows %d, want 0/0", nFTS, nMap)
	}
}

// TestMigration0008 migrates a v7 database holding messages to v8: every
// message is re-indexed under the rowid link, secure-delete stays on, and
// a down/up round trip leaves a working index.
func TestMigration0008(t *testing.T) {
	ctx := context.Background()
	dsn, err := buildDSN(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrationFS)
	t.Cleanup(func() { goose.SetBaseFS(nil) })
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatal(err)
	}
	goose.SetLogger(goose.NopLogger())
	if err := goose.UpTo(db, "migrations", 7); err != nil {
		t.Fatalf("up to 7: %v", err)
	}
	for i, body := range []string{"canoe portage", "lunch menu", "portage map"} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, folder, date, body_text)
			 VALUES (?, ?, 's', 'a@example.com', 'A', '[]', 'inbox', ?, ?)`,
			fmt.Sprintf("m%d", i), fmt.Sprintf("m%d", i), i, body,
		); err != nil {
			t.Fatalf("seed v7 row: %v", err)
		}
	}

	if err := goose.UpTo(db, "migrations", 8); err != nil {
		t.Fatalf("up to 8: %v", err)
	}
	// Re-running is a no-op.
	if err := goose.UpTo(db, "migrations", 8); err != nil {
		t.Fatalf("re-run up to 8: %v", err)
	}

	s := &Store{DB: db}
	if ids := searchIDs(t, s, "portage"); len(ids) != 2 {
		t.Errorf("portage after 0008 → %v, want 2 hits", ids)
	}
	var secure string
	if err := db.QueryRowContext(ctx, `SELECT v FROM messages_fts_config WHERE k = 'secure-delete'`).Scan(&secure); err != nil {
		t.Fatalf("secure-delete config: %v", err)
	}
	if secure != "1" {
		t.Errorf("secure-delete = %q, want 1", secure)
	}
	assertFTSTriggersIndexed(t, db)

	// Down to 7 restores the old index, back up re-links it.
	if err := goose.DownTo(db, "migrations", 7); err != nil {
		t.Fatalf("down to 7: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'portage'`).Scan(&n); err != nil || n != 2 {
		t.Errorf("v7 index after down: n=%d err=%v, want 2", n, err)
	}
	if err := goose.UpTo(db, "migrations", 8); err != nil {
		t.Fatalf("up to 8 again: %v", err)
	}
	if ids := searchIDs(t, s, "portage"); len(ids) != 2 {
		t.Errorf("portage after down/up → %v, want 2 hits", ids)
	}
}

// BenchmarkUpsertExisting measures re-upserting an envelope (with a
// changed subject) into a pre-filled mirror. With the pre-0008 triggers
// each upsert full-scanned messages_fts, so per-op time grew with the
// mirror (~2.4 ms at 10k rows); with the rowid link it stays flat (~0.2 ms).
func BenchmarkUpsertExisting(b *testing.B) {
	for _, size := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("mirror=%d", size), func(b *testing.B) {
			s, err := Open(filepath.Join(b.TempDir(), "bench.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			ctx := context.Background()
			tx, err := s.DB.BeginTx(ctx, nil)
			if err != nil {
				b.Fatal(err)
			}
			for i := 0; i < size; i++ {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO messages (id, thread_id, subject, date) VALUES (?, ?, ?, ?)`,
					fmt.Sprintf("m%d", i), "t", fmt.Sprintf("subject %d", i), i); err != nil {
					b.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				id := fmt.Sprintf("m%d", i%size)
				if err := s.UpsertMessage(ctx, Message{ID: id, ThreadID: "t",
					Subject: fmt.Sprintf("changed %d", i), Date: time.Unix(int64(i), 0)}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
