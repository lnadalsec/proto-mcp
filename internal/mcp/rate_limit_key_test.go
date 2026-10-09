package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

// callEchoAs runs one initialize + tools/call conversation as peer and
// reports whether the handler actually ran.
func callEchoAs(t *testing.T, srv *Server, peer caller.Caller, ran *int) bool {
	t.Helper()
	before := *ran
	in := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	}, "\n") + "\n")
	var out bytes.Buffer
	if err := srv.Serve(caller.WithCaller(context.Background(), peer), in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	return *ran > before
}

// A new shim / Claude client is a new PID. Keying the bucket on PID
// gave each one a fresh budget; the budget must follow the user (UID).
func TestRateLimitSharedAcrossPIDsOfSameUser(t *testing.T) {
	pol := newTestPolicy(t, `tools:
  echo: { decision: allow, rate_limit: "1/hour" }
`)
	srv := New(nil, WithPolicy(pol))
	ran := 0
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(Context, json.RawMessage) (*ToolResult, error) {
			ran++
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})

	if !callEchoAs(t, srv, caller.Caller{PID: 1001, UID: 501}, &ran) {
		t.Fatal("first call should be within the 1/hour budget")
	}
	if callEchoAs(t, srv, caller.Caller{PID: 2002, UID: 501}, &ran) {
		t.Fatal("a new PID of the same user got a fresh budget — rate limit bypassed by reconnecting")
	}
}

func TestRateLimitKey(t *testing.T) {
	a := rateLimitKey("mail_send", caller.Caller{PID: 1, UID: 501})
	b := rateLimitKey("mail_send", caller.Caller{PID: 2, UID: 501})
	if a != b {
		t.Errorf("same user, different PIDs: %q != %q", a, b)
	}
	if a == rateLimitKey("mail_send", caller.Caller{PID: 1, UID: 502}) {
		t.Error("different users must not share a bucket")
	}
	if a == rateLimitKey("mail_reply", caller.Caller{PID: 1, UID: 501}) {
		t.Error("different tools must not share a bucket")
	}
}

type pruningPersister struct {
	fakePersister
	cutoff time.Time
	pruned bool
}

func (p *pruningPersister) PruneOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	p.pruned = true
	p.cutoff = cutoff
	return 0, nil
}

// Startup prunes fully-refilled buckets on disk and ignores them in
// memory; a recent (drained) bucket is still honored.
func TestSetPersisterPrunesStaleBuckets(t *testing.T) {
	now := time.Unix(10_000_000, 0)
	p := &pruningPersister{fakePersister: fakePersister{preload: map[string]PersistedBucket{
		"mail_send|4242":    {LimitSpec: "3/hour", Tokens: 0, LastRefill: now.Add(-30 * 24 * time.Hour)},
		"mail_send|uid:501": {LimitSpec: "3/hour", Tokens: 0, LastRefill: now},
	}}}
	r := newRateLimiter()
	r.now = func() time.Time { return now }
	if err := r.setPersister(p); err != nil {
		t.Fatal(err)
	}
	if !p.pruned {
		t.Fatal("setPersister did not prune the persisted table")
	}
	if want := now.Add(-staleBucketAge); !p.cutoff.Equal(want) {
		t.Errorf("prune cutoff = %v, want %v", p.cutoff, want)
	}
	if _, ok := r.buckets["mail_send|4242"]; ok {
		t.Error("stale legacy bucket loaded into memory")
	}
	if ok, _ := r.Allow("mail_send|uid:501", "3/hour"); ok {
		t.Error("recent drained bucket was not honored after restart")
	}
}
