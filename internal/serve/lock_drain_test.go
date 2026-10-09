package serve

import (
	"testing"
	"time"

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

// Lock must not zero the session while a tool call still uses it:
// Session.Close deletes from AddrKRs, and a concurrent read of that
// map is a fatal runtime error, not a recoverable panic. Lock waits
// for open call brackets, and refuses new ones.
func TestLock_WaitsForInFlightCalls(t *testing.T) {
	withTempHome(t)
	rt := &Runtime{Session: &protonclient.Session{}}

	release, ok := rt.beginCall()
	if !ok {
		t.Fatal("beginCall refused on an unlocked runtime")
	}

	lockDone := make(chan struct{})
	go func() { rt.Lock("test"); close(lockDone) }()

	select {
	case <-lockDone:
		t.Fatal("Lock returned while a tool call was still in flight")
	case <-time.After(100 * time.Millisecond):
	}
	if locked, _ := rt.Locked(); !locked {
		t.Fatal("runtime should report locked as soon as Lock starts")
	}

	release()
	select {
	case <-lockDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Lock did not complete after the in-flight call ended")
	}

	if _, ok := rt.beginCall(); ok {
		t.Fatal("beginCall admitted a call on a locked runtime")
	}
}
