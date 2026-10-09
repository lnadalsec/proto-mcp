package approval

import "testing"

// cacheKey must be injective: bytes may not slide between the tool
// name, the PID and the args. Without length prefixes,
// sha256(tool‖pid‖args) let a different (tool, pid, args) triple hit
// an approval cached for another one.
func TestCacheKeyFieldBoundaries(t *testing.T) {
	// pid=0 encodes as 8 zero bytes. Moving those bytes plus one
	// arg byte across the tool/pid/args boundaries produced the same
	// concatenation under the unprefixed scheme:
	//   "send" ‖ 00×8 ‖ "\x00{}"     vs   "send\x00" ‖ 00×8 ‖ "{}"
	a := cacheKey("send", 0, []byte("\x00{}"))
	b := cacheKey("send\x00", 0, []byte("{}"))
	if a == b {
		t.Fatal("cacheKey collides when a byte moves from args to tool")
	}

	c := cacheKey("send_message", 7, []byte(`{"to":"a"}`))
	d := cacheKey("send_message", 7, []byte(`{"to":"a"}`))
	if c != d {
		t.Fatal("cacheKey is not deterministic")
	}
	if cacheKey("send_message", 7, nil) == cacheKey("send_message", 8, nil) {
		t.Error("different PIDs must give different keys")
	}
}
