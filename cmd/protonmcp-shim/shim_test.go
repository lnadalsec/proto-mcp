package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultSocketPathHasExpectedShape(t *testing.T) {
	p, err := defaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p, "Application Support/protonmcp/protonmcp.sock") {
		t.Errorf("unexpected default socket path: %s", p)
	}
}

// TestEmitDaemonUnavailableError checks the JSON-RPC error frame we
// emit when the daemon isn't reachable. It must be valid NDJSON
// (one line, ends with \n) and include the dial error so the user
// can act on it.
func TestEmitDaemonUnavailableError(t *testing.T) {
	// Redirect os.Stdout to a temp file for inspection. The
	// emitDaemonUnavailableError function writes directly to it.
	tmp, err := os.CreateTemp(t.TempDir(), "stdout*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	orig := os.Stdout
	os.Stdout = tmp
	defer func() { os.Stdout = orig }()

	emitDaemonUnavailableError("/tmp/test.sock", net.ErrClosed)
	tmp.Sync()
	_ = tmp.Close()

	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		t.Error("error frame must end with newline (NDJSON framing)")
	}
	if !strings.Contains(s, `"jsonrpc":"2.0"`) {
		t.Errorf("missing JSON-RPC envelope: %s", s)
	}
	if !strings.Contains(s, "/tmp/test.sock") {
		t.Errorf("missing socket path: %s", s)
	}
	if !strings.Contains(s, `"data":{"dial_error":`) {
		t.Errorf("missing structured dial_error: %s", s)
	}
}

// TestDaemonUnavailableFrameIsValidJSONForHostilePaths: the frame used
// to be built with Sprintf, interpolating the path raw and the dial
// error with Go's %q. A home directory containing `"` or `\`, or a dial
// error with a control byte, produced a frame the client could not
// parse. Every case here must round-trip through encoding/json.
func TestDaemonUnavailableFrameIsValidJSONForHostilePaths(t *testing.T) {
	cases := []struct{ path, dialErr string }{
		{`/Users/a"b/Library/protonmcp.sock`, "connect: no such file"},
		{`/Users/a\b/protonmcp.sock`, "x"},
		{"/Users/tab\there/protonmcp.sock", "ctrl \x00\x07 bytes"},
		{"/Users/émoji😀/protonmcp.sock", "dial: \U0001F600"},
		{"/Users/x/protonmcp.sock", "line1\nline2"},
	}
	for _, tc := range cases {
		frame := daemonUnavailableFrame(tc.path, errors.New(tc.dialErr))
		if n := strings.Count(string(frame), "\n"); n != 1 || frame[len(frame)-1] != '\n' {
			t.Errorf("frame for %q is not a single NDJSON line: %q", tc.path, frame)
		}
		var got struct {
			JSONRPC string           `json:"jsonrpc"`
			ID      *json.RawMessage `json:"id"`
			Error   struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Data    struct {
					DialError string `json:"dial_error"`
				} `json:"data"`
			} `json:"error"`
		}
		if err := json.Unmarshal(frame, &got); err != nil {
			t.Errorf("frame for path %q is not valid JSON: %v\n%s", tc.path, err, frame)
			continue
		}
		if got.JSONRPC != "2.0" || got.ID != nil || got.Error.Code != -32099 {
			t.Errorf("bad envelope: %+v", got)
		}
		if !strings.Contains(got.Error.Message, tc.path) {
			t.Errorf("message lost the path %q: %q", tc.path, got.Error.Message)
		}
		if got.Error.Data.DialError != tc.dialErr {
			t.Errorf("dial_error = %q, want %q", got.Error.Data.DialError, tc.dialErr)
		}
	}
}

// TestShortSocketPathConstraint sanity-checks that the default
// socket path fits within macOS's 104-char sockaddr_un limit. If
// this ever fails for some path-config reason, the shim would also
// fail to connect and we'd want to know first.
func TestShortSocketPathConstraint(t *testing.T) {
	p, err := defaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) > 104 {
		t.Errorf("default socket path %d chars > 104 (sockaddr_un limit): %s", len(p), p)
	}
	// Sanity: the path is rooted under the user's home dir.
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(p, filepath.Clean(home)) {
		t.Errorf("default socket path not under home: %s (home=%s)", p, home)
	}
}
