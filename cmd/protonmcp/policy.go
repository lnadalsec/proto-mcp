package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// runPolicy is the `protonmcp policy {reload|show|validate}`
// subcommand entry point.
func runPolicy(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: protonmcp policy {reload|show|validate <path>}")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "reload":
		return runPolicyReload(ctx, rest)
	case "show":
		return runPolicyShow(ctx, rest)
	case "validate":
		return runPolicyValidate(ctx, rest)
	default:
		return fmt.Errorf("unknown policy subcommand: %s", sub)
	}
}

// runPolicyReload finds every live `protonmcp serve-stdio` process
// via pgrep and sends each one SIGHUP. The daemon's HUP handler calls
// policy.Engine.Reload(). Multiple processes (Claude Desktop + Claude
// Code running concurrently) all reload their independently-loaded
// policy snapshots.
//
// SECURITY D9: the previous PID-file-based approach was
// unauthenticated — any local process could write a PID file with
// its own PID and steal the SIGHUP. pgrep filters by process
// command line, so the signal goes to actual serve-stdio instances.
func runPolicyReload(_ context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("policy reload takes no arguments; got %v", args)
	}
	pids, err := policy.FindRunningPIDs()
	if err != nil {
		if errors.Is(err, policy.ErrNotRunning) {
			return errors.New("no protonmcp serve-stdio appears to be running")
		}
		return err
	}
	for _, pid := range pids {
		p, err := os.FindProcess(pid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: find pid %d: %v\n", pid, err)
			continue
		}
		if err := p.Signal(syscall.SIGHUP); err != nil {
			fmt.Fprintf(os.Stderr, "warning: signal pid %d: %v\n", pid, err)
			continue
		}
		fmt.Printf("sent SIGHUP to protonmcp serve-stdio pid %d\n", pid)
	}
	fmt.Printf("reload signal sent to %d instance(s) — check each daemon's logs for the outcome\n", len(pids))
	return nil
}

// runPolicyShow prints the merged policy (default + user override).
// Entries that LOOSEN the defaults are flagged in a header: the daemon
// only applies them after a Touch ID approval at load (policy.NewGated)
// and keeps the defaults if that approval is refused, so they can't be
// presented as unconditionally in force.
func runPolicyShow(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("policy show takes no arguments; got %v", args)
	}
	overridePath, err := policy.DefaultOverridePath()
	if err != nil {
		return err
	}
	return writePolicyShow(ctx, os.Stdout, overridePath)
}

// writePolicyShow renders `policy show` for overridePath to w. The
// header is YAML comments so the output stays valid YAML.
func writePolicyShow(ctx context.Context, w io.Writer, overridePath string) error {
	// Display-only, ungated: shows the policy as it is once approved.
	e, err := policy.New(ctx, overridePath, nil)
	if err != nil {
		return err
	}
	out, err := e.SnapshotYAML()
	if err != nil {
		return err
	}
	changes, lerr := policy.Loosenings(overridePath)
	switch {
	case lerr != nil:
		_, _ = fmt.Fprintf(w, "# NOTE: the override %s is not applied (%v);\n"+
			"# the embedded defaults below are what the daemon runs.\n", overridePath, lerr)
	case len(changes) > 0:
		_, _ = fmt.Fprintf(w, "# WARNING: the override %s LOOSENS the default policy:\n", overridePath)
		for _, c := range changes {
			_, _ = fmt.Fprintf(w, "#   - %s\n", c)
		}
		_, _ = fmt.Fprint(w, "# The daemon applies these only after a Touch ID approval when it loads\n"+
			"# (or reloads) the policy. If that approval was refused, the daemon runs\n"+
			"# the embedded defaults for the WHOLE override, not the policy below.\n")
	}
	_, err = w.Write(out)
	return err
}

// runPolicyValidate parses a candidate YAML file the same way the
// engine would. Useful for "does my override file have a typo"
// before running `policy reload` against a daemon.
func runPolicyValidate(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: protonmcp policy validate <path>")
	}
	// Construct a candidate engine pointing at the user-supplied
	// path; Reload reads + parses without committing on error.
	e, err := policy.New(ctx, args[0], nil)
	if err != nil {
		return err
	}
	if err := e.Reload(); err != nil {
		return fmt.Errorf("policy %s is invalid: %w", args[0], err)
	}
	fmt.Printf("policy %s parses cleanly\n", args[0])
	return nil
}
