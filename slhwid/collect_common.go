//go:build !windows

// collect_common.go holds the shared subprocess plumbing for the platform
// factor collectors.
package slhwid

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"time"
)

// runCmd runs a command with a hard timeout and returns its stdout. Slow or
// failing commands simply yield an error; every factor degrades gracefully.
func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("%s timed out", name)
	}
	if err != nil {
		return "", fmt.Errorf("%s failed: %w", name, err)
	}
	return string(out), nil
}

// firstMatch returns the first regex capture group in s, or "".
func firstMatch(pattern, s string) string {
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// allMatches returns every first capture group in s.
func allMatches(pattern, s string) []string {
	found := regexp.MustCompile(pattern).FindAllStringSubmatch(s, -1)
	out := make([]string, 0, len(found))
	for _, m := range found {
		if len(m) >= 2 {
			out = append(out, m[1])
		}
	}
	return out
}
