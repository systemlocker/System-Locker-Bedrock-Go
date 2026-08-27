//go:build windows

package slhwid

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"syscall"
	"time"
)

const commandOutputLimit = 1024 * 1024

// runCmd bounds provider output and kills the whole Windows process tree on a
// deadline. PowerShell/CIM can leave children behind if only its direct host
// process is terminated.
func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	var stdout bytes.Buffer
	cmd.Stdout = &limitedWriter{buffer: &stdout, limit: commandOutputLimit}
	cmd.Stderr = &limitedWriter{limit: commandOutputLimit}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("%s failed: %w", name, err)
	}
	err := cmd.Wait()
	if ctx.Err() == context.DeadlineExceeded {
		_ = exec.Command("taskkill.exe", "/PID", fmt.Sprint(cmd.Process.Pid), "/T", "/F").Run()
		return "", fmt.Errorf("%s timed out", name)
	}
	if err != nil {
		return "", fmt.Errorf("%s failed: %w", name, err)
	}
	return stdout.String(), nil
}

type limitedWriter struct {
	buffer *bytes.Buffer
	limit  int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.buffer != nil && w.buffer.Len()+len(p) <= w.limit {
		_, _ = w.buffer.Write(p)
		return len(p), nil
	}
	return 0, fmt.Errorf("command output exceeds limit")
}

func firstMatch(pattern, s string) string {
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
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
