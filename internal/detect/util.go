package detect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

var errUnsupported = errors.New("not supported on this platform")

// runCmd runs a command and returns stdout. A non-zero exit is returned as
// *exec.ExitError together with whatever stdout was produced.
func runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return stdout.String(), fmt.Errorf("%s: %w: %s", name, err, firstLine(msg))
		}
		return stdout.String(), fmt.Errorf("%s: %w", name, err)
	}
	return stdout.String(), nil
}

// exitCode returns the exit code of err from runCmd, or -1 if it was not an exit error.
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err == nil {
		return 0
	}
	return -1
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// suspiciousExecDirs are world-writable / temporary locations where legitimate
// software rarely runs from but droppers and miners often do.
func inSuspiciousDir(path string) bool {
	if path == "" {
		return false
	}
	for _, d := range suspiciousDirs {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinLimit(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s 외 %d건", strings.Join(items[:n], ", "), len(items)-n)
}

// runCmdCombined runs a command and returns stdout+stderr (for tools such as
// codesign -dv that report on stderr).
func runCmdCombined(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
