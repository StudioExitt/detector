package detect

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// listListeners uses `netstat -anv -p tcp`, which (unlike lsof) shows the
// owning PID of every socket without root.
func listListeners(ctx context.Context) ([]listener, error) {
	out, err := runCmd(ctx, 20*time.Second, "netstat", "-anv", "-p", "tcp")
	if err != nil {
		return nil, err
	}
	procs, _ := darwinProcNames(ctx)

	pidCol := -1
	var ls []listener
	seen := map[string]bool{}
	for line := range strings.Lines(out) {
		if strings.HasPrefix(line, "Proto") {
			h := strings.NewReplacer("Local Address", "Local_Address", "Foreign Address", "Foreign_Address").Replace(line)
			for i, f := range strings.Fields(h) {
				if f == "pid" {
					pidCol = i
				}
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 6 || f[5] != "LISTEN" || !strings.HasPrefix(f[0], "tcp") {
			continue
		}
		addr, port, ok := splitDarwinAddr(f[3])
		if !ok {
			continue
		}
		l := listener{Proto: "tcp", Addr: addr, Port: port}
		if f[0] == "tcp6" && addr == "*" {
			l.Addr = "::"
		}
		if pidCol >= 0 && pidCol < len(f) {
			l.PID, _ = strconv.Atoi(f[pidCol])
		} else if p := strings.LastIndexByte(f[len(f)-1], ':'); p >= 0 {
			// older macOS: "process:pid" column
			l.PID, _ = strconv.Atoi(f[len(f)-1][p+1:])
		}
		if exe, ok := procs[l.PID]; ok {
			l.Exe = exe
			l.Process = filepath.Base(exe)
		}
		// tcp46 and tcp4/tcp6 pairs: keep one entry per addr/port/process
		if k := l.key(); !seen[k] {
			seen[k] = true
			ls = append(ls, l)
		}
	}
	return ls, nil
}

// splitDarwinAddr parses "*.9009", "127.0.0.1.631", "::1.5174", "fe80::1%lo0.123".
func splitDarwinAddr(s string) (string, int, bool) {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	return s[:i], port, true
}

// darwinProcNames maps pid -> executable path (or name) using ps.
func darwinProcNames(ctx context.Context) (map[int]string, error) {
	out, err := runCmd(ctx, 20*time.Second, "ps", "-axww", "-o", "pid=,comm=")
	if err != nil {
		return nil, err
	}
	m := map[int]string{}
	for line := range strings.Lines(out) {
		line = strings.TrimSpace(line)
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			continue
		}
		pid, err := strconv.Atoi(line[:sp])
		if err != nil {
			continue
		}
		m[pid] = strings.TrimSpace(line[sp+1:])
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("ps returned no processes")
	}
	return m, nil
}
