package detect

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

var suspiciousDirs = []string{
	"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/",
}

// listProcesses joins `ps -o pid,user,comm` (exe path, may contain spaces) with
// `ps -o pid,args` (full command line).
func listProcesses(ctx context.Context) ([]proc, error) {
	out, err := runCmd(ctx, 20*time.Second, "ps", "-axww", "-o", "pid=,user=,comm=")
	if err != nil {
		return nil, err
	}
	argsOut, err := runCmd(ctx, 20*time.Second, "ps", "-axww", "-o", "pid=,args=")
	if err != nil {
		return nil, err
	}
	args := map[int]string{}
	for line := range strings.Lines(argsOut) {
		f := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(f) != 2 {
			continue
		}
		if pid, err := strconv.Atoi(f[0]); err == nil {
			args[pid] = strings.TrimSpace(f[1])
		}
	}

	var ps []proc
	live := map[int]bool{}
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		// comm is everything after the user column (paths may contain spaces)
		rest := strings.TrimSpace(line)
		rest = strings.TrimSpace(rest[len(f[0]):])
		rest = strings.TrimSpace(rest[len(f[1]):])
		exe := strings.TrimSpace(rest)
		if !strings.HasPrefix(exe, "/") {
			// ps shows argv[0] as typed (e.g. "./xmrig"); resolve the real path
			exe = exeCache.resolve(ctx, pid, exe)
		}
		live[pid] = true
		ps = append(ps, proc{PID: pid, User: f[1], Exe: exe, Args: args[pid]})
	}
	exeCache.retain(live)
	return ps, nil
}

// exeCache remembers lsof lookups per (pid, comm) so each process is resolved once.
var exeCache = &pidExeCache{m: map[int]cachedExe{}}

type cachedExe struct{ comm, exe string }

type pidExeCache struct {
	mu sync.Mutex
	m  map[int]cachedExe
}

func (c *pidExeCache) resolve(ctx context.Context, pid int, comm string) string {
	c.mu.Lock()
	if e, ok := c.m[pid]; ok && e.comm == comm {
		c.mu.Unlock()
		return e.exe
	}
	c.mu.Unlock()
	exe := darwinExePath(ctx, pid)
	if exe == "" {
		exe = comm
	}
	c.mu.Lock()
	c.m[pid] = cachedExe{comm: comm, exe: exe}
	c.mu.Unlock()
	return exe
}

func (c *pidExeCache) retain(live map[int]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for pid := range c.m {
		if !live[pid] {
			delete(c.m, pid)
		}
	}
}

// darwinExePath returns the executable of pid from its first "txt" mapping.
// Only works for processes the detector's user may inspect (all of them as root).
func darwinExePath(ctx context.Context, pid int) string {
	out, err := runCmd(ctx, 5*time.Second, "lsof", "-a", "-p", strconv.Itoa(pid), "-d", "txt", "-Fn")
	if err != nil && out == "" {
		return ""
	}
	for line := range strings.Lines(out) {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "n"); ok && strings.HasPrefix(p, "/") {
			return p
		}
	}
	return ""
}
