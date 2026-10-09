package detect

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var suspiciousDirs = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/var/run/shm/",
}

// listProcesses reads /proc. Kernel threads (no exe) are skipped; without root
// other users' exe links are unreadable and fall back to cmdline[0].
func listProcesses(context.Context) ([]proc, error) {
	dirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, err
	}
	users := map[uint32]string{}
	var ps []proc
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(d + "/cmdline")
		if err != nil || len(raw) == 0 {
			continue // exited or kernel thread
		}
		args := strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
		p := proc{PID: pid, Args: args}

		if exe, err := os.Readlink(d + "/exe"); err == nil {
			p.Deleted = strings.HasSuffix(exe, " (deleted)")
			p.Exe = strings.TrimSuffix(exe, " (deleted)")
		} else if i := strings.IndexByte(string(raw), 0); i > 0 {
			p.Exe = string(raw[:i])
		}

		if fi, err := os.Stat(d); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				name, ok := users[st.Uid]
				if !ok {
					name = strconv.Itoa(int(st.Uid))
					if u, err := user.LookupId(name); err == nil {
						name = u.Username
					}
					users[st.Uid] = name
				}
				p.User = name
			}
		}
		ps = append(ps, p)
	}
	if len(ps) == 0 {
		return nil, fmt.Errorf("no processes readable from /proc")
	}
	return ps, nil
}
