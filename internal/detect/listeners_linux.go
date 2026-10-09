package detect

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// listListeners parses /proc/net/tcp{,6} (state 0A = LISTEN) and maps socket
// inodes to processes via /proc/<pid>/fd. Without root only the detector's
// own user's processes can be mapped; others are reported without a name.
func listListeners(context.Context) ([]listener, error) {
	inodes := map[string]listener{}
	for _, f := range []struct{ path, proto string }{{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"}} {
		if err := readProcNetTCP(f.path, inodes); err != nil && f.proto == "tcp" {
			return nil, err
		}
	}
	owners := socketOwners(inodes)

	var ls []listener
	seen := map[string]bool{}
	for inode, l := range inodes {
		if pid, ok := owners[inode]; ok {
			l.PID = pid
			l.Exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
				l.Process = strings.TrimSpace(string(comm))
			} else if l.Exe != "" {
				l.Process = filepath.Base(l.Exe)
			}
		}
		if k := l.key(); !seen[k] {
			seen[k] = true
			ls = append(ls, l)
		}
	}
	return ls, nil
}

func readProcNetTCP(path string, out map[string]listener) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 || fs[3] != "0A" {
			continue
		}
		addr, port, ok := decodeProcAddr(fs[1])
		if !ok {
			continue
		}
		out[fs[9]] = listener{Proto: "tcp", Addr: addr, Port: port}
	}
	return sc.Err()
}

func socketOwners(inodes map[string]listener) map[string]int {
	owners := map[string]int{}
	pids, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range pids {
		pid, err := strconv.Atoi(filepath.Base(p))
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(p + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(p + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if _, ok := inodes[ino]; ok {
				owners[ino] = pid
			}
		}
	}
	return owners
}
