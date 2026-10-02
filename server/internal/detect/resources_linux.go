package detect

import (
	"bufio"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// sysSampler keeps the previous /proc counters to compute CPU deltas.
type sysSampler struct {
	at       time.Time
	cpuTotal uint64
	cpuIdle  uint64
	cpuUser  uint64
	cpuSys   uint64
	procCPU  map[int]uint64 // pid -> utime+stime (ticks)
	users    map[string]string
}

const clockTicks = 100 // USER_HZ on all mainstream Linux architectures

func isSystemExe(string) bool { return false }

func sampleSystem(_ context.Context, s *sysSampler) (SystemSnapshot, []ProcStat, error) {
	now := time.Now()
	snap := SystemSnapshot{At: now}
	snap.CPU.Cores = runtime.NumCPU()

	// CPU from /proc/stat deltas
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		line, _, _ := strings.Cut(string(b), "\n")
		f := strings.Fields(line)
		var vals []uint64
		for _, x := range f[1:] {
			v, _ := strconv.ParseUint(x, 10, 64)
			vals = append(vals, v)
		}
		if len(vals) >= 5 {
			var total uint64
			for _, v := range vals[:min(8, len(vals))] {
				total += v
			}
			idle := vals[3] + vals[4] // idle + iowait
			user := vals[0] + vals[1]
			sys := vals[2]
			if s.cpuTotal > 0 && total > s.cpuTotal {
				dt := float64(total - s.cpuTotal)
				snap.CPU.UsagePct = 100 - float64(idle-s.cpuIdle)/dt*100
				snap.CPU.UserPct = float64(user-s.cpuUser) / dt * 100
				snap.CPU.SystemPct = float64(sys-s.cpuSys) / dt * 100
			}
			s.cpuTotal, s.cpuIdle, s.cpuUser, s.cpuSys = total, idle, user, sys
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			snap.CPU.Load1, _ = strconv.ParseFloat(f[0], 64)
			snap.CPU.Load5, _ = strconv.ParseFloat(f[1], 64)
			snap.CPU.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}

	// memory
	mi := map[string]uint64{}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
			n, _ := strconv.ParseUint(strings.Fields(v)[0], 10, 64)
			mi[k] = n * 1024
		}
		f.Close()
	}
	snap.Memory.Total = mi["MemTotal"]
	if snap.Memory.Total > 0 {
		snap.Memory.Used = snap.Memory.Total - min(mi["MemAvailable"], snap.Memory.Total)
		snap.Memory.UsedPct = float64(snap.Memory.Used) / float64(snap.Memory.Total) * 100
	}
	snap.Memory.SwapTotal = mi["SwapTotal"]
	snap.Memory.SwapUsed = mi["SwapTotal"] - min(mi["SwapFree"], mi["SwapTotal"])
	snap.Memory.Pressure = "normal"
	if b, err := os.ReadFile("/proc/pressure/memory"); err == nil {
		// "some avg10=1.23 ..." (PSI): share of time tasks stalled on memory
		for _, f := range strings.Fields(string(b)) {
			if v, ok := strings.CutPrefix(f, "avg10="); ok {
				p, _ := strconv.ParseFloat(v, 64)
				switch {
				case p >= 30:
					snap.Memory.Pressure = "critical"
				case p >= 10:
					snap.Memory.Pressure = "warn"
				}
				break
			}
		}
	}

	snap.Disks = linuxDisks()

	procs := s.procUsage(now)
	s.at = now
	topProcs(&snap, procs, 8)
	return snap, procs, nil
}

func (s *sysSampler) procUsage(now time.Time) []ProcStat {
	if s.procCPU == nil {
		s.procCPU = map[int]uint64{}
		s.users = map[string]string{}
	}
	elapsed := now.Sub(s.at).Seconds()
	pageSize := uint64(os.Getpagesize())
	next := map[int]uint64{}
	var out []ProcStat
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil {
			continue
		}
		b, err := os.ReadFile(d + "/stat")
		if err != nil {
			continue
		}
		// comm may contain spaces: fields after the closing ')'
		i := strings.LastIndexByte(string(b), ')')
		if i < 0 {
			continue
		}
		name := string(b[strings.IndexByte(string(b), '(')+1 : i])
		f := strings.Fields(string(b[i+2:]))
		if len(f) < 22 {
			continue
		}
		ut, _ := strconv.ParseUint(f[11], 10, 64)
		st, _ := strconv.ParseUint(f[12], 10, 64)
		rssPages, _ := strconv.ParseUint(f[21], 10, 64)
		ticks := ut + st
		next[pid] = ticks
		p := ProcStat{PID: pid, Name: name, RSS: rssPages * pageSize}
		if prev, ok := s.procCPU[pid]; ok && elapsed > 0 && ticks >= prev {
			p.CPUPct = float64(ticks-prev) / clockTicks / elapsed * 100
		}
		p.Exe, _ = os.Readlink(d + "/exe")
		p.Exe = strings.TrimSuffix(p.Exe, " (deleted)")
		if fi, err := os.Stat(d); err == nil {
			if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
				uid := strconv.Itoa(int(sys.Uid))
				if _, ok := s.users[uid]; !ok {
					s.users[uid] = uid
					if u, err := user.LookupId(uid); err == nil {
						s.users[uid] = u.Username
					}
				}
				p.User = s.users[uid]
			}
		}
		out = append(out, p)
	}
	s.procCPU = next
	return out
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "jfs": true, "reiserfs": true}

func linuxDisks() []DiskStat {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []DiskStat
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 3 || !realFS[fs[2]] || seen[fs[0]] {
			continue
		}
		seen[fs[0]] = true
		var st syscall.Statfs_t
		if syscall.Statfs(fs[1], &st) != nil || st.Blocks == 0 {
			continue
		}
		total := st.Blocks * uint64(st.Bsize)
		free := st.Bavail * uint64(st.Bsize)
		out = append(out, DiskStat{Mount: fs[1], Total: total, Free: free, Used: total - free, UsedPct: float64(total-free) / float64(total) * 100})
	}
	// root first
	for i, d := range out {
		if d.Mount == "/" && i > 0 {
			out[0], out[i] = out[i], out[0]
		}
	}
	return out
}
