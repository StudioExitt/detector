package detect

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type sysSampler struct{}

var (
	reTopCPU  = regexp.MustCompile(`CPU usage: ([\d.]+)% user, ([\d.]+)% sys, ([\d.]+)% idle`)
	reTopLoad = regexp.MustCompile(`Load Avg: ([\d.]+), ([\d.]+), ([\d.]+)`)
	reVMPage  = regexp.MustCompile(`page size of (\d+) bytes`)
	reVMLine  = regexp.MustCompile(`^"?([^:"]+)"?:\s+(\d+)\.`)
	reSwap    = regexp.MustCompile(`total = ([\d.]+)M\s+used = ([\d.]+)M`)
)

// SIP-protected locations: only Apple-signed code lives here.
func isSystemExe(p string) bool {
	for _, pre := range []string{"/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func sampleSystem(ctx context.Context, _ *sysSampler) (SystemSnapshot, []ProcStat, error) {
	snap := SystemSnapshot{At: time.Now()}

	// two samples 1s apart: the first `top` sample is an average since boot
	top, err := runCmd(ctx, 15*time.Second, "top", "-l", "2", "-n", "0", "-s", "1")
	if err != nil {
		return snap, nil, err
	}
	if m := reTopCPU.FindAllStringSubmatch(top, -1); len(m) > 0 {
		last := m[len(m)-1]
		snap.CPU.UserPct, _ = strconv.ParseFloat(last[1], 64)
		snap.CPU.SystemPct, _ = strconv.ParseFloat(last[2], 64)
		idle, _ := strconv.ParseFloat(last[3], 64)
		snap.CPU.UsagePct = 100 - idle
	}
	if m := reTopLoad.FindAllStringSubmatch(top, -1); len(m) > 0 {
		last := m[len(m)-1]
		snap.CPU.Load1, _ = strconv.ParseFloat(last[1], 64)
		snap.CPU.Load5, _ = strconv.ParseFloat(last[2], 64)
		snap.CPU.Load15, _ = strconv.ParseFloat(last[3], 64)
	}

	sc, err := runCmd(ctx, 5*time.Second, "sysctl", "-n", "hw.memsize", "hw.ncpu", "kern.memorystatus_vm_pressure_level", "vm.swapusage")
	if err != nil {
		return snap, nil, err
	}
	lines := strings.Split(strings.TrimSpace(sc), "\n")
	if len(lines) >= 4 {
		snap.Memory.Total, _ = strconv.ParseUint(strings.TrimSpace(lines[0]), 10, 64)
		snap.CPU.Cores, _ = strconv.Atoi(strings.TrimSpace(lines[1]))
		switch strings.TrimSpace(lines[2]) {
		case "2":
			snap.Memory.Pressure = "warn"
		case "4":
			snap.Memory.Pressure = "critical"
		default:
			snap.Memory.Pressure = "normal"
		}
		if m := reSwap.FindStringSubmatch(lines[3]); m != nil {
			t, _ := strconv.ParseFloat(m[1], 64)
			u, _ := strconv.ParseFloat(m[2], 64)
			snap.Memory.SwapTotal, snap.Memory.SwapUsed = uint64(t*1024*1024), uint64(u*1024*1024)
		}
	}

	// "Memory Used" like Activity Monitor: active (app) + wired + compressed
	vm, err := runCmd(ctx, 5*time.Second, "vm_stat")
	if err == nil {
		page := uint64(16384)
		if m := reVMPage.FindStringSubmatch(vm); m != nil {
			page, _ = strconv.ParseUint(m[1], 10, 64)
		}
		pages := map[string]uint64{}
		for line := range strings.Lines(vm) {
			if m := reVMLine.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				pages[m[1]], _ = strconv.ParseUint(m[2], 10, 64)
			}
		}
		used := (pages["Pages active"] + pages["Pages wired down"] + pages["Pages occupied by compressor"]) * page
		snap.Memory.Used = min(used, snap.Memory.Total)
		if snap.Memory.Total > 0 {
			snap.Memory.UsedPct = float64(snap.Memory.Used) / float64(snap.Memory.Total) * 100
		}
	}

	snap.Disks = darwinDisks()

	procs, err := darwinProcUsage(ctx)
	if err != nil {
		return snap, nil, err
	}
	topProcs(&snap, procs, 8)
	return snap, procs, nil
}

// darwinDisks reports the APFS data volume (the user-visible "Macintosh HD")
// and mounted local volumes under /Volumes. Usage is total minus available,
// so space used by sibling APFS volumes in the container is included.
func darwinDisks() []DiskStat {
	var out []DiskStat
	seen := map[[2]uint64]bool{}
	mounts := append([]string{"/System/Volumes/Data"}, globOrNil("/Volumes/*")...)
	for _, m := range mounts {
		var st syscall.Statfs_t
		if syscall.Statfs(m, &st) != nil || st.Blocks == 0 {
			continue
		}
		fstype := int8sToString(st.Fstypename[:])
		if fstype != "apfs" && fstype != "hfs" && fstype != "exfat" && fstype != "msdos" && fstype != "ntfs" {
			continue
		}
		total := st.Blocks * uint64(st.Bsize)
		free := st.Bavail * uint64(st.Bsize)
		// volumes of one APFS container (Data, Recovery, ...) share size and free space
		key := [2]uint64{total, free}
		if seen[key] || st.Flags&0x1 != 0 { // MNT_RDONLY
			continue
		}
		seen[key] = true
		label := m
		if m == "/System/Volumes/Data" {
			label = "/"
		}
		out = append(out, DiskStat{Mount: label, Total: total, Free: free, Used: total - free, UsedPct: float64(total-free) / float64(total) * 100})
	}
	return out
}

func int8sToString(b []int8) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

func globOrNil(p string) []string {
	m, _ := filepath.Glob(p)
	return m
}

// darwinProcUsage: ps %cpu is a decaying average (~1 minute) per process, 100 = one core.
func darwinProcUsage(ctx context.Context) ([]ProcStat, error) {
	out, err := runCmd(ctx, 15*time.Second, "ps", "-axww", "-o", "pid=,pcpu=,rss=,user=,comm=")
	if err != nil {
		return nil, err
	}
	var procs []ProcStat
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		cpu, _ := strconv.ParseFloat(f[1], 64)
		rssKB, _ := strconv.ParseUint(f[2], 10, 64)
		// comm (may contain spaces) is everything after the 4th field
		rest := strings.TrimSpace(line)
		for i := 0; i < 4; i++ {
			rest = strings.TrimSpace(rest[len(strings.Fields(rest)[0]):])
		}
		exe := rest
		if !strings.HasPrefix(exe, "/") {
			exe = exeCache.resolve(ctx, pid, exe)
		}
		procs = append(procs, ProcStat{PID: pid, Name: filepath.Base(exe), Exe: exe, User: f[3], CPUPct: cpu, RSS: rssKB * 1024})
	}
	if len(procs) == 0 {
		return nil, fmt.Errorf("ps returned no processes")
	}
	return procs, nil
}
