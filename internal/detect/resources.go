package detect

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"detector/internal/config"
)

// SystemSnapshot is the latest system state, served by GET /system/status.
type SystemSnapshot struct {
	At     time.Time
	CPU    CPUStat
	Memory MemStat
	Disks  []DiskStat
	TopCPU []ProcStat
	TopMem []ProcStat
}

type CPUStat struct {
	UsagePct, UserPct, SystemPct float64
	Load1, Load5, Load15         float64
	Cores                        int
}

type MemStat struct {
	Total, Used         uint64
	UsedPct             float64
	Pressure            string // normal / warn / critical
	SwapTotal, SwapUsed uint64
}

type DiskStat struct {
	Mount             string
	Total, Used, Free uint64
	UsedPct           float64
}

type ProcStat struct {
	PID       int
	Name      string
	Exe       string
	User      string
	CPUPct    float64 // 100 = one core
	RSS       uint64  // bytes
	HighSince time.Time
}

func (p ProcStat) key() string { return fmt.Sprintf("%d|%s", p.PID, p.Exe) }

// resourcesDetector samples CPU / memory / disk and flags sustained abuse:
// a process pinning CPU (coin miners), the whole machine overloaded, memory
// pressure, a process hogging RAM, disks filling up or growing suddenly.
type resourcesDetector struct {
	cfg     config.ResourcesDetectConfig
	sampler *sysSampler

	procHigh     map[string]time.Time // proc key -> high CPU since
	sysHighSince time.Time
	pressureFrom time.Time
	diskHist     []diskPoint
}

type diskPoint struct {
	At   time.Time
	Used map[string]uint64
}

func newResourcesDetector(cfg config.ResourcesDetectConfig) Detector {
	return &resourcesDetector{cfg: cfg, sampler: &sysSampler{}, procHigh: map[string]time.Time{}}
}

func (d *resourcesDetector) Name() string { return "resources" }

const gib = 1 << 30

func (d *resourcesDetector) Check(ctx context.Context, env *Env) (Report, error) {
	snap, procs, err := sampleSystem(ctx, d.sampler)
	if err != nil {
		return Report{}, err
	}
	now := snap.At
	var findings []Finding

	// --- per-process CPU, sustained ---
	live := map[string]bool{}
	for i := range procs {
		p := &procs[i]
		k := p.key()
		live[k] = true
		if p.CPUPct < d.cfg.ProcCPUPercent || d.ignored(p) {
			delete(d.procHigh, k)
			continue
		}
		since, ok := d.procHigh[k]
		if !ok {
			since = now
			d.procHigh[k] = since
		}
		p.HighSince = since
		dur := now.Sub(since)
		if dur < d.cfg.Sustain {
			continue
		}
		sev, why := SevMedium, "CPU 과점유"
		switch {
		case inSuspiciousDir(p.Exe) || strings.Contains(p.Exe, "/."):
			sev, why = SevHigh, "임시/숨김 경로 프로세스의 CPU 과점유 — 채굴/악성 의심"
		case p.CPUPct >= 200:
			sev, why = SevHigh, "여러 코어를 장시간 점유 — 암호화폐 채굴 의심"
		}
		findings = append(findings, Finding{
			Rule: "res.cpu_hog", Category: CategoryResourceAbuse, Severity: sev, Source: orNone(p.Exe), Key: k,
			Message: fmt.Sprintf("%s: %s (pid %d, user %s) CPU %.0f%% 가 %s 이상 지속 — %s",
				why, p.Name, p.PID, p.User, p.CPUPct, humanDur(dur), orNone(p.Exe)),
		})
	}
	for k := range d.procHigh {
		if !live[k] {
			delete(d.procHigh, k)
		}
	}

	// --- whole machine CPU, sustained ---
	if snap.CPU.UsagePct >= d.cfg.SystemCPUPercent {
		if d.sysHighSince.IsZero() {
			d.sysHighSince = now
		}
		if dur := now.Sub(d.sysHighSince); dur >= d.cfg.Sustain {
			findings = append(findings, Finding{
				Rule: "res.cpu_high", Category: CategoryResourceAbuse, Severity: SevMedium, Source: env.Host,
				Message: fmt.Sprintf("시스템 CPU 사용률 %.0f%% 가 %s 이상 지속 (load %.2f / %d코어) — 상위: %s",
					snap.CPU.UsagePct, humanDur(dur), snap.CPU.Load1, snap.CPU.Cores, topNames(snap.TopCPU, 3)),
			})
		}
	} else {
		d.sysHighSince = time.Time{}
	}

	// --- memory ---
	switch snap.Memory.Pressure {
	case "critical":
		findings = append(findings, Finding{
			Rule: "res.mem_pressure", Category: CategoryResourceAbuse, Severity: SevHigh, Source: env.Host, Key: "critical",
			Message: fmt.Sprintf("메모리 압박 critical — 사용 %.0f%%, 스왑 %s 사용 — 상위: %s",
				snap.Memory.UsedPct, humanBytes(snap.Memory.SwapUsed), topNames(snap.TopMem, 3)),
		})
		d.pressureFrom = time.Time{}
	case "warn":
		if d.pressureFrom.IsZero() {
			d.pressureFrom = now
		}
		if dur := now.Sub(d.pressureFrom); dur >= d.cfg.Sustain {
			findings = append(findings, Finding{
				Rule: "res.mem_pressure", Category: CategoryResourceAbuse, Severity: SevMedium, Source: env.Host, Key: "warn",
				Message: fmt.Sprintf("메모리 압박 경고가 %s 이상 지속 — 사용 %.0f%%, 상위: %s",
					humanDur(dur), snap.Memory.UsedPct, topNames(snap.TopMem, 3)),
			})
		}
	default:
		d.pressureFrom = time.Time{}
	}
	if snap.Memory.Total > 0 {
		for _, p := range procs {
			share := float64(p.RSS) / float64(snap.Memory.Total) * 100
			if share >= d.cfg.ProcMemPercent && !d.ignored(&p) {
				findings = append(findings, Finding{
					Rule: "res.mem_hog", Category: CategoryResourceAbuse, Severity: SevMedium, Source: orNone(p.Exe), Key: p.key(),
					Message: fmt.Sprintf("단일 프로세스가 메모리 %.0f%% (%s) 점유: %s (pid %d, user %s)", share, humanBytes(p.RSS), p.Name, p.PID, p.User),
				})
			}
		}
	}

	// --- disks: fullness and sudden growth ---
	cur := diskPoint{At: now, Used: map[string]uint64{}}
	for _, ds := range snap.Disks {
		cur.Used[ds.Mount] = ds.Used
		switch {
		case ds.UsedPct >= d.cfg.DiskCritPercent:
			findings = append(findings, Finding{
				Rule: "res.disk_full", Category: CategoryResourceAbuse, Severity: SevHigh, Source: ds.Mount, Key: ds.Mount + "|crit",
				Message: fmt.Sprintf("디스크 %s 사용률 %.1f%% (남은 공간 %s)", ds.Mount, ds.UsedPct, humanBytes(ds.Free)),
			})
		case ds.UsedPct >= d.cfg.DiskWarnPercent:
			findings = append(findings, Finding{
				Rule: "res.disk_full", Category: CategoryResourceAbuse, Severity: SevMedium, Source: ds.Mount, Key: ds.Mount + "|warn",
				Message: fmt.Sprintf("디스크 %s 사용률 %.1f%% (남은 공간 %s)", ds.Mount, ds.UsedPct, humanBytes(ds.Free)),
			})
		}
	}
	d.diskHist = append(d.diskHist, cur)
	for len(d.diskHist) > 0 && now.Sub(d.diskHist[0].At) > 10*time.Minute {
		d.diskHist = d.diskHist[1:]
	}
	if old := d.diskHist[0]; now.Sub(old.At) >= 2*time.Minute {
		for mount, used := range cur.Used {
			if prev, ok := old.Used[mount]; ok && used > prev {
				if grow := float64(used-prev) / gib; grow >= d.cfg.DiskGrowthGB {
					findings = append(findings, Finding{
						Rule: "res.disk_growth", Category: CategoryResourceAbuse, Severity: SevMedium, Source: mount,
						Message: fmt.Sprintf("디스크 %s 사용량 급증: %s 동안 +%.1f GB — 대용량 다운로드/로그 폭주/데이터 수집(유출 준비) 확인 필요",
							mount, humanDur(now.Sub(old.At)), grow),
					})
				}
			}
		}
	}

	// sustained-high timestamps for the UI
	for i := range snap.TopCPU {
		if t, ok := d.procHigh[snap.TopCPU[i].key()]; ok {
			snap.TopCPU[i].HighSince = t
		}
	}

	metrics := map[string]float64{
		"cpu.usage":     snap.CPU.UsagePct,
		"cpu.load1":     snap.CPU.Load1,
		"mem.used_pct":  snap.Memory.UsedPct,
		"mem.swap_used": float64(snap.Memory.SwapUsed) / gib,
	}
	if len(snap.Disks) > 0 {
		metrics["disk.used_pct"] = snap.Disks[0].UsedPct
	}

	return Report{
		Findings: findings,
		Summary: fmt.Sprintf("CPU %.0f%% (load %.2f) · 메모리 %.0f%% (%s) · 디스크 %s",
			snap.CPU.UsagePct, snap.CPU.Load1, snap.Memory.UsedPct, snap.Memory.Pressure, diskSummary(snap.Disks)),
		Checks:   d.checks(snap),
		Metrics:  metrics,
		Snapshot: snap,
	}, nil
}

func (d *resourcesDetector) ignored(p *ProcStat) bool {
	return isSystemExe(p.Exe) || slices.Contains(d.cfg.IgnoreProcesses, p.Name)
}

func (d *resourcesDetector) checks(s SystemSnapshot) []Check {
	st := func(v, warn, fail float64) string {
		switch {
		case v >= fail:
			return CheckFail
		case v >= warn:
			return CheckWarn
		}
		return CheckOK
	}
	pressure := CheckOK
	switch s.Memory.Pressure {
	case "warn":
		pressure = CheckWarn
	case "critical":
		pressure = CheckFail
	}
	checks := []Check{
		{Name: "CPU", Status: st(s.CPU.UsagePct, 75, d.cfg.SystemCPUPercent),
			Detail: fmt.Sprintf("%.1f%% (user %.1f%%, system %.1f%%), load %.2f / %.2f / %.2f, %d코어",
				s.CPU.UsagePct, s.CPU.UserPct, s.CPU.SystemPct, s.CPU.Load1, s.CPU.Load5, s.CPU.Load15, s.CPU.Cores)},
		{Name: "memory", Status: pressure,
			Detail: fmt.Sprintf("%s / %s (%.0f%%), 압박 %s", humanBytes(s.Memory.Used), humanBytes(s.Memory.Total), s.Memory.UsedPct, s.Memory.Pressure)},
		{Name: "swap", Status: CheckOK, Detail: fmt.Sprintf("%s / %s", humanBytes(s.Memory.SwapUsed), humanBytes(s.Memory.SwapTotal))},
	}
	for _, ds := range s.Disks {
		checks = append(checks, Check{Name: "disk " + ds.Mount, Status: st(ds.UsedPct, d.cfg.DiskWarnPercent, d.cfg.DiskCritPercent),
			Detail: fmt.Sprintf("%.1f%% 사용 — %s / %s, 남은 공간 %s", ds.UsedPct, humanBytes(ds.Used), humanBytes(ds.Total), humanBytes(ds.Free))})
	}
	for _, p := range s.TopCPU {
		status, note := CheckOK, ""
		if !p.HighSince.IsZero() {
			status, note = CheckWarn, fmt.Sprintf(", 고부하 %s째", humanDur(s.At.Sub(p.HighSince)))
		}
		checks = append(checks, Check{Name: fmt.Sprintf("top cpu %s (%d)", p.Name, p.PID), Status: status,
			Detail: fmt.Sprintf("CPU %.1f%%, 메모리 %s, user %s%s — %s", p.CPUPct, humanBytes(p.RSS), p.User, note, orNone(p.Exe))})
	}
	for _, p := range s.TopMem {
		checks = append(checks, Check{Name: fmt.Sprintf("top mem %s (%d)", p.Name, p.PID), Status: CheckOK,
			Detail: fmt.Sprintf("메모리 %s, CPU %.1f%%, user %s — %s", humanBytes(p.RSS), p.CPUPct, p.User, orNone(p.Exe))})
	}
	return checks
}

// topProcs fills TopCPU / TopMem (n each).
func topProcs(snap *SystemSnapshot, procs []ProcStat, n int) {
	byCPU := slices.Clone(procs)
	sort.Slice(byCPU, func(i, j int) bool { return byCPU[i].CPUPct > byCPU[j].CPUPct })
	snap.TopCPU = byCPU[:min(n, len(byCPU))]
	byMem := slices.Clone(procs)
	sort.Slice(byMem, func(i, j int) bool { return byMem[i].RSS > byMem[j].RSS })
	snap.TopMem = byMem[:min(n, len(byMem))]
}

func topNames(ps []ProcStat, n int) string {
	var parts []string
	for i, p := range ps {
		if i >= n {
			break
		}
		if p.CPUPct > 0 {
			parts = append(parts, fmt.Sprintf("%s %.0f%%", p.Name, p.CPUPct))
		} else {
			parts = append(parts, fmt.Sprintf("%s %s", p.Name, humanBytes(p.RSS)))
		}
	}
	return orNone(strings.Join(parts, ", "))
}

func diskSummary(ds []DiskStat) string {
	var parts []string
	for _, d := range ds {
		parts = append(parts, fmt.Sprintf("%s %.0f%%", d.Mount, d.UsedPct))
	}
	return orNone(strings.Join(parts, ", "))
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// humanDur: "45초", "6분", "1시간 20분"
func humanDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d초", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d분", int(d.Minutes()))
	}
	return fmt.Sprintf("%d시간 %d분", int(d.Hours()), int(d.Minutes())%60)
}
