package detect

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type proc struct {
	PID     int
	User    string
	Exe     string // executable path
	Args    string // full command line
	Deleted bool   // linux: executable removed from disk while running
}

// Known coin miners / Linux malware families (matched on the executable name).
var minerNames = map[string]bool{
	"xmrig": true, "xmr-stak": true, "xmrig-notls": true, "minerd": true, "cpuminer": true,
	"cpuminer-multi": true, "ccminer": true, "cgminer": true, "bfgminer": true, "ethminer": true,
	"nbminer": true, "t-rex": true, "lolminer": true, "phoenixminer": true, "nanominer": true,
	"teamredminer": true, "gminer": true, "srbminer": true, "srbminer-multi": true,
	"kdevtmpfsi": true, "kinsing": true, "kthreaddi": true, "dbused": true, "xmr": true,
}

var reMinerArgs = regexp.MustCompile(`(?i)stratum\+(tcp|ssl)://|--donate-level|\bpool\.(minexmr|supportxmr|hashvault|nanopool)`)

var reverseShellPatterns = []*regexp.Regexp{
	regexp.MustCompile(`/dev/(tcp|udp)/[^/\s]+/\d+`),
	regexp.MustCompile(`\b(nc|ncat|netcat)\b.*\s-[a-zA-Z]*[ec]\s`),
	regexp.MustCompile(`\bsocat\b.*\bexec:`),
	regexp.MustCompile(`\b(bash|sh|zsh)\s+-i\b.*[<>]&`),
	regexp.MustCompile(`\bmkfifo\b.*\b(nc|ncat|sh|bash)\b`),
	regexp.MustCompile(`python[0-9.]*\s+-c\s+.*socket.*(subprocess|pty\.spawn|os\.dup2)`),
	regexp.MustCompile(`\bperl\b.*-e\s+.*socket.*exec`),
	regexp.MustCompile(`\bphp\b.*-r\s+.*fsockopen`),
	regexp.MustCompile(`\bruby\b.*-rsocket`),
}

// Browsers started with a forced extension (ChromeLoader / Choziosi family
// relaunch Chrome with --load-extension pointing at a dropped folder).
var reBrowserLoadExt = regexp.MustCompile(`(?i)(chrome|chromium|msedge|microsoft edge|brave|whale|vivaldi|opera)[^\n]*\s--load-extension=(\S+)`)

type processDetector struct {
	self int
}

func newProcessDetector() Detector { return &processDetector{self: os.Getpid()} }

func (d *processDetector) Name() string { return "process" }

func (d *processDetector) Check(ctx context.Context, env *Env) (Report, error) {
	procs, err := listProcesses(ctx)
	if err != nil {
		return Report{}, err
	}

	var findings []Finding
	var checks []Check
	for _, p := range procs {
		if p.PID == d.self {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(baseName(p.Exe), " (deleted)"))
		desc := fmt.Sprintf("pid %d, user %s, %s", p.PID, p.User, truncate(p.Args, 200))

		switch {
		case minerNames[name] || reMinerArgs.MatchString(p.Args):
			findings = append(findings, Finding{
				Rule: "proc.miner", Category: CategoryResourceAbuse, Severity: SevCritical, Source: p.Exe, Key: p.Exe,
				Message: "암호화폐 채굴/악성 프로세스 의심: " + desc,
			})
		case matchesAny(reverseShellPatterns, p.Args):
			findings = append(findings, Finding{
				Rule: "proc.reverse_shell", Category: CategoryIntrusion, Severity: SevCritical, Source: p.Exe, Key: p.Args,
				Message: "리버스 셸 의심 명령: " + desc,
			})
		}
		if m := reBrowserLoadExt.FindStringSubmatch(p.Args); m != nil {
			findings = append(findings, Finding{
				Rule: "proc.browser_load_extension", Category: CategoryIntrusion, Severity: SevHigh, Source: p.Exe, Key: m[2],
				Message: "브라우저가 --load-extension 으로 강제 확장 로드 중 (ChromeLoader 계열 수법): " + m[2] + " — " + desc,
			})
		}
		if p.Deleted {
			findings = append(findings, Finding{
				Rule: "proc.deleted_exe", Category: CategoryIntrusion, Severity: SevHigh, Source: p.Exe, Key: p.Exe,
				Message: "디스크에서 삭제된 실행파일이 실행 중 (흔적 지우기 의심): " + desc,
			})
		}
		if inSuspiciousDir(p.Exe) {
			findings = append(findings, Finding{
				Rule: "proc.suspicious_path", Category: CategoryIntrusion, Severity: SevHigh, Source: p.Exe, Key: p.Exe,
				Message: "임시/공용 디렉토리에서 실행 중인 프로세스: " + desc,
			})
			checks = append(checks, Check{Name: p.Exe, Status: CheckWarn, Detail: desc})
		}
	}

	checks = append([]Check{{Name: "watched dirs", Status: CheckOK, Detail: strings.Join(suspiciousDirs, " ")}}, checks...)
	return Report{
		Findings: findings,
		Summary:  fmt.Sprintf("프로세스 %d개 검사 — 의심 %d건", len(procs), len(findings)),
		Checks:   checks,
	}, nil
}

func matchesAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
