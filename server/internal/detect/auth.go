package detect

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"detector/internal/config"
)

type authKind int

const (
	authSSHFail      authKind = iota // failed password / invalid user
	authSSHSuccess                   // accepted login
	authLocalFail                    // local password verification failed (macOS opendirectoryd)
	authSudoFail                     // sudo: N incorrect password attempts
	authSudoNotAllow                 // sudo: user NOT in sudoers
)

type authEvent struct {
	Time   time.Time
	Kind   authKind
	User   string
	IP     string
	Method string
	Count  int // sudo attempt count
}

// authSource reads new authentication log entries since the previous call.
// Implementations keep their cursor in env.State.
type authSource interface {
	Name() string
	Fetch(ctx context.Context, env *Env) ([]authEvent, error)
}

var (
	reSSHFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S*) from (\S+) port \d+`)
	reSSHInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)`)
	reSSHAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)
	reSudoFail    = regexp.MustCompile(`^\s*(\S+) : (\d+) incorrect password attempts?`)
	reSudoNotIn   = regexp.MustCompile(`^\s*(\S+) : (?:user NOT in sudoers|.*not allowed to execute)`)
)

// parseSSHD parses an sshd / sshd-session message.
func parseSSHD(msg string) (authEvent, bool) {
	if m := reSSHFailed.FindStringSubmatch(msg); m != nil {
		if m[2] != "" {
			// "Invalid user ..." was already counted for this attempt
			return authEvent{}, false
		}
		return authEvent{Kind: authSSHFail, Method: m[1], User: m[3], IP: m[4]}, true
	}
	if m := reSSHInvalid.FindStringSubmatch(msg); m != nil {
		return authEvent{Kind: authSSHFail, Method: "invalid_user", User: m[1], IP: m[2]}, true
	}
	if m := reSSHAccepted.FindStringSubmatch(msg); m != nil {
		return authEvent{Kind: authSSHSuccess, Method: m[1], User: m[2], IP: m[3]}, true
	}
	return authEvent{}, false
}

// parseSudo parses a sudo log message.
func parseSudo(msg string) (authEvent, bool) {
	if m := reSudoFail.FindStringSubmatch(msg); m != nil {
		n, _ := strconv.Atoi(m[2])
		return authEvent{Kind: authSudoFail, User: m[1], Count: n}, true
	}
	if m := reSudoNotIn.FindStringSubmatch(msg); m != nil {
		return authEvent{Kind: authSudoNotAllow, User: m[1]}, true
	}
	return authEvent{}, false
}

type authDetector struct {
	cfg config.AuthDetectConfig
	src authSource
	// failures per key ("ssh:<ip>", "local:<user>", "sudo:<user>") inside the window
	fails     map[string][]time.Time
	failUsers map[string]map[string]struct{}
}

func newAuthDetector(cfg config.AuthDetectConfig) Detector {
	src := newAuthSource(cfg)
	if src == nil {
		return nil
	}
	return &authDetector{cfg: cfg, src: src, fails: map[string][]time.Time{}, failUsers: map[string]map[string]struct{}{}}
}

func (d *authDetector) Name() string { return "auth" }

const knownSourcesKey = "known_ssh_sources"

func (d *authDetector) Check(ctx context.Context, env *Env) (Report, error) {
	events, err := d.src.Fetch(ctx, env)
	if err != nil {
		return Report{Checks: []Check{{Name: "log source", Status: CheckFail, Detail: d.src.Name() + ": " + err.Error()}}}, err
	}

	known := map[string]string{} // ip -> first seen
	if _, err := env.State.Load(ctx, knownSourcesKey, &known); err != nil {
		return Report{}, err
	}
	knownChanged := false

	var findings []Finding
	var nFail, nOK int
	now := time.Now()
	for _, ev := range events {
		if ev.Time.IsZero() {
			ev.Time = now
		}
		switch ev.Kind {
		case authSSHFail:
			nFail++
			key := "ssh:" + ev.IP
			if n := d.addFail(key, ev.User, ev.Time, 1); n >= d.cfg.FailThreshold {
				findings = append(findings, Finding{
					Rule: "auth.ssh_bruteforce", Category: CategoryIntrusion, Severity: SevHigh, Source: ev.IP,
					Message: fmt.Sprintf("SSH 로그인 실패 %d회 (%s 내) — 출발지 %s, 시도 계정: %s",
						n, d.cfg.FailWindow, ev.IP, d.users(key)),
				})
			}
		case authSSHSuccess:
			nOK++
			key := "ssh:" + ev.IP
			if n := d.count(key, ev.Time); n > 0 {
				findings = append(findings, Finding{
					Rule: "auth.ssh_success_after_failures", Category: CategoryIntrusion, Severity: SevCritical, Source: ev.IP,
					Message: fmt.Sprintf("SSH 로그인 실패 %d회 후 성공 — 계정 %s, 출발지 %s (%s). 계정 탈취 가능성",
						n, ev.User, ev.IP, ev.Method),
				})
			} else if ev.User == "root" {
				findings = append(findings, Finding{
					Rule: "auth.ssh_root_login", Category: CategoryIntrusion, Severity: SevHigh, Source: ev.IP,
					Message: fmt.Sprintf("root 계정 SSH 직접 로그인 — 출발지 %s (%s)", ev.IP, ev.Method),
				})
			} else if _, ok := known[ev.IP]; !ok && len(known) > 0 {
				findings = append(findings, Finding{
					Rule: "auth.ssh_new_source", Category: CategoryIntrusion, Severity: SevMedium, Source: ev.IP,
					Message: fmt.Sprintf("처음 보는 출발지에서 SSH 로그인 — 계정 %s, 출발지 %s (%s)", ev.User, ev.IP, ev.Method),
				})
			}
			if _, ok := known[ev.IP]; !ok && len(known) < 1000 {
				known[ev.IP] = ev.Time.UTC().Format(time.RFC3339)
				knownChanged = true
			}
		case authLocalFail:
			nFail++
			key := "local:" + ev.User
			if n := d.addFail(key, ev.User, ev.Time, 1); n >= d.cfg.FailThreshold {
				findings = append(findings, Finding{
					Rule: "auth.local_bruteforce", Category: CategoryIntrusion, Severity: SevHigh, Source: env.Host, Key: ev.User,
					Message: fmt.Sprintf("로컬 계정 %s 비밀번호 인증 실패 %d회 (%s 내) — 잠금화면/sudo/암호 입력창 무차별 대입 의심",
						ev.User, n, d.cfg.FailWindow),
				})
			}
		case authSudoFail:
			nFail++
			key := "sudo:" + ev.User
			if n := d.addFail(key, ev.User, ev.Time, max(ev.Count, 1)); n >= 3 {
				findings = append(findings, Finding{
					Rule: "auth.sudo_failures", Category: CategoryIntrusion, Severity: SevMedium, Source: env.Host, Key: ev.User,
					Message: fmt.Sprintf("sudo 비밀번호 실패 %d회 (%s 내) — 계정 %s", n, d.cfg.FailWindow, ev.User),
				})
			}
		case authSudoNotAllow:
			nFail++
			findings = append(findings, Finding{
				Rule: "auth.sudo_not_allowed", Category: CategoryIntrusion, Severity: SevHigh, Source: env.Host, Key: ev.User,
				Message: fmt.Sprintf("sudo 권한 없는 계정의 권한 상승 시도 — 계정 %s", ev.User),
			})
		}
	}

	if knownChanged {
		if err := env.State.Save(ctx, knownSourcesKey, known); err != nil {
			return Report{}, err
		}
	}

	d.prune(now)
	return Report{
		Findings: findings,
		Summary:  fmt.Sprintf("%s: 이번 실행에서 인증 이벤트 %d건 (실패 %d, SSH 성공 %d)", d.src.Name(), len(events), nFail, nOK),
		Checks:   append([]Check{{Name: "log source", Status: CheckOK, Detail: d.src.Name()}}, d.watchChecks(now)...),
	}, nil
}

func (d *authDetector) addFail(key, user string, t time.Time, n int) int {
	for range n {
		d.fails[key] = append(d.fails[key], t)
	}
	if user != "" {
		if d.failUsers[key] == nil {
			d.failUsers[key] = map[string]struct{}{}
		}
		d.failUsers[key][user] = struct{}{}
	}
	return d.count(key, t)
}

// count returns failures for key within the window ending at t.
func (d *authDetector) count(key string, t time.Time) int {
	n := 0
	for _, ft := range d.fails[key] {
		if t.Sub(ft) <= d.cfg.FailWindow && !ft.After(t.Add(time.Second)) {
			n++
		}
	}
	return n
}

func (d *authDetector) users(key string) string {
	return joinLimit(sortedKeys(d.failUsers[key]), 5)
}

func (d *authDetector) prune(now time.Time) {
	for k, ts := range d.fails {
		kept := ts[:0]
		for _, t := range ts {
			if now.Sub(t) <= d.cfg.FailWindow {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(d.fails, k)
			delete(d.failUsers, k)
		} else {
			d.fails[k] = kept
		}
	}
}

// watchChecks lists keys that currently have failures inside the window.
func (d *authDetector) watchChecks(now time.Time) []Check {
	type kv struct {
		k string
		n int
	}
	var items []kv
	for k := range d.fails {
		items = append(items, kv{k, d.count(k, now)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].n > items[j].n })
	var out []Check
	for i, it := range items {
		if i >= 10 {
			break
		}
		st := CheckWarn
		if it.n >= d.cfg.FailThreshold {
			st = CheckFail
		}
		out = append(out, Check{
			Name:   "failures " + strings.Replace(it.k, ":", " ", 1),
			Status: st,
			Detail: fmt.Sprintf("%d회 / %s (임계값 %d)", it.n, d.cfg.FailWindow, d.cfg.FailThreshold),
		})
	}
	return out
}
