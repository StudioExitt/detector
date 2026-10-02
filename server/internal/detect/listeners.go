package detect

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"detector/internal/config"
)

type listener struct {
	Proto   string
	Addr    string // bind address; "*" for any
	Port    int
	PID     int
	Process string // short name
	Exe     string // full path when known
}

func (l listener) key() string {
	return fmt.Sprintf("%s|%s|%d|%s", l.Proto, l.Addr, l.Port, l.Process)
}

func (l listener) wildcard() bool {
	switch l.Addr {
	case "*", "0.0.0.0", "::", "[::]":
		return true
	}
	return false
}

func (l listener) String() string {
	proc := l.Process
	if proc == "" {
		proc = "?"
	}
	if l.PID > 0 {
		proc = fmt.Sprintf("%s(pid %d)", proc, l.PID)
	}
	return fmt.Sprintf("%s %s %s", l.Proto, l.hostPort(), proc)
}

func (l listener) hostPort() string {
	if strings.Contains(l.Addr, ":") {
		return fmt.Sprintf("[%s]:%d", l.Addr, l.Port)
	}
	return fmt.Sprintf("%s:%d", l.Addr, l.Port)
}

type listenerDetector struct {
	ignore map[int]bool
}

func newListenerDetector(cfg config.ListenersDetectConfig) Detector {
	ig := map[int]bool{}
	for _, p := range cfg.IgnorePorts {
		ig[p] = true
	}
	return &listenerDetector{ignore: ig}
}

func (d *listenerDetector) Name() string { return "listeners" }

const knownListenersKey = "known"

func (d *listenerDetector) Check(ctx context.Context, env *Env) (Report, error) {
	ls, err := listListeners(ctx)
	if err != nil {
		return Report{}, err
	}
	self := os.Getpid()
	ls = slices.DeleteFunc(ls, func(l listener) bool { return d.ignore[l.Port] || l.PID == self })
	sort.Slice(ls, func(i, j int) bool {
		if ls[i].Port != ls[j].Port {
			return ls[i].Port < ls[j].Port
		}
		return ls[i].key() < ls[j].key()
	})

	known := map[string]string{} // key -> first seen
	found, err := env.State.Load(ctx, knownListenersKey, &known)
	if err != nil {
		return Report{}, err
	}
	knownProc := map[string]bool{}
	for k := range known {
		knownProc[procOfKey(k)] = true
	}

	var findings []Finding
	var checks []Check
	newByProc := map[string][]listener{}
	external := 0
	now := time.Now().UTC().Format(time.RFC3339)
	for _, l := range ls {
		if l.wildcard() {
			external++
		}
		st := CheckOK
		if l.wildcard() {
			st = CheckWarn
		}
		if len(checks) < 100 {
			checks = append(checks, Check{Name: l.Proto + " " + l.hostPort(), Status: st, Detail: l.Exe + procDetail(l)})
		}

		k := l.key()
		if _, ok := known[k]; ok {
			continue
		}
		known[k] = now
		if !found {
			continue // building the baseline
		}
		// ephemeral ports of an already known process (e.g. rapportd) are routine
		if l.Port >= 49152 && knownProc[l.Process] {
			continue
		}

		newByProc[l.Exe+"|"+l.Process] = append(newByProc[l.Exe+"|"+l.Process], l)
	}

	// one finding per process, listing every newly opened port
	for _, pk := range sortedKeys(newByProc) {
		group := newByProc[pk]
		first := group[0]
		sev, scope := SevLow, "로컬(loopback) 전용"
		var addrs, keys []string
		for _, l := range group {
			addrs = append(addrs, l.hostPort())
			keys = append(keys, l.key())
			if l.wildcard() {
				sev, scope = SevMedium, "모든 인터페이스에 노출"
			}
		}
		if inSuspiciousDir(first.Exe) {
			sev = SevHigh
			scope += ", ⚠ 임시 경로의 실행파일"
		}
		proc := first.Process
		if proc == "" {
			proc = "?"
		}
		findings = append(findings, Finding{
			Rule: "net.new_listener", Category: CategoryIntrusion, Severity: sev, Source: joinLimit(addrs, 3), Key: strings.Join(keys, ","),
			Message: fmt.Sprintf("새 리스닝 포트 %d개: %s — %s(pid %d) (%s)%s",
				len(group), joinLimit(addrs, 8), proc, first.PID, scope, exeSuffix(first.Exe)),
		})
	}

	if len(known) > 5000 {
		known = map[string]string{} // runaway growth guard; rebuilt from current state
		for _, l := range ls {
			known[l.key()] = now
		}
	}
	if err := env.State.Save(ctx, knownListenersKey, known); err != nil {
		return Report{}, err
	}

	summary := fmt.Sprintf("LISTEN 소켓 %d개 (외부 노출 %d개)", len(ls), external)
	if !found {
		summary = "기준선 생성: " + summary
	}
	return Report{Findings: findings, Summary: summary, Checks: checks}, nil
}

func procOfKey(k string) string {
	// proto|addr|port|process
	n := 0
	for i := range len(k) {
		if k[i] == '|' {
			n++
			if n == 3 {
				return k[i+1:]
			}
		}
	}
	return ""
}

func procDetail(l listener) string {
	if l.Exe == "" {
		if l.PID > 0 {
			return l.Process + " pid " + strconv.Itoa(l.PID)
		}
		return l.Process
	}
	return " pid " + strconv.Itoa(l.PID)
}

func exeSuffix(exe string) string {
	if exe == "" {
		return ""
	}
	return " — " + exe
}
