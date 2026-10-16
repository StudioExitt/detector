package detect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// FirewallSnapshot describes every firewall layer found on the host.
type FirewallSnapshot struct {
	At         time.Time
	Platform   string
	Active     bool // at least one firewall component is on
	Components []FirewallComponent
}

type FirewallComponent struct {
	ID       string // alf, pf, ufw, firewalld, nftables, iptables, ext:<bundle>, netext
	Name     string
	Kind     string // builtin / third_party / info
	State    string // on / off / unknown / info
	Detail   string // e.g. why the state is unknown
	Settings []FirewallSetting
	Rules    []FirewallRule
	Files    []FirewallFile // configuration files (pf.conf, anchors ...)
}

type FirewallSetting struct {
	Name   string
	Value  string
	Status string // ok / warn / fail
	Note   string
}

type FirewallRule struct {
	Target string // app path, port/proto, rule text
	Action string // allow / block / rule
	Note   string
	Warn   bool
}

type FirewallFile struct {
	Path    string
	Content string
}

const (
	fwOn      = "on"
	fwOff     = "off"
	fwUnknown = "unknown"
	fwInfo    = "info"
)

// CollectFirewall reads the current firewall configuration (no findings).
func CollectFirewall(ctx context.Context) (FirewallSnapshot, error) {
	comps, err := collectFirewall(ctx)
	if err != nil {
		return FirewallSnapshot{}, err
	}
	snap := FirewallSnapshot{At: time.Now(), Platform: Platform(), Components: comps}
	for _, c := range comps {
		if c.State == fwOn && c.Kind != fwInfo {
			snap.Active = true
		}
	}
	return snap, nil
}

// firewallDetector reports changes: a firewall turned off, settings
// weakened, apps newly allowed to accept connections, rule files edited, a
// third-party firewall removed. The "firewall is off" state itself is
// reported once by the posture detector.
type firewallDetector struct{}

func newFirewallDetector() Detector { return &firewallDetector{} }

func (d *firewallDetector) Name() string { return "firewall" }

type fwBaseline struct {
	States   map[string]string `json:"states"`   // component -> state
	Settings map[string]string `json:"settings"` // component|setting -> value
	Rules    map[string]string `json:"rules"`    // component|target -> action
	Files    map[string]string `json:"files"`    // path -> sha256
	Names    map[string]string `json:"names"`    // component -> display name
}

func (d *firewallDetector) Check(ctx context.Context, env *Env) (Report, error) {
	snap, err := CollectFirewall(ctx)
	if err != nil {
		return Report{}, err
	}
	cur := fwBaseline{States: map[string]string{}, Settings: map[string]string{}, Rules: map[string]string{}, Files: map[string]string{}, Names: map[string]string{}}
	for _, c := range snap.Components {
		cur.States[c.ID] = c.State
		cur.Names[c.ID] = c.Name
		for _, s := range c.Settings {
			cur.Settings[c.ID+"|"+s.Name] = s.Value
		}
		for _, r := range c.Rules {
			cur.Rules[c.ID+"|"+r.Target] = r.Action
		}
		for _, f := range c.Files {
			h := sha256.Sum256([]byte(f.Content))
			cur.Files[f.Path] = hex.EncodeToString(h[:])
		}
	}

	var prev fwBaseline
	found, err := env.State.Load(ctx, "baseline", &prev)
	if err != nil {
		return Report{}, err
	}
	var findings []Finding
	if found {
		findings = firewallChanges(prev, cur, snap, env.Host)
	}
	if err := env.State.Save(ctx, "baseline", cur); err != nil {
		return Report{}, err
	}

	var checks []Check
	on := 0
	for _, c := range snap.Components {
		st := CheckOK
		switch {
		case c.State == fwOff && c.Kind != fwInfo:
			st = CheckWarn
		case c.State == fwUnknown:
			st = CheckWarn
		case c.State == fwOn && c.Kind != fwInfo:
			on++
		}
		detail := stateText(c.State)
		if c.Detail != "" {
			detail += " — " + c.Detail
		}
		if len(c.Rules) > 0 {
			detail += fmt.Sprintf(" · 규칙 %d개", len(c.Rules))
		}
		checks = append(checks, Check{Name: c.Name, Status: st, Detail: detail})
		for _, s := range c.Settings {
			if s.Status != CheckOK {
				checks = append(checks, Check{Name: c.Name + " · " + s.Name, Status: s.Status, Detail: strings.TrimSpace(s.Value + " " + s.Note)})
			}
		}
		for _, r := range c.Rules {
			if r.Warn {
				checks = append(checks, Check{Name: c.Name + " · " + r.Target, Status: CheckWarn, Detail: r.Action + " — " + r.Note})
			}
		}
	}
	summary := "활성화된 방화벽 없음"
	if snap.Active {
		summary = fmt.Sprintf("방화벽 %d개 활성", on)
	}
	return Report{Findings: findings, Summary: summary + fmt.Sprintf(" (구성요소 %d개 점검)", len(snap.Components)), Checks: checks}, nil
}

func stateText(s string) string {
	switch s {
	case fwOn:
		return "켜짐"
	case fwOff:
		return "꺼짐"
	case fwInfo:
		return "정보"
	}
	return "확인 불가"
}

func firewallChanges(prev, cur fwBaseline, snap FirewallSnapshot, host string) []Finding {
	var out []Finding
	name := func(id string) string {
		if n := cur.Names[id]; n != "" {
			return n
		}
		return prev.Names[id]
	}

	for _, id := range sortedKeys(prev.States) {
		was, now := prev.States[id], cur.States[id]
		switch {
		case was == fwOn && now == fwOff:
			out = append(out, Finding{Rule: "firewall.disabled", Category: CategoryIntrusion, Severity: SevHigh, Source: host, Key: id,
				Message: fmt.Sprintf("방화벽이 꺼짐: %s — 사용자가 끈 것이 아니라면 악성코드의 보안 해제 의심", name(id))})
		case was == fwOff && now == fwOn:
			out = append(out, Finding{Rule: "firewall.enabled", Category: CategoryIntrusion, Severity: SevLow, Source: host, Key: id,
				Message: fmt.Sprintf("방화벽이 켜짐: %s", name(id))})
		case now == "" && strings.HasPrefix(id, "ext:") && was == fwOn:
			out = append(out, Finding{Rule: "firewall.removed", Category: CategoryIntrusion, Severity: SevHigh, Source: host, Key: id,
				Message: fmt.Sprintf("서드파티 방화벽이 사라짐: %s — 제거/비활성화 여부 확인", name(id))})
		}
	}

	for _, k := range sortedKeys(cur.Settings) {
		was, ok := prev.Settings[k]
		if !ok || was == cur.Settings[k] {
			continue
		}
		id, setting, _ := strings.Cut(k, "|")
		sev := SevLow
		if weakened(setting, was, cur.Settings[k]) {
			sev = SevMedium
		}
		out = append(out, Finding{Rule: "firewall.setting_changed", Category: CategoryIntrusion, Severity: sev, Source: host, Key: k + "|" + cur.Settings[k],
			Message: fmt.Sprintf("방화벽 설정 변경 (%s): %s %s → %s", name(id), setting, was, cur.Settings[k])})
	}

	ruleIndex := map[string]FirewallRule{}
	for _, c := range snap.Components {
		for _, r := range c.Rules {
			ruleIndex[c.ID+"|"+r.Target] = r
		}
	}
	for _, k := range sortedKeys(cur.Rules) {
		action := cur.Rules[k]
		was, ok := prev.Rules[k]
		if ok && was == action {
			continue
		}
		id, target, _ := strings.Cut(k, "|")
		r := ruleIndex[k]
		sev := SevLow
		if action == "allow" {
			sev = SevMedium
			if inSuspiciousDir(target) || r.Warn {
				sev = SevHigh
			}
		}
		what := "새 규칙"
		if ok {
			what = fmt.Sprintf("규칙 변경 (%s →)", was)
		}
		msg := fmt.Sprintf("방화벽 %s (%s): %s %s", what, name(id), actionText(action), target)
		if r.Note != "" {
			msg += " — " + r.Note
		}
		out = append(out, Finding{Rule: "firewall.rule_added", Category: CategoryIntrusion, Severity: sev, Source: target, Key: k + "|" + action, Message: msg})
	}
	var removed []string
	for _, k := range sortedKeys(prev.Rules) {
		if _, ok := cur.Rules[k]; !ok {
			_, target, _ := strings.Cut(k, "|")
			removed = append(removed, target)
		}
	}
	if len(removed) > 0 {
		out = append(out, Finding{Rule: "firewall.rule_removed", Category: CategoryIntrusion, Severity: SevLow, Source: host, Key: strings.Join(removed, ","),
			Message: "방화벽 규칙 삭제: " + joinLimit(removed, 5)})
	}

	for _, p := range sortedKeys(cur.Files) {
		if h, ok := prev.Files[p]; ok && h != cur.Files[p] {
			out = append(out, Finding{Rule: "firewall.config_changed", Category: CategoryIntrusion, Severity: SevMedium, Source: p, Key: p + "|" + cur.Files[p],
				Message: "방화벽 설정 파일 변경: " + p})
		}
	}
	return out
}

// weakened reports whether a setting change lowers protection.
func weakened(setting, was, now string) bool {
	on := func(v string) bool {
		v = strings.ToLower(v)
		return slices.Contains([]string{"on", "enabled", "켜짐", "yes", "true", "deny", "reject"}, v)
	}
	switch {
	case strings.Contains(setting, "자동 허용"):
		return !on(was) && on(now) // auto-allow switched on
	default:
		return on(was) && !on(now)
	}
}

func actionText(a string) string {
	switch a {
	case "allow":
		return "허용"
	case "block":
		return "차단"
	}
	return a
}

// interpreters allowed to accept connections let any script open a port
var interpreterNames = []string{"python", "python3", "python2", "ruby", "perl", "node", "php", "bash", "sh", "zsh", "osascript", "java"}

func isInterpreter(path string) bool {
	b := strings.ToLower(baseName(path))
	for _, n := range interpreterNames {
		if b == n || strings.HasPrefix(b, n+"3.") || strings.HasPrefix(b, n+"2.") {
			return true
		}
	}
	return false
}

func sortRules(rs []FirewallRule) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Warn != rs[j].Warn {
			return rs[i].Warn
		}
		return false
	})
}

func parseUFW(out string, c *FirewallComponent) {
	inRules := false
	for line := range strings.Lines(out) {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "Status:"):
			if strings.Contains(t, "inactive") {
				c.State = fwOff
			} else {
				c.State = fwOn
			}
		case strings.HasPrefix(t, "Default:"):
			v := strings.TrimSpace(strings.TrimPrefix(t, "Default:"))
			st := CheckOK
			if strings.Contains(v, "allow (incoming)") {
				st = CheckWarn
			}
			c.Settings = append(c.Settings, FirewallSetting{Name: "기본 정책", Value: v, Status: st})
		case strings.HasPrefix(t, "Logging:"):
			v := strings.TrimSpace(strings.TrimPrefix(t, "Logging:"))
			st := CheckOK
			if strings.HasPrefix(v, "off") {
				st = CheckWarn
			}
			c.Settings = append(c.Settings, FirewallSetting{Name: "로깅", Value: v, Status: st})
		case strings.HasPrefix(t, "--"):
			inRules = true
		case inRules && t != "":
			action := "rule"
			switch {
			case strings.Contains(t, "ALLOW"):
				action = "allow"
			case strings.Contains(t, "DENY"), strings.Contains(t, "REJECT"):
				action = "block"
			}
			r := FirewallRule{Target: strings.Join(strings.Fields(t), " "), Action: action}
			if action == "allow" && strings.Contains(t, "Anywhere") && (strings.HasPrefix(t, "22") || strings.HasPrefix(t, "OpenSSH")) {
				r.Note = "SSH 를 모든 출발지에 개방"
			}
			c.Rules = append(c.Rules, r)
		}
	}
}
