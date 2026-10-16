package detect

import (
	"context"
	"os"
	"regexp"
	"strings"
	"time"
)

const socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

var (
	reALFState = regexp.MustCompile(`State = (\d)`)
	reALFApp   = regexp.MustCompile(`^\s*\d+\s*:\s*(.+?)\s*$`)
)

// Known third-party firewalls delivered as network system extensions.
var thirdPartyFirewalls = map[string]string{
	"at.obdev.littlesnitch":  "Little Snitch",
	"com.objective-see.lulu": "LuLu",
	"com.radiosilenceapp":    "Radio Silence",
	"com.intego.netbarrier":  "Intego NetBarrier",
	"com.metakine.handsoff":  "Hands Off!",
	"com.murusfirewall":      "Murus",
	"com.vallumfirewall":     "Vallum",
}

func collectFirewall(ctx context.Context) ([]FirewallComponent, error) {
	comps := []FirewallComponent{alfComponent(ctx), pfComponent(ctx)}
	comps = append(comps, networkExtensions(ctx)...)
	return comps, nil
}

// alfComponent: the macOS application firewall (System Settings > Network > Firewall).
func alfComponent(ctx context.Context) FirewallComponent {
	c := FirewallComponent{ID: "alf", Name: "애플리케이션 방화벽 (macOS)", Kind: "builtin", State: fwUnknown}
	run := func(arg string) string {
		out, _ := runCmd(ctx, 10*time.Second, socketfilterfw, arg)
		return strings.TrimSpace(out)
	}

	global := run("--getglobalstate")
	if m := reALFState.FindStringSubmatch(global); m != nil {
		switch m[1] {
		case "0":
			c.State = fwOff
		default:
			c.State = fwOn
		}
	} else {
		c.Detail = "socketfilterfw 응답 없음: " + firstLine(global)
		return c
	}
	onOff := func(v bool) string {
		if v {
			return "켜짐"
		}
		return "꺼짐"
	}
	set := func(name string, on bool, wantOn bool, note string) {
		st := CheckOK
		if on != wantOn {
			st = CheckWarn
		}
		c.Settings = append(c.Settings, FirewallSetting{Name: name, Value: onOff(on), Status: st, Note: note})
	}
	set("방화벽", c.State == fwOn, true, "꺼져 있으면 모든 앱이 외부 접속을 받을 수 있음")
	set("모든 수신 연결 차단", strings.Contains(run("--getblockall"), "enabled"), false, "켜면 필수 서비스 외 모든 수신 차단 (공용 Wi-Fi 권장)")
	signed := run("--getallowsigned")
	builtin, downloaded := false, false
	for line := range strings.Lines(signed) {
		l := strings.ToLower(line)
		if strings.Contains(l, "built-in") {
			builtin = strings.Contains(l, "enabled")
		}
		if strings.Contains(l, "downloaded") {
			downloaded = strings.Contains(l, "enabled")
		}
	}
	set("서명된 내장 소프트웨어 자동 허용", builtin, builtin, "")
	set("서명된 다운로드 소프트웨어 자동 허용", downloaded, false, "켜져 있으면 서명만 된 앱은 확인 없이 수신 허용")
	set("스텔스 모드", strings.Contains(run("--getstealthmode"), "on"), true, "ping·포트 스캔에 응답하지 않음")
	logMode := strings.Contains(run("--getloggingmode"), "on")
	set("로깅", logMode, true, "꺼져 있으면 차단/허용 기록이 남지 않음")
	if logMode {
		opt := strings.TrimSpace(strings.TrimPrefix(run("--getloggingopt"), "Log Option is"))
		c.Settings = append(c.Settings, FirewallSetting{Name: "로깅 수준", Value: opt, Status: CheckOK})
	}

	// per-app rules: "N : /path" followed by "(Allow|Block incoming connections)"
	apps := run("--listapps")
	var last string
	for line := range strings.Lines(apps) {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "(Allow"), strings.HasPrefix(t, "(Block"):
			if last == "" {
				continue
			}
			r := FirewallRule{Target: last, Action: "allow"}
			if strings.HasPrefix(t, "(Block") {
				r.Action = "block"
			}
			if r.Action == "allow" {
				switch {
				case isInterpreter(last):
					r.Warn, r.Note = true, "스크립트 인터프리터 — 모든 스크립트가 포트를 열 수 있음"
				case inSuspiciousDir(last):
					r.Warn, r.Note = true, "임시/공용 경로의 프로그램"
				}
				if _, err := os.Stat(last); err != nil {
					r.Warn, r.Note = true, strings.TrimPrefix(r.Note+"; 파일 없음 (삭제된 앱의 남은 규칙)", "; ")
				}
			}
			c.Rules = append(c.Rules, r)
			last = ""
		default:
			if m := reALFApp.FindStringSubmatch(t); m != nil && !strings.HasPrefix(t, "Total") {
				last = m[1]
			}
		}
	}
	sortRules(c.Rules)
	return c
}

// pfComponent: the BSD packet filter. Runtime state needs root; the
// configuration files are world-readable.
func pfComponent(ctx context.Context) FirewallComponent {
	c := FirewallComponent{ID: "pf", Name: "패킷 필터 (pf)", Kind: "builtin", State: fwUnknown}
	info, err := runCmd(ctx, 10*time.Second, "pfctl", "-s", "info")
	switch {
	case err == nil:
		if strings.Contains(info, "Status: Enabled") {
			c.State = fwOn
		} else {
			c.State = fwOff
		}
		if rules, err := runCmd(ctx, 10*time.Second, "pfctl", "-s", "rules"); err == nil {
			for line := range strings.Lines(rules) {
				if t := strings.TrimSpace(line); t != "" {
					action := "rule"
					switch {
					case strings.HasPrefix(t, "pass"):
						action = "allow"
					case strings.HasPrefix(t, "block"):
						action = "block"
					}
					c.Rules = append(c.Rules, FirewallRule{Target: t, Action: action})
				}
			}
		}
	case strings.Contains(err.Error(), "Permission denied"):
		c.Detail = "실행 상태와 적용 중인 규칙은 root 권한 필요 (sudo pfctl -s info) — 아래는 설정 파일"
	default:
		c.Detail = firstLine(err.Error())
	}
	for _, p := range append([]string{"/etc/pf.conf"}, globOrNil("/etc/pf.anchors/*")...) {
		if b, err := os.ReadFile(p); err == nil && len(b) < 256<<10 {
			c.Files = append(c.Files, FirewallFile{Path: p, Content: string(b)})
		}
	}
	return c
}

// networkExtensions lists network system extensions; known firewalls become
// their own components, the rest (VPNs, content filters) are listed for context.
func networkExtensions(ctx context.Context) []FirewallComponent {
	out, err := runCmd(ctx, 10*time.Second, "systemextensionsctl", "list")
	if err != nil && out == "" {
		return nil
	}
	var comps []FirewallComponent
	others := FirewallComponent{ID: "netext", Name: "기타 네트워크 확장", Kind: fwInfo, State: fwInfo,
		Detail: "트래픽을 가로챌 수 있는 시스템 확장 (VPN, 콘텐츠 필터 등)"}
	section := ""
	for line := range strings.Lines(out) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "---") {
			section = t
			continue
		}
		if !strings.Contains(section, "network_extension") {
			continue
		}
		f := strings.Split(t, "\t")
		if len(f) < 5 || f[0] == "enabled" {
			continue
		}
		bundle := strings.Fields(f[3])[0]
		name := strings.TrimSpace(f[4])
		if i := strings.Index(name, "\t"); i > 0 {
			name = name[:i]
		}
		active := strings.TrimSpace(f[0]) == "*" && strings.TrimSpace(f[1]) == "*"
		state := strings.TrimSpace(t[strings.LastIndex(t, "["):])
		if label, ok := knownFirewall(bundle); ok {
			st := fwOff
			if active {
				st = fwOn
			}
			comps = append(comps, FirewallComponent{ID: "ext:" + bundle, Name: label + " (서드파티)", Kind: "third_party", State: st,
				Detail: bundle + " " + state})
			continue
		}
		action := "inactive"
		if active {
			action = "active"
		}
		others.Rules = append(others.Rules, FirewallRule{Target: name + " (" + bundle + ")", Action: action, Note: state})
	}
	if len(others.Rules) > 0 {
		comps = append(comps, others)
	}
	return comps
}

func knownFirewall(bundle string) (string, bool) {
	for prefix, name := range thirdPartyFirewalls {
		if strings.HasPrefix(bundle, prefix) {
			return name, true
		}
	}
	return "", false
}
