package detect

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"detector/internal/config"
)

// Recording kinds.
const (
	RecScreen = "screen"
	RecMic    = "mic"
	RecCamera = "camera"
	RecRemote = "remote" // remote screen viewing / control (tools only)
)

// RecordingSnapshot is the current screen / microphone / camera capture state.
type RecordingSnapshot struct {
	At       time.Time
	Platform string
	Uses     []RecUse   // processes currently capturing (OS indicator / device level)
	Devices  []AVDevice // microphones and cameras
	Tools    []RecTool  // running screen/audio recorders and remote-viewing tools
	// TCC grants (macOS): which apps may record the screen, microphone, camera
	Permissions []RecPermission
	PermError   string
	Recent      []RecActivity // capture sessions seen since process start, newest first
	Notes       []string      // source limitations (e.g. log stream unavailable)
}

// AVDevice is one microphone or camera.
type AVDevice struct {
	Name  string
	Kind  string // mic / camera
	InUse bool
}

type RecUse struct {
	Kind    string // screen / mic / camera
	App     string // bundle id, process name or exe
	Name    string // display name
	PID     int
	Exe     string
	Hidden  bool // the OS could not attribute the capture to an app
	Trusted bool // matched trustedApps (shown, not reported)
	Note    string
	Since   time.Time
}

type RecTool struct {
	Kind    string // screen / mic / remote
	Label   string
	PID     int
	User    string
	Exe     string
	Args    string
	Trusted bool
	Warn    bool
	Note    string
}

type RecPermission struct {
	Service string // screen / mic / camera / input
	Client  string // bundle id or path
	Allowed bool
	Scope   string // user / system
	Updated time.Time
	Warn    bool
	Note    string
}

type RecActivity struct {
	Kind   string
	App    string
	Name   string
	PID    int
	Hidden bool
	Start  time.Time
	End    time.Time // zero while active
}

// recSample is what the platform layer reports on each run.
type recSample struct {
	Uses        []RecUse
	Devices     []AVDevice
	Permissions []RecPermission
	PermError   string
	PermChecked bool // permissions were read (baseline may be compared)
	Notes       []string
}

// recSource collects capture state for the current OS.
type recSource interface {
	Start(ctx context.Context, env *Env)
	Sample(ctx context.Context) (recSample, error)
}

// recordingDetector reports when the screen, a microphone or a camera starts
// being captured, captures the OS could not attribute to an app, recorder /
// remote-viewing tools that start running, and new recording permissions.
type recordingDetector struct {
	cfg     config.RecordingDetectConfig
	src     recSource
	trusted []string

	mu     sync.Mutex
	active map[string]RecUse  // kind|app -> current use
	tools  map[string]RecTool // exe|kind -> running tool
	recent []RecActivity
}

func newRecordingDetector(cfg config.RecordingDetectConfig) Detector {
	src := newRecSource()
	if src == nil {
		return nil
	}
	var trusted []string
	for _, t := range cfg.TrustedApps {
		trusted = append(trusted, strings.ToLower(t))
	}
	return &recordingDetector{cfg: cfg, src: src, trusted: trusted, active: map[string]RecUse{}, tools: map[string]RecTool{}}
}

func (d *recordingDetector) Name() string { return "recording" }

func (d *recordingDetector) Start(ctx context.Context, env *Env) { d.src.Start(ctx, env) }

// isTrusted matches bundle id, process name or exe path (case-insensitive).
func (d *recordingDetector) isTrusted(vals ...string) bool {
	for _, v := range vals {
		if v == "" {
			continue
		}
		v = strings.ToLower(v)
		if slices.Contains(d.trusted, v) || slices.Contains(d.trusted, strings.ToLower(baseName(v))) {
			return true
		}
	}
	return false
}

func (d *recordingDetector) Check(ctx context.Context, env *Env) (Report, error) {
	s, err := d.src.Sample(ctx)
	if err != nil {
		return Report{}, err
	}
	procs, perr := listProcesses(ctx)
	if perr != nil {
		s.Notes = append(s.Notes, "프로세스 목록 확인 불가: "+perr.Error())
	}
	byPID := map[int]proc{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	now := time.Now()

	var findings []Finding
	d.mu.Lock()
	// ── capture sessions ──
	cur := map[string]RecUse{}
	for _, u := range s.Uses {
		if u.Exe == "" && u.PID > 0 {
			u.Exe = byPID[u.PID].Exe
		}
		if u.Name == "" {
			u.Name = orNone(firstNonEmpty(u.App, baseName(u.Exe)))
		}
		u.Trusted = d.isTrusted(u.App, u.Exe)
		key := u.Kind + "|" + firstNonEmpty(u.App, fmt.Sprint(u.PID))
		if prev, ok := d.active[key]; ok {
			u.Since = prev.Since
		} else {
			if u.Since.IsZero() {
				u.Since = now
			}
			d.recent = append([]RecActivity{{Kind: u.Kind, App: u.App, Name: u.Name, PID: u.PID, Hidden: u.Hidden, Start: u.Since}}, d.recent...)
			if f, ok := d.useFinding(u, env.Host); ok {
				findings = append(findings, f)
			}
		}
		cur[key] = u
	}
	for key, u := range d.active {
		if _, ok := cur[key]; ok {
			continue
		}
		for i := range d.recent {
			r := &d.recent[i]
			if r.End.IsZero() && r.Kind == u.Kind && r.App == u.App && r.PID == u.PID {
				r.End = now
				break
			}
		}
	}
	d.active = cur
	if len(d.recent) > 100 {
		d.recent = d.recent[:100]
	}

	// ── recorder / remote-viewing tools ──
	tools := matchRecTools(procs)
	curTools := map[string]RecTool{}
	for i := range tools {
		t := &tools[i]
		t.Trusted = d.isTrusted(t.Exe)
		if inSuspiciousDir(t.Exe) {
			t.Warn = true
			t.Note = strings.TrimPrefix(t.Note+" · 임시 경로에서 실행", " · ")
		}
		key := t.Exe + "|" + t.Kind
		if _, seen := d.tools[key]; !seen && !t.Trusted {
			findings = append(findings, toolFinding(*t))
		}
		curTools[key] = *t
	}
	d.tools = curTools
	recent := append([]RecActivity(nil), d.recent...)
	d.mu.Unlock()

	// ── permissions (baseline compare) ──
	if s.PermChecked {
		pf, err := d.permissionChanges(ctx, env, s.Permissions)
		if err != nil {
			return Report{}, err
		}
		findings = append(findings, pf...)
	}

	uses := make([]RecUse, 0, len(cur))
	for _, u := range cur {
		uses = append(uses, u)
	}
	sort.Slice(uses, func(i, j int) bool {
		if uses[i].Kind != uses[j].Kind {
			return uses[i].Kind < uses[j].Kind
		}
		return uses[i].Since.Before(uses[j].Since)
	})
	snap := RecordingSnapshot{At: now, Platform: Platform(), Uses: uses, Devices: s.Devices, Tools: tools,
		Permissions: s.Permissions, PermError: s.PermError, Recent: recent, Notes: s.Notes}

	return Report{Findings: findings, Summary: recSummary(snap), Checks: recChecks(snap), Snapshot: snap}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func RecKindText(kind string) string {
	switch kind {
	case RecScreen:
		return "화면"
	case RecMic:
		return "마이크"
	case RecCamera:
		return "카메라"
	case RecRemote:
		return "원격 화면"
	case "input":
		return "입력 감시"
	}
	return kind
}

func (d *recordingDetector) useFinding(u RecUse, host string) (Finding, bool) {
	if u.Trusted {
		return Finding{}, false
	}
	what := map[string]string{RecScreen: "화면을 녹화/캡처", RecMic: "마이크로 녹음", RecCamera: "카메라로 촬영"}[u.Kind]
	if what == "" {
		return Finding{}, false
	}
	who := u.Name
	if u.App != "" && u.App != u.Name {
		who += " (" + u.App + ")"
	}
	if u.PID > 0 {
		who += fmt.Sprintf(" PID %d", u.PID)
	}
	if u.Exe != "" && u.Exe != u.App {
		who += " " + u.Exe
	}
	f := Finding{Category: CategoryIntrusion, Severity: SevMedium, Source: firstNonEmpty(u.Exe, u.App, host), Key: u.Kind + "|" + firstNonEmpty(u.App, u.Exe)}
	switch {
	case u.Hidden:
		f.Rule = "rec.unattributed_capture"
		f.Severity = SevHigh
		f.Key = u.Kind + "|hidden|" + firstNonEmpty(u.Exe, fmt.Sprint(u.PID))
		f.Message = fmt.Sprintf("앱 정보를 확인할 수 없는 프로세스가 %s 중: %s — 백그라운드 도구나 숨겨진 프로그램일 수 있음", what, who)
	default:
		f.Rule = "rec." + u.Kind + "_active"
		f.Message = fmt.Sprintf("%s 중: %s", what, who)
		if inSuspiciousDir(u.Exe) {
			f.Severity = SevHigh
			f.Message += " — 임시 경로에서 실행된 프로그램"
		} else if unsigned, known := exeUnsigned(u.Exe); known && unsigned {
			f.Severity = SevHigh
			f.Message += " — 서명되지 않은 프로그램"
		}
	}
	if u.Note != "" {
		f.Message += " (" + u.Note + ")"
	}
	return f, true
}

func toolFinding(t RecTool) Finding {
	sev := SevMedium
	if t.Warn {
		sev = SevHigh
	}
	msg := fmt.Sprintf("%s 도구 실행 중: %s (PID %d, %s)", RecKindText(t.Kind), t.Label, t.PID, t.Exe)
	if t.Kind == RecRemote {
		msg = fmt.Sprintf("원격 화면 보기/제어 도구 실행 중: %s (PID %d, %s) — 직접 연결한 것이 아니라면 원격 지원 사기·원격 제어 악성코드 의심", t.Label, t.PID, t.Exe)
	}
	if t.Note != "" {
		msg += " — " + t.Note
	}
	return Finding{Rule: "rec.tool_running", Category: CategoryIntrusion, Severity: sev, Source: t.Exe, Key: t.Kind + "|" + t.Exe, Message: msg}
}

func (d *recordingDetector) permissionChanges(ctx context.Context, env *Env, perms []RecPermission) ([]Finding, error) {
	cur := map[string]bool{}
	for _, p := range perms {
		cur[p.Service+"|"+p.Client] = p.Allowed
	}
	var prev map[string]bool
	found, err := env.State.Load(ctx, "permissions", &prev)
	if err != nil {
		return nil, err
	}
	var out []Finding
	if found {
		for _, p := range perms {
			k := p.Service + "|" + p.Client
			if !p.Allowed || prev[k] || d.isTrusted(p.Client) {
				continue
			}
			sev := SevMedium
			msg := fmt.Sprintf("%s 권한이 새로 허용됨: %s", RecKindText(p.Service), p.Client)
			if p.Warn {
				sev = SevHigh
			}
			if p.Note != "" {
				msg += " — " + p.Note
			}
			out = append(out, Finding{Rule: "rec.permission_granted", Category: CategoryIntrusion, Severity: sev, Source: p.Client, Key: k, Message: msg})
		}
	}
	if err := env.State.Save(ctx, "permissions", cur); err != nil {
		return nil, err
	}
	return out, nil
}

func recSummary(s RecordingSnapshot) string {
	var parts []string
	for _, k := range []string{RecScreen, RecMic, RecCamera} {
		n := 0
		for _, u := range s.Uses {
			if u.Kind == k {
				n++
			}
		}
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", RecKindText(k), n))
		}
	}
	out := "녹화/녹음 없음"
	if len(parts) > 0 {
		out = "사용 중: " + strings.Join(parts, ", ")
	}
	if len(s.Tools) > 0 {
		out += fmt.Sprintf(" · 녹화/원격 도구 %d개", len(s.Tools))
	}
	return out
}

func recChecks(s RecordingSnapshot) []Check {
	var checks []Check
	for _, k := range []string{RecScreen, RecMic, RecCamera} {
		var who []string
		st := CheckOK
		for _, u := range s.Uses {
			if u.Kind != k {
				continue
			}
			who = append(who, u.Name)
			if !u.Trusted && st == CheckOK {
				st = CheckWarn
			}
			if u.Hidden {
				st = CheckFail
			}
		}
		detail := "사용 안 함"
		if len(who) > 0 {
			detail = "사용 중: " + joinLimit(who, 5)
		}
		checks = append(checks, Check{Name: RecKindText(k), Status: st, Detail: detail})
	}
	for _, dev := range s.Devices {
		if dev.InUse {
			checks = append(checks, Check{Name: RecKindText(dev.Kind) + " 장치 · " + dev.Name, Status: CheckWarn, Detail: "사용 중"})
		}
	}
	for _, t := range s.Tools {
		st := CheckWarn
		if t.Warn {
			st = CheckFail
		} else if t.Trusted {
			st = CheckOK
		}
		checks = append(checks, Check{Name: RecKindText(t.Kind) + " 도구 · " + t.Label, Status: st, Detail: fmt.Sprintf("PID %d %s", t.PID, t.Exe)})
	}
	if s.PermError != "" {
		checks = append(checks, Check{Name: "녹화 권한 목록", Status: CheckWarn, Detail: "확인 불가: " + s.PermError})
	} else if len(s.Permissions) > 0 {
		n := 0
		for _, p := range s.Permissions {
			if p.Allowed {
				n++
			}
		}
		checks = append(checks, Check{Name: "녹화 권한 목록", Status: CheckOK, Detail: fmt.Sprintf("허용된 앱 %d개", n)})
	}
	for _, n := range s.Notes {
		checks = append(checks, Check{Name: "수집 제한", Status: CheckWarn, Detail: n})
	}
	return checks
}

// recToolDef identifies a screen/audio recorder or remote-viewing tool by the
// executable name (lowercase base name, or prefix when it ends with "*").
type recToolDef struct {
	Kind  string
	Label string
	Names []string
	Args  *regexp.Regexp // when set, the command line must match too
	Note  string
}

var recToolDefs = []recToolDef{
	// screen recorders
	{Kind: RecScreen, Label: "OBS Studio", Names: []string{"obs", "obs64"}},
	{Kind: RecScreen, Label: "ffmpeg 화면 캡처", Names: []string{"ffmpeg"}, Args: regexp.MustCompile(`(?i)-f\s+(avfoundation|x11grab|kmsgrab|gdigrab|lavfi\s+.*ddagrab)`)},
	{Kind: RecScreen, Label: "screencapture 동영상", Names: []string{"screencapture"}, Args: regexp.MustCompile(`(?:^|\s)-[a-zA-Z]*[vV]`)},
	{Kind: RecScreen, Label: "Loom", Names: []string{"loom"}},
	{Kind: RecScreen, Label: "Kap", Names: []string{"kap"}},
	{Kind: RecScreen, Label: "CleanShot X", Names: []string{"cleanshot x"}},
	{Kind: RecScreen, Label: "ScreenFlow", Names: []string{"screenflow"}},
	{Kind: RecScreen, Label: "Camtasia", Names: []string{"camtasia*"}},
	{Kind: RecScreen, Label: "Snagit", Names: []string{"snagit*"}},
	{Kind: RecScreen, Label: "SimpleScreenRecorder", Names: []string{"simplescreenrecorder"}},
	{Kind: RecScreen, Label: "Kazam", Names: []string{"kazam"}},
	{Kind: RecScreen, Label: "recordMyDesktop", Names: []string{"recordmydesktop"}},
	{Kind: RecScreen, Label: "vokoscreen", Names: []string{"vokoscreen", "vokoscreenng"}},
	{Kind: RecScreen, Label: "Peek", Names: []string{"peek"}},
	{Kind: RecScreen, Label: "wf-recorder", Names: []string{"wf-recorder"}},
	{Kind: RecScreen, Label: "gpu-screen-recorder", Names: []string{"gpu-screen-recorder"}},
	{Kind: RecScreen, Label: "Kooha", Names: []string{"kooha"}},
	{Kind: RecScreen, Label: "byzanz", Names: []string{"byzanz-record"}},
	// audio recorders
	{Kind: RecMic, Label: "ffmpeg 오디오 녹음", Names: []string{"ffmpeg"}, Args: regexp.MustCompile(`(?i)-f\s+(pulse|alsa|jack|pipewire)\b`)},
	{Kind: RecMic, Label: "arecord", Names: []string{"arecord"}},
	{Kind: RecMic, Label: "parecord", Names: []string{"parecord", "parec"}},
	{Kind: RecMic, Label: "pw-record", Names: []string{"pw-record"}},
	{Kind: RecMic, Label: "sox rec", Names: []string{"rec"}},
	{Kind: RecMic, Label: "Audio Hijack", Names: []string{"audio hijack"}},
	{Kind: RecMic, Label: "Piezo", Names: []string{"piezo"}},
	// remote viewing / control
	{Kind: RecRemote, Label: "macOS 화면 공유 (접속 중)", Names: []string{"screensharingd"}},
	{Kind: RecRemote, Label: "AnyDesk", Names: []string{"anydesk"}},
	{Kind: RecRemote, Label: "TeamViewer", Names: []string{"teamviewer", "teamviewerd", "teamviewer_desktop"}},
	{Kind: RecRemote, Label: "RustDesk", Names: []string{"rustdesk"}},
	{Kind: RecRemote, Label: "Chrome 원격 데스크톱", Names: []string{"remoting_me2me_host", "remoting_host", "chrome-remote-desktop-host"}},
	{Kind: RecRemote, Label: "Splashtop", Names: []string{"splashtop*", "srstreamer"}},
	{Kind: RecRemote, Label: "ScreenConnect", Names: []string{"screenconnect*", "connectwisecontrol*"}},
	{Kind: RecRemote, Label: "x11vnc", Names: []string{"x11vnc"}},
	{Kind: RecRemote, Label: "wayvnc", Names: []string{"wayvnc"}},
	{Kind: RecRemote, Label: "vino", Names: []string{"vino-server"}},
	{Kind: RecRemote, Label: "krfb", Names: []string{"krfb"}},
	{Kind: RecRemote, Label: "xrdp", Names: []string{"xrdp"}},
}

func (t recToolDef) matches(name, args string) bool {
	hit := false
	for _, n := range t.Names {
		if p, ok := strings.CutSuffix(n, "*"); ok {
			hit = hit || strings.HasPrefix(name, p)
		} else {
			hit = hit || name == n
		}
	}
	return hit && (t.Args == nil || t.Args.MatchString(args))
}

// matchRecTools finds running recorder / remote-viewing tools. One entry per
// (exe, kind): helper processes of the same app are folded together.
func matchRecTools(procs []proc) []RecTool {
	var out []RecTool
	seen := map[string]bool{}
	for _, p := range procs {
		name := strings.ToLower(strings.TrimSuffix(baseName(p.Exe), " (deleted)"))
		for _, def := range recToolDefs {
			if !def.matches(name, p.Args) {
				continue
			}
			key := p.Exe + "|" + def.Kind
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, RecTool{Kind: def.Kind, Label: def.Label, PID: p.PID, User: p.User, Exe: p.Exe, Args: p.Args, Note: def.Note})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Label < out[j].Label
	})
	return out
}
