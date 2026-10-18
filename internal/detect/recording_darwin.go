package detect

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// darwinRecSource combines:
//   - ControlCenter "sensor-indicators" unified log (the menu bar privacy
//     indicators): which apps use the screen (scr), microphone (mic) and
//     camera (cam), plus captures macOS could not attribute to an app
//   - CoreAudio / CoreMediaIO: whether each microphone / camera is running,
//     and (macOS 14+) which processes record audio
//   - TCC databases: apps allowed to record the screen / microphone / camera
//     and monitor input (needs Full Disk Access)
type darwinRecSource struct {
	mu        sync.Mutex
	streaming bool
	streamErr string
	active    map[string]time.Time // "scr:com.app" -> start
	missed    map[string]time.Time // sessions that started and ended between samples
	names     map[string]string    // bundle id -> display name
	hidden    map[string]RecUse    // kind|pid -> unattributed capture, kept until the process exits
}

func newRecSource() recSource {
	return &darwinRecSource{active: map[string]time.Time{}, missed: map[string]time.Time{}, names: map[string]string{}, hidden: map[string]RecUse{}}
}

const sensorPredicate = `subsystem == "com.apple.controlcenter" AND category == "sensor-indicators" AND ` +
	`(eventMessage BEGINSWITH "Active activity attributions changed to" OR eventMessage BEGINSWITH "Sorted active attributions" OR eventMessage BEGINSWITH "Failed to create")`

var (
	reAttrList   = regexp.MustCompile(`"([a-z]+):([^"]+)"`)
	reAttrSorted = regexp.MustCompile(`\[\[([a-z]+)\] (.+?) \(([^()]+)\)\]?`)
	reAttrFailed = regexp.MustCompile(`^Failed to create ([a-z]+) ActivityAttribution`)
	reAuditPID   = regexp.MustCompile(`\bPID: (\d+);`)
)

var sensorKinds = map[string]string{"scr": RecScreen, "mic": RecMic, "cam": RecCamera}

func (s *darwinRecSource) Start(ctx context.Context, env *Env) {
	go s.stream(ctx, env)
}

// stream follows the sensor indicator log. It first replays the last hour so
// a capture that started before the detector is known, then follows live.
func (s *darwinRecSource) stream(ctx context.Context, env *Env) {
	if out, err := runCmd(ctx, 90*time.Second, "/usr/bin/log", "show", "--style", "ndjson", "--last", "1h", "--predicate", sensorPredicate); err == nil {
		s.consume(strings.NewReader(out), true)
	}
	backoff := 5 * time.Second
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, "/usr/bin/log", "stream", "--style", "ndjson", "--predicate", sensorPredicate)
		stdout, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			s.setStream(false, err.Error())
		} else {
			s.setStream(true, "")
			started := time.Now()
			s.consume(stdout, false)
			err = cmd.Wait()
			if time.Since(started) > time.Minute {
				backoff = 5 * time.Second
			}
			if ctx.Err() == nil {
				msg := "log stream 종료"
				if err != nil {
					msg += ": " + err.Error()
				}
				s.setStream(false, msg)
				env.Log.Warn("sensor log stream stopped", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Minute)
	}
}

func (s *darwinRecSource) setStream(on bool, errMsg string) {
	s.mu.Lock()
	s.streaming, s.streamErr = on, errMsg
	s.mu.Unlock()
}

func (s *darwinRecSource) consume(r io.Reader, replay bool) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e ulogEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.EventMessage == "" {
			continue
		}
		ts, _ := time.Parse(ulogTimeLayout, e.Timestamp)
		s.apply(e.EventMessage, ts, replay)
	}
}

func (s *darwinRecSource) apply(msg string, ts time.Time, replay bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case strings.HasPrefix(msg, "Active activity attributions changed to"):
		active := map[string]time.Time{}
		for _, m := range reAttrList.FindAllStringSubmatch(msg, -1) {
			if _, ok := sensorKinds[m[1]]; !ok {
				continue
			}
			k := m[1] + ":" + m[2]
			if t, ok := s.active[k]; ok {
				active[k] = t
			} else {
				active[k] = ts
			}
		}
		for k, t := range s.active {
			if _, ok := active[k]; !ok && !replay {
				s.missed[k] = t // reported once by the next sample even if already over
			}
		}
		s.active = active
	case strings.HasPrefix(msg, "Sorted active attributions"):
		for _, m := range reAttrSorted.FindAllStringSubmatch(msg, -1) {
			s.names[m[3]] = m[2]
		}
	default:
		m := reAttrFailed.FindStringSubmatch(msg)
		kind, ok := sensorKinds[safeIndex(m, 1)]
		if !ok {
			return
		}
		pm := reAuditPID.FindStringSubmatch(msg)
		if pm == nil {
			return
		}
		var pid int
		fmt.Sscan(pm[1], &pid)
		// a replayed entry only counts if that process is still alive
		if replay && !pidAlive(pid) {
			return
		}
		key := fmt.Sprintf("%s|%d", kind, pid)
		if _, ok := s.hidden[key]; !ok {
			s.hidden[key] = RecUse{Kind: kind, PID: pid, Hidden: true, Since: ts, Note: "macOS 가 앱 이름/경로를 확인하지 못함"}
		}
	}
}

func safeIndex(m []string, i int) string {
	if i < len(m) {
		return m[i]
	}
	return ""
}

func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, os.ErrPermission)
}

func (s *darwinRecSource) Sample(ctx context.Context) (recSample, error) {
	var out recSample

	s.mu.Lock()
	streaming, streamErr := s.streaming, s.streamErr
	for k, since := range s.active {
		code, app, _ := strings.Cut(k, ":")
		out.Uses = append(out.Uses, RecUse{Kind: sensorKinds[code], App: app, Name: s.names[app], Since: since})
	}
	for k, since := range s.missed {
		if _, ok := s.active[k]; !ok {
			code, app, _ := strings.Cut(k, ":")
			out.Uses = append(out.Uses, RecUse{Kind: sensorKinds[code], App: app, Name: s.names[app], Since: since})
		}
	}
	clear(s.missed)
	for k, u := range s.hidden {
		if !pidAlive(u.PID) {
			delete(s.hidden, k)
			continue
		}
		out.Uses = append(out.Uses, u)
	}
	s.mu.Unlock()
	if !streaming && streamErr != "" { // not yet started is fine (initial replay)
		out.Notes = append(out.Notes, "화면 녹화 표시 로그(ControlCenter) 수신 안 됨 — 화면 캡처 앱을 확인할 수 없음 ("+streamErr+")")
	}

	mics, err := listMicrophones()
	if err != nil {
		out.Notes = append(out.Notes, "마이크 상태 확인 불가: "+err.Error())
	}
	cams, err := listCameras()
	if err != nil {
		out.Notes = append(out.Notes, "카메라 상태 확인 불가: "+err.Error())
	}
	out.Devices = append(mics, cams...)

	// CoreAudio process objects attribute microphone use to a PID even when
	// the log is unavailable.
	if procs, err := audioInputProcesses(); err == nil {
		for _, p := range procs {
			if hasUse(out.Uses, RecMic, p.BundleID) {
				continue
			}
			out.Uses = append(out.Uses, RecUse{Kind: RecMic, App: p.BundleID, PID: p.PID, Name: s.names[p.BundleID]})
		}
	}
	// a running device with no attributed app (e.g. log lag or no log access)
	for _, dev := range out.Devices {
		if dev.InUse && !hasKind(out.Uses, dev.Kind) {
			out.Uses = append(out.Uses, RecUse{Kind: dev.Kind, App: "device:" + dev.Name, Name: dev.Name, Note: "장치는 사용 중이나 사용하는 앱은 확인 불가"})
		}
	}

	out.Permissions, out.PermError = tccPermissions(ctx)
	out.PermChecked = out.PermError == ""
	return out, nil
}

func hasUse(us []RecUse, kind, app string) bool {
	for _, u := range us {
		if u.Kind == kind && app != "" && u.App == app {
			return true
		}
	}
	return false
}

func hasKind(us []RecUse, kind string) bool {
	for _, u := range us {
		if u.Kind == kind {
			return true
		}
	}
	return false
}

var tccServices = map[string]string{
	"kTCCServiceScreenCapture": RecScreen,
	"kTCCServiceMicrophone":    RecMic,
	"kTCCServiceCamera":        RecCamera,
	"kTCCServiceListenEvent":   "input",
}

// tccPermissions reads the system and the login user's TCC databases.
// Reading them requires Full Disk Access for the detector binary.
func tccPermissions(ctx context.Context) ([]RecPermission, string) {
	dbs := []struct{ path, scope string }{{"/Library/Application Support/com.apple.TCC/TCC.db", "system"}}
	for _, home := range tccHomes() {
		dbs = append(dbs, struct{ path, scope string }{filepath.Join(home, "Library/Application Support/com.apple.TCC/TCC.db"), "user"})
	}
	var out []RecPermission
	var errs []string
	for _, d := range dbs {
		ps, err := readTCC(ctx, d.path, d.scope)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		out = append(out, ps...)
	}
	if len(errs) == len(dbs) {
		return nil, "TCC.db 읽기 불가 — 전체 디스크 접근 권한(Full Disk Access) 필요"
	}
	return out, ""
}

// tccHomes returns the home of the user running the detector, or every user
// home when running as root.
func tccHomes() []string {
	if os.Geteuid() != 0 {
		if u, err := user.Current(); err == nil {
			return []string{u.HomeDir}
		}
		return nil
	}
	homes, _ := filepath.Glob("/Users/*")
	var out []string
	for _, h := range homes {
		if b := filepath.Base(h); b != "Shared" && !strings.HasPrefix(b, ".") {
			out = append(out, h)
		}
	}
	return out
}

func readTCC(ctx context.Context, path, scope string) ([]RecPermission, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT service, client, client_type, auth_value, last_modified FROM access
		WHERE service IN ('kTCCServiceScreenCapture','kTCCServiceMicrophone','kTCCServiceCamera','kTCCServiceListenEvent')`)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer rows.Close()
	var out []RecPermission
	for rows.Next() {
		var svc, client string
		var ctype, auth, mod int64
		if err := rows.Scan(&svc, &client, &ctype, &auth, &mod); err != nil {
			return nil, err
		}
		p := RecPermission{Service: tccServices[svc], Client: client, Allowed: auth == 2 || auth == 3, Scope: scope, Updated: time.Unix(mod, 0)}
		if ctype == 1 { // absolute path instead of a bundle id
			switch {
			case inSuspiciousDir(client):
				p.Warn, p.Note = true, "임시 경로 프로그램"
			case isInterpreter(client):
				p.Warn, p.Note = true, "스크립트 인터프리터 — 어떤 스크립트든 이 권한을 사용할 수 있음"
			case !fileExists(client):
				p.Note = "프로그램이 삭제됨"
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
