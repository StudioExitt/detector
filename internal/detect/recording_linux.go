package detect

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// linuxRecSource: Linux has no system-wide capture indicator, so
//   - microphone: ALSA capture substreams in state RUNNING (/proc/asound) and,
//     when reachable, PulseAudio/PipeWire source outputs (pactl)
//   - camera: processes holding /dev/video* open (/proc/<pid>/fd)
//   - screen: only from recorder / remote-viewing processes (common tool list)
type linuxRecSource struct{}

func newRecSource() recSource { return linuxRecSource{} }

func (linuxRecSource) Start(context.Context, *Env) {}

func (linuxRecSource) Sample(ctx context.Context) (recSample, error) {
	var out recSample
	mics, uses := alsaCapture()
	out.Devices = append(out.Devices, mics...)
	out.Uses = append(out.Uses, uses...)
	out.Uses = append(out.Uses, pulseSourceOutputs(ctx)...)

	cams, camUses := videoDevices()
	out.Devices = append(out.Devices, cams...)
	out.Uses = append(out.Uses, camUses...)
	if os.Geteuid() != 0 {
		out.Notes = append(out.Notes, "root 가 아니면 다른 사용자 프로세스의 카메라 사용은 확인할 수 없음")
	}
	out.Notes = append(out.Notes, "Linux 는 화면 캡처를 OS 가 알려주지 않음 — 화면 녹화는 녹화/원격 도구 프로세스로만 판단")
	return out, nil
}

var reALSAOwner = regexp.MustCompile(`owner_pid\s*:\s*(\d+)`)

// alsaCapture lists capture PCM devices and the processes recording from them.
// With PipeWire/PulseAudio the owner is the sound server, not the real app.
func alsaCapture() ([]AVDevice, []RecUse) {
	pcms, _ := filepath.Glob("/proc/asound/card*/pcm*c")
	var devs []AVDevice
	var uses []RecUse
	for _, pcm := range pcms {
		name := strings.TrimSpace(infoField(pcm+"/info", "name"))
		if name == "" {
			name = filepath.Base(filepath.Dir(pcm)) + "/" + filepath.Base(pcm)
		}
		dev := AVDevice{Name: name, Kind: RecMic}
		subs, _ := filepath.Glob(pcm + "/sub*/status")
		for _, st := range subs {
			b, err := os.ReadFile(st)
			if err != nil || !strings.Contains(string(b), "state: RUNNING") {
				continue
			}
			dev.InUse = true
			if m := reALSAOwner.FindStringSubmatch(string(b)); m != nil {
				pid, _ := strconv.Atoi(m[1])
				exe, _ := os.Readlink("/proc/" + m[1] + "/exe")
				u := RecUse{Kind: RecMic, App: baseName(exe), PID: pid, Exe: exe}
				switch baseName(exe) {
				case "pipewire", "pulseaudio", "wireplumber", "jackd":
					u.Note = "사운드 서버 경유 — 실제 녹음 앱은 pactl 결과 참고"
				}
				uses = append(uses, u)
			}
		}
		devs = append(devs, dev)
	}
	return devs, uses
}

func infoField(path, key string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(b)) {
		if v, ok := strings.CutPrefix(line, key+":"); ok {
			return v
		}
	}
	return ""
}

var rePulseProp = regexp.MustCompile(`^\s*(application\.name|application\.process\.id|application\.process\.binary) = "(.*)"`)

// pulseSourceOutputs lists recording streams of the sound server (only
// reachable from the desktop user's session).
func pulseSourceOutputs(ctx context.Context) []RecUse {
	out, err := runCmd(ctx, 5*time.Second, "pactl", "list", "source-outputs")
	if err != nil {
		return nil
	}
	var uses []RecUse
	var cur *RecUse
	for line := range strings.Lines(out) {
		if strings.HasPrefix(line, "Source Output #") {
			uses = append(uses, RecUse{Kind: RecMic, Note: "pactl source-output"})
			cur = &uses[len(uses)-1]
			continue
		}
		m := rePulseProp.FindStringSubmatch(line)
		if cur == nil || m == nil {
			continue
		}
		switch m[1] {
		case "application.name":
			cur.Name = m[2]
		case "application.process.id":
			cur.PID, _ = strconv.Atoi(m[2])
		case "application.process.binary":
			cur.App = m[2]
		}
	}
	// skip level meters / monitors of the desktop itself
	var kept []RecUse
	for _, u := range uses {
		if u.App == "" {
			u.App = u.Name
		}
		if u.App != "" {
			kept = append(kept, u)
		}
	}
	return kept
}

// videoDevices lists V4L2 devices and the processes that have them open.
func videoDevices() ([]AVDevice, []RecUse) {
	nodes, _ := filepath.Glob("/dev/video*")
	if len(nodes) == 0 {
		return nil, nil
	}
	names := map[string]string{}
	for _, n := range nodes {
		b, _ := os.ReadFile("/sys/class/video4linux/" + filepath.Base(n) + "/name")
		names[n] = strings.TrimSpace(string(b))
	}
	inUse := map[string]bool{}
	var uses []RecUse
	fds, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	seen := map[string]bool{}
	for _, fd := range fds {
		target, err := os.Readlink(fd)
		if err != nil || !strings.HasPrefix(target, "/dev/video") {
			continue
		}
		pidStr := strings.Split(fd, "/")[2]
		if seen[pidStr+target] {
			continue
		}
		seen[pidStr+target] = true
		inUse[target] = true
		pid, _ := strconv.Atoi(pidStr)
		exe, _ := os.Readlink("/proc/" + pidStr + "/exe")
		uses = append(uses, RecUse{Kind: RecCamera, App: baseName(exe), PID: pid, Exe: exe, Note: orNone(names[target])})
	}
	var devs []AVDevice
	for _, n := range nodes {
		name := names[n]
		if name == "" {
			name = n
		}
		devs = append(devs, AVDevice{Name: name + " (" + n + ")", Kind: RecCamera, InUse: inUse[n]})
	}
	return devs, uses
}
