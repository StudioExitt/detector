package detect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"detector/internal/config"
)

// USB device kinds (from the USB device / interface classes).
const (
	UsbStorage  = "storage"  // mass storage (a disk the OS mounts)
	UsbMTP      = "mtp"      // phone / camera file transfer (MTP/PTP, still image class)
	UsbKeyboard = "keyboard" // HID keyboard (BadUSB devices pose as keyboards)
	UsbMouse    = "mouse"
	UsbHID      = "hid"
	UsbNetwork  = "network" // CDC ethernet / RNDIS / wireless adapters
	UsbSerial   = "serial"
	UsbAudio    = "audio"
	UsbVideo    = "video"
	UsbHub      = "hub"
	UsbOther    = "other"
)

// UsbSnapshot is the current USB device / external disk state.
type UsbSnapshot struct {
	At       time.Time
	Platform string
	Root     bool // running as root (other users' processes are visible / killable)
	Devices  []UsbDevice
	Disks    []UsbDisk
	Recent   []UsbActivity // connects, disconnects and actions since process start, newest first
	Notes    []string
}

// UsbDevice is one connected USB device (hubs excluded).
type UsbDevice struct {
	ID        string // stable for the connection (macOS: usb-<locationID>, Linux: usb-<sysfs name>)
	Name      string
	Vendor    string
	Serial    string
	VendorID  int
	ProductID int
	Speed     string
	Kinds     []string
	Disks     []string  // whole-disk names backed by this device (disk4 / sdb)
	Clients   []UsbProc // processes holding the USB device itself open (MTP apps, libusb ...)
	Trusted   bool
	Known     bool      // seen before (persisted baseline)
	Since     time.Time // first seen connected by this process
}

// UsbDisk is an external disk (USB stick, external SSD, SD card ...).
type UsbDisk struct {
	Disk       string // disk4 / sdb
	DeviceID   string // UsbDevice.ID ("" when not attached through USB, e.g. Thunderbolt)
	Name       string
	Bus        string
	Size       uint64
	Removable  bool
	Volumes    []UsbVolume
	Occupants  []UsbProc // processes with files open on the disk (or the raw device)
	ReadBytes  uint64    // cumulative since connect (0 when unknown)
	WriteBytes uint64
	WriteBps   float64 // since the previous run
	Write10m   uint64  // bytes written during the last 10 minutes
	StatsKnown bool
	Trusted    bool
}

type UsbVolume struct {
	ID         string // disk4s1 / sdb1
	Name       string
	MountPoint string // "" when not mounted
	FS         string
	Size       uint64
	Free       uint64
	ReadOnly   bool
}

// UsbProc is a process using a USB device or disk.
type UsbProc struct {
	PID    int
	Name   string
	User   string
	Exe    string
	Files  []string // sample of open paths (max 5)
	Count  int      // open files on the disk
	System bool     // indexing / OS service (Spotlight, fseventsd, udisks ...) — usually harmless
}

type UsbActivity struct {
	At     time.Time
	Kind   string // connect / disconnect / eject / force_eject / kill
	Target string
	Detail string
	OK     bool
}

// UsbStep is one step of a release / eject action.
type UsbStep struct {
	Action string // kill / eject / unmount / force_unmount / power_off
	Target string
	OK     bool
	Detail string
}

type UsbActionResult struct {
	OK    bool
	Steps []UsbStep
}

// ErrUsbTarget is returned when the requested disk / device is not connected.
var ErrUsbTarget = errors.New("USB device or disk not found")

type usbSample struct {
	Devices []UsbDevice
	Disks   []UsbDisk
	Notes   []string
}

type usbSource interface {
	Sample(ctx context.Context) (usbSample, error)
}

// usbActor is implemented by the usb detector (actions requested via the API).
type usbActor interface {
	UsbRelease(ctx context.Context, target string, pids []int, hard, eject bool) (UsbActionResult, []Finding, error)
	UsbEject(ctx context.Context, disk string, force bool) (UsbActionResult, []Finding, error)
	UsbTransferred(target, detail string, ok bool) (UsbActionResult, []Finding, error)
}

type usbWritePoint struct {
	At    time.Time
	Bytes uint64 // disk write counter
	Other uint64 // counter minus what this server wrote itself (file transfers from the web UI)
}

// bytes the server itself wrote to external disks (by disk name), so its own
// transfers don't raise usb.bulk_write
var usbSelf = struct {
	sync.Mutex
	m map[string]uint64
}{m: map[string]uint64{}}

// NoteUsbSelfWrite records n bytes written by this server to an external disk.
func NoteUsbSelfWrite(disk string, n uint64) {
	usbSelf.Lock()
	usbSelf.m[disk] += n
	usbSelf.Unlock()
}

func usbSelfWritten(disk string) uint64 {
	usbSelf.Lock()
	defer usbSelf.Unlock()
	return usbSelf.m[disk]
}

// usbDetector reports USB devices / disks being connected, devices never seen
// before (a new keyboard may be a BadUSB key injector), and bulk copies to
// external disks. It also performs eject / release actions for the web UI.
type usbDetector struct {
	cfg     config.UsbDetectConfig
	src     usbSource
	trusted []string

	actMu sync.Mutex // one action at a time

	mu      sync.Mutex
	present map[string]UsbDevice // id -> device
	disks   map[string]bool      // disk key -> present
	writes  map[string][]usbWritePoint
	known   map[string]string // signature -> first seen (RFC3339)
	loaded  bool              // known was loaded from state
	hadBase bool              // a baseline existed before this process
	recent  []UsbActivity
}

func newUsbDetector(cfg config.UsbDetectConfig) Detector {
	src := newUsbSource()
	if src == nil {
		return nil
	}
	var trusted []string
	for _, t := range cfg.TrustedDevices {
		trusted = append(trusted, strings.ToLower(strings.TrimSpace(t)))
	}
	return &usbDetector{cfg: cfg, src: src, trusted: trusted, present: map[string]UsbDevice{}, disks: map[string]bool{},
		writes: map[string][]usbWritePoint{}, known: map[string]string{}}
}

func (d *usbDetector) Name() string { return "usb" }

// usbSignature identifies a device across connections.
func usbSignature(dev UsbDevice) string {
	id := dev.Serial
	if id == "" {
		id = dev.Name
	}
	return fmt.Sprintf("%04x:%04x|%s", dev.VendorID, dev.ProductID, id)
}

func (d *usbDetector) isTrusted(dev UsbDevice) bool {
	vp := fmt.Sprintf("%04x:%04x", dev.VendorID, dev.ProductID)
	for _, v := range []string{dev.Serial, vp, dev.Name} {
		if v != "" && slices.Contains(d.trusted, strings.ToLower(v)) {
			return true
		}
	}
	return false
}

func diskKey(k UsbDisk) string { return k.DeviceID + "|" + k.Disk }

func (d *usbDetector) Check(ctx context.Context, env *Env) (Report, error) {
	s, err := d.src.Sample(ctx)
	if err != nil {
		return Report{}, err
	}
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.loaded {
		found, err := env.State.Load(ctx, "known", &d.known)
		if err != nil {
			return Report{}, err
		}
		if d.known == nil {
			d.known = map[string]string{}
		}
		d.loaded, d.hadBase = true, found
	}

	var findings []Finding
	knownChanged := false
	byID := map[string]*UsbDevice{}
	cur := map[string]UsbDevice{}
	for i := range s.Devices {
		dev := &s.Devices[i]
		byID[dev.ID] = dev
		sig := usbSignature(*dev)
		_, dev.Known = d.known[sig]
		dev.Trusted = d.isTrusted(*dev)
		prev, wasPresent := d.present[dev.ID]
		if wasPresent && usbSignature(prev) == sig {
			dev.Since = prev.Since
		} else {
			dev.Since = now
			if !env.FirstRun {
				d.addRecent(UsbActivity{At: now, Kind: "connect", Target: dev.Name, Detail: usbDevDesc(*dev), OK: true})
			}
			if f, ok := d.connectFinding(*dev, env.FirstRun); ok {
				findings = append(findings, f)
			}
		}
		if !dev.Known {
			d.known[sig] = now.UTC().Format(time.RFC3339)
			knownChanged = true
		}
		cur[dev.ID] = *dev
	}
	for id, dev := range d.present {
		if _, ok := cur[id]; !ok {
			d.addRecent(UsbActivity{At: now, Kind: "disconnect", Target: dev.Name, Detail: usbDevDesc(dev), OK: true})
		}
	}
	d.present = cur

	// ── disks: write volume ──
	curDisks := map[string]bool{}
	for i := range s.Disks {
		k := &s.Disks[i]
		key := diskKey(*k)
		curDisks[key] = true
		if dev := byID[k.DeviceID]; dev != nil {
			k.Trusted = dev.Trusted
		}
		if !k.StatsKnown {
			continue
		}
		other := k.WriteBytes - min(k.WriteBytes, usbSelfWritten(k.Disk))
		pts := d.writes[key]
		if n := len(pts); n > 0 && (k.WriteBytes < pts[n-1].Bytes || other < pts[n-1].Other) {
			pts = nil // counter reset (reconnected under the same name)
		}
		if n := len(pts); n > 0 {
			if dt := now.Sub(pts[n-1].At).Seconds(); dt > 0 {
				k.WriteBps = float64(k.WriteBytes-pts[n-1].Bytes) / dt
			}
		}
		pts = append(pts, usbWritePoint{At: now, Bytes: k.WriteBytes, Other: other})
		for len(pts) > 1 && now.Sub(pts[1].At) >= 10*time.Minute {
			pts = pts[1:]
		}
		d.writes[key] = pts
		k.Write10m = other - pts[0].Other // the server's own transfers excluded
		if limit := uint64(d.cfg.WriteMB * 1024 * 1024); limit > 0 && k.Write10m >= limit && !k.Trusted {
			findings = append(findings, bulkWriteFinding(*k))
		}
	}
	for key := range d.writes {
		if !curDisks[key] {
			delete(d.writes, key)
		}
	}
	if !env.FirstRun {
		names := map[string]bool{}
		for _, k := range s.Disks {
			names[k.Disk] = true
		}
		usbSelf.Lock()
		for disk := range usbSelf.m {
			if !names[disk] {
				delete(usbSelf.m, disk) // disconnected: counters restart on reconnect
			}
		}
		usbSelf.Unlock()
	}
	d.disks = curDisks

	if knownChanged {
		if err := env.State.Save(ctx, "known", d.known); err != nil {
			return Report{}, err
		}
	}

	devices := make([]UsbDevice, 0, len(cur))
	for _, dev := range cur {
		devices = append(devices, dev)
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Since.Equal(devices[j].Since) {
			return devices[i].ID < devices[j].ID
		}
		return devices[i].Since.After(devices[j].Since)
	})
	snap := UsbSnapshot{At: now, Platform: Platform(), Root: os.Geteuid() == 0, Devices: devices, Disks: s.Disks,
		Recent: append([]UsbActivity(nil), d.recent...), Notes: s.Notes}
	if !snap.Root {
		snap.Notes = append(snap.Notes, "root 가 아니어서 다른 사용자(시스템) 프로세스의 점유는 보이지 않거나 종료할 수 없음")
	}
	metrics := map[string]float64{"usb.devices": float64(len(devices)), "usb.disks": float64(len(s.Disks))}
	var wbps float64
	for _, k := range s.Disks {
		wbps += k.WriteBps
	}
	metrics["usb.write_bps"] = wbps
	return Report{Findings: findings, Summary: usbSummary(snap), Checks: usbChecks(snap), Snapshot: snap, Metrics: metrics}, nil
}

func (d *usbDetector) addRecent(a UsbActivity) {
	d.recent = append([]UsbActivity{a}, d.recent...)
	if len(d.recent) > 100 {
		d.recent = d.recent[:100]
	}
}

// usbClassKind maps a USB device / interface class to a kind ("" = ignore).
func usbClassKind(class, sub, proto int64) string {
	switch class {
	case 0x01:
		return UsbAudio
	case 0x02:
		if sub == 0x02 {
			return UsbSerial // ACM modem / serial
		}
		return UsbNetwork // ECM / NCM / EEM
	case 0x03:
		switch {
		case sub == 1 && proto == 1:
			return UsbKeyboard
		case sub == 1 && proto == 2:
			return UsbMouse
		}
		return UsbHID
	case 0x06:
		return UsbMTP
	case 0x08:
		return UsbStorage
	case 0x0e:
		return UsbVideo
	case 0xe0:
		return UsbNetwork // wireless controller (RNDIS, Bluetooth)
	}
	return ""
}

func usbDevDesc(dev UsbDevice) string {
	parts := []string{fmt.Sprintf("%04x:%04x", dev.VendorID, dev.ProductID)}
	if dev.Vendor != "" {
		parts = append(parts, dev.Vendor)
	}
	if dev.Serial != "" {
		parts = append(parts, "시리얼 "+dev.Serial)
	}
	if len(dev.Kinds) > 0 {
		var ks []string
		for _, k := range dev.Kinds {
			ks = append(ks, UsbKindText(k))
		}
		parts = append(parts, strings.Join(ks, "/"))
	}
	return strings.Join(parts, ", ")
}

func UsbKindText(kind string) string {
	switch kind {
	case UsbStorage:
		return "저장장치"
	case UsbMTP:
		return "휴대폰·카메라(MTP/PTP)"
	case UsbKeyboard:
		return "키보드"
	case UsbMouse:
		return "마우스"
	case UsbHID:
		return "입력장치(HID)"
	case UsbNetwork:
		return "네트워크"
	case UsbSerial:
		return "시리얼"
	case UsbAudio:
		return "오디오"
	case UsbVideo:
		return "카메라(UVC)"
	case UsbHub:
		return "허브"
	}
	return "기타"
}

// connectFinding: storage / phone connected, or a device never seen before.
// On the first run only devices missing from an existing baseline are reported.
func (d *usbDetector) connectFinding(dev UsbDevice, firstRun bool) (Finding, bool) {
	// first run: devices already connected become the baseline, unless a
	// baseline exists and this device was connected while the server was down
	if dev.Trusted || (firstRun && (dev.Known || !d.hadBase)) {
		return Finding{}, false
	}
	has := func(k string) bool { return slices.Contains(dev.Kinds, k) }
	who := fmt.Sprintf("%s (%s)", orNone(dev.Name), usbDevDesc(dev))
	f := Finding{Category: CategoryIntrusion, Source: firstNonEmpty(dev.Serial, dev.Name, dev.ID), Key: usbSignature(dev)}
	newTag := ""
	if !dev.Known {
		newTag = "처음 보는 "
	}
	switch {
	case has(UsbKeyboard) && !dev.Known:
		f.Rule, f.Severity = "usb.new_keyboard", SevHigh
		f.Message = "처음 보는 USB 키보드 연결: " + who + " — 직접 연결한 키보드가 아니라면 키 입력을 주입하는 BadUSB 장치일 수 있음"
		if has(UsbStorage) {
			f.Message += " (저장장치 기능도 함께 가진 장치)"
		}
	case has(UsbStorage):
		f.Rule, f.Severity = "usb.storage_connected", SevLow
		if !dev.Known {
			f.Severity = SevMedium
		}
		f.Message = newTag + "USB 저장장치 연결: " + who
		if len(dev.Disks) > 0 {
			f.Message += " → " + strings.Join(dev.Disks, ", ")
		}
	case has(UsbMTP):
		f.Rule, f.Severity = "usb.mtp_connected", SevLow
		if !dev.Known {
			f.Severity = SevMedium
		}
		f.Message = newTag + "휴대폰/카메라 연결 (MTP/PTP 파일 전송 가능): " + who
	case !dev.Known:
		f.Rule, f.Severity = "usb.new_device", SevLow
		f.Message = "처음 보는 USB 장치 연결: " + who
	default:
		return Finding{}, false
	}
	return f, true
}

func bulkWriteFinding(k UsbDisk) Finding {
	var who []string
	for _, p := range k.Occupants {
		if !p.System {
			who = append(who, fmt.Sprintf("%s(PID %d)", p.Name, p.PID))
		}
	}
	msg := fmt.Sprintf("외장 디스크로 대량 쓰기: %s (%s) 최근 10분간 %s", orNone(k.Name), k.Disk, humanBytes(k.Write10m))
	if len(who) > 0 {
		msg += " — 사용 중인 프로세스: " + joinLimit(who, 5)
	}
	msg += " · 허가되지 않은 복사라면 데이터 유출 의심"
	return Finding{Rule: "usb.bulk_write", Category: CategoryIntrusion, Severity: SevHigh, Source: k.Disk, Key: diskKey(k), Message: msg}
}

func usbSummary(s UsbSnapshot) string {
	busy := 0
	for _, k := range s.Disks {
		if len(k.Occupants) > 0 {
			busy++
		}
	}
	out := fmt.Sprintf("USB 장치 %d개 · 외장 디스크 %d개", len(s.Devices), len(s.Disks))
	if busy > 0 {
		out += fmt.Sprintf(" (사용 중 %d)", busy)
	}
	return out
}

func usbChecks(s UsbSnapshot) []Check {
	var checks []Check
	for _, dev := range s.Devices {
		st := CheckOK
		if !dev.Known && !dev.Trusted {
			st = CheckWarn
		}
		detail := usbDevDesc(dev)
		if len(dev.Clients) > 0 {
			var names []string
			for _, p := range dev.Clients {
				names = append(names, fmt.Sprintf("%s(%d)", p.Name, p.PID))
			}
			detail += " · 사용 중: " + joinLimit(names, 5)
		}
		checks = append(checks, Check{Name: "USB · " + orNone(dev.Name), Status: st, Detail: detail})
	}
	for _, k := range s.Disks {
		st, detail := CheckOK, "사용 중인 프로세스 없음"
		var names []string
		for _, p := range k.Occupants {
			names = append(names, fmt.Sprintf("%s(%d)", p.Name, p.PID))
			if !p.System {
				st = CheckWarn
			}
		}
		if len(names) > 0 {
			detail = "사용 중: " + joinLimit(names, 5)
		}
		if k.Write10m > 0 {
			detail += " · 10분간 쓰기 " + humanBytes(k.Write10m)
		}
		checks = append(checks, Check{Name: "디스크 · " + k.Disk + " " + k.Name, Status: st, Detail: detail})
	}
	for _, n := range s.Notes {
		checks = append(checks, Check{Name: "수집 제한", Status: CheckWarn, Detail: n})
	}
	return checks
}

// ── actions ──

var usbSystemProcs = []string{"mds", "mds_stores", "mdworker", "mdworker_shared", "mdsync", "fseventsd", "quicklookd",
	"quicklookuiservice", "revisiond", "diskarbitrationd", "deleted", "kernel_task", "spotlightknowledged", "photoanalysisd",
	"ptpcamerad", "icdd", "udisksd", "systemd-udevd", "tracker-miner-fs", "tracker-miner-fs-3", "gvfsd", "gvfs-udisks2-volume-monitor", "baloo_file"}

// isUsbSystemProc reports OS services that touch every mounted volume.
func isUsbSystemProc(name string) bool {
	n := strings.ToLower(name)
	return slices.Contains(usbSystemProcs, n) || strings.HasPrefix(n, "mdworker") || strings.HasPrefix(n, "gvfsd")
}

var usbProtectedProcs = []string{"launchd", "kernel_task", "windowserver", "loginwindow", "systemd", "init"}

// UsbRelease terminates processes occupying a disk / USB device (all of them,
// or only pids), optionally escalating to SIGKILL, then optionally ejects.
func (d *usbDetector) UsbRelease(ctx context.Context, target string, pids []int, hard, eject bool) (UsbActionResult, []Finding, error) {
	d.actMu.Lock()
	defer d.actMu.Unlock()
	s, err := d.src.Sample(ctx)
	if err != nil {
		return UsbActionResult{}, nil, err
	}
	var holders []UsbProc
	var disks []UsbDisk
	found := false
	for _, k := range s.Disks {
		if k.Disk == target {
			found = true
			holders = append(holders, k.Occupants...)
			disks = append(disks, k)
		}
	}
	for _, dev := range s.Devices {
		if dev.ID != target {
			continue
		}
		found = true
		holders = append(holders, dev.Clients...)
		for _, k := range s.Disks {
			if k.DeviceID == dev.ID {
				holders = append(holders, k.Occupants...)
				disks = append(disks, k)
			}
		}
	}
	if !found {
		return UsbActionResult{}, nil, fmt.Errorf("%w: %s", ErrUsbTarget, target)
	}
	byPID := map[int]UsbProc{}
	for _, p := range holders {
		byPID[p.PID] = p
	}

	res := UsbActionResult{OK: true}
	want := pids
	if len(want) == 0 {
		want = sortedPIDs(byPID)
	}
	var killed []string
	for _, pid := range want {
		p, ok := byPID[pid]
		step := UsbStep{Action: "kill", Target: fmt.Sprintf("PID %d", pid)}
		switch {
		case !ok:
			step.Detail = "이 장치를 사용 중인 프로세스가 아님 (이미 종료되었을 수 있음)"
		case pid <= 1 || pid == os.Getpid() || slices.Contains(usbProtectedProcs, strings.ToLower(p.Name)):
			step.Target += " " + p.Name
			step.Detail = "시스템 핵심 프로세스라 종료하지 않음"
		default:
			step.Target += " " + p.Name
			step.OK, step.Detail = killAndWait(pid, hard)
			if step.OK {
				killed = append(killed, fmt.Sprintf("%s(%d)", p.Name, pid))
			}
		}
		if !step.OK {
			res.OK = false
		}
		res.Steps = append(res.Steps, step)
	}
	if len(want) == 0 {
		res.Steps = append(res.Steps, UsbStep{Action: "kill", Target: target, OK: true, Detail: "사용 중인 프로세스 없음"})
	}
	if eject {
		if len(disks) == 0 {
			res.Steps = append(res.Steps, UsbStep{Action: "eject", Target: target, Detail: "꺼낼 디스크가 없는 장치"})
			res.OK = false
		}
		for _, k := range disks {
			for _, st := range usbEjectDisk(ctx, k, false) {
				res.OK = res.OK && st.OK
				res.Steps = append(res.Steps, st)
			}
		}
	}

	now := time.Now()
	detail := "종료: " + orNone(strings.Join(killed, ", "))
	if eject {
		detail += " → 꺼내기"
	}
	d.mu.Lock()
	d.addRecent(UsbActivity{At: now, Kind: "kill", Target: target, Detail: detail, OK: res.OK})
	d.mu.Unlock()
	f := Finding{Rule: "usb.action", Category: CategoryIntrusion, Severity: SevLow, Source: target,
		Key: "release|" + target + "|" + now.Format(time.RFC3339Nano),
		Message: fmt.Sprintf("사용자 요청으로 %s 점유 프로세스 종료 (%s)%s", target, map[bool]string{true: "강제", false: "정상"}[hard],
			" — "+detail+resultText(res.OK))}
	return res, []Finding{f}, nil
}

// UsbEject ejects a disk; force unmounts even with open files (may lose data being written).
func (d *usbDetector) UsbEject(ctx context.Context, disk string, force bool) (UsbActionResult, []Finding, error) {
	d.actMu.Lock()
	defer d.actMu.Unlock()
	s, err := d.src.Sample(ctx)
	if err != nil {
		return UsbActionResult{}, nil, err
	}
	idx := slices.IndexFunc(s.Disks, func(k UsbDisk) bool { return k.Disk == disk })
	if idx < 0 {
		return UsbActionResult{}, nil, fmt.Errorf("%w: %s", ErrUsbTarget, disk)
	}
	k := s.Disks[idx]
	res := UsbActionResult{OK: true, Steps: usbEjectDisk(ctx, k, force)}
	for _, st := range res.Steps {
		res.OK = res.OK && st.OK
	}
	if !res.OK && !force && len(k.Occupants) > 0 {
		var names []string
		for _, p := range k.Occupants {
			names = append(names, fmt.Sprintf("%s(PID %d)", p.Name, p.PID))
		}
		res.Steps = append(res.Steps, UsbStep{Action: "hint", Target: disk,
			Detail: "사용 중인 프로세스: " + joinLimit(names, 8) + " — 점유 종료 후 꺼내기 또는 강제 꺼내기를 사용하세요"})
	}

	now := time.Now()
	kind := "eject"
	if force {
		kind = "force_eject"
	}
	d.mu.Lock()
	d.addRecent(UsbActivity{At: now, Kind: kind, Target: disk + " " + k.Name, Detail: firstNonEmpty(lastStepDetail(res)), OK: res.OK})
	d.mu.Unlock()
	what := "꺼내기"
	if force {
		what = "강제 꺼내기 (열린 파일 무시)"
	}
	f := Finding{Rule: "usb.action", Category: CategoryIntrusion, Severity: SevLow, Source: disk,
		Key:     kind + "|" + disk + "|" + now.Format(time.RFC3339Nano),
		Message: fmt.Sprintf("사용자 요청으로 %s %s: %s%s", disk, what, orNone(k.Name), resultText(res.OK))}
	return res, []Finding{f}, nil
}

// UsbTransferred records a finished file transfer made from the web UI.
func (d *usbDetector) UsbTransferred(target, detail string, ok bool) (UsbActionResult, []Finding, error) {
	now := time.Now()
	d.mu.Lock()
	d.addRecent(UsbActivity{At: now, Kind: "transfer", Target: target, Detail: detail, OK: ok})
	d.mu.Unlock()
	f := Finding{Rule: "usb.action", Category: CategoryIntrusion, Severity: SevLow, Source: target,
		Key:     "transfer|" + target + "|" + now.Format(time.RFC3339Nano),
		Message: "사용자 요청으로 파일 전송: " + target + " — " + detail + resultText(ok)}
	return UsbActionResult{OK: ok}, []Finding{f}, nil
}

func lastStepDetail(r UsbActionResult) string {
	if len(r.Steps) == 0 {
		return ""
	}
	return r.Steps[len(r.Steps)-1].Detail
}

func resultText(ok bool) string {
	if ok {
		return " · 성공"
	}
	return " · 실패"
}

func sortedPIDs(m map[int]UsbProc) []int {
	out := make([]int, 0, len(m))
	for pid := range m {
		out = append(out, pid)
	}
	sort.Ints(out)
	return out
}

// mergeUsbProcs folds open-file records of the same process together.
func mergeUsbProcs(ps []UsbProc) []UsbProc {
	idx := map[int]int{}
	var out []UsbProc
	for _, p := range ps {
		if i, ok := idx[p.PID]; ok {
			o := &out[i]
			o.Count += p.Count
			for _, f := range p.Files {
				if len(o.Files) < 5 && !slices.Contains(o.Files, f) {
					o.Files = append(o.Files, f)
				}
			}
			continue
		}
		idx[p.PID] = len(out)
		p.System = isUsbSystemProc(p.Name)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].System != out[j].System {
			return !out[i].System
		}
		return out[i].PID < out[j].PID
	})
	return out
}

func cmdDetail(out string, err error) string {
	s := strings.Join(strings.Fields(strings.TrimSpace(out)), " ")
	if err != nil && s == "" {
		s = err.Error()
	}
	return s
}
