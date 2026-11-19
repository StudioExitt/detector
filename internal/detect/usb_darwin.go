package detect

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// darwinUsbSource reads USB devices from the IORegistry (ioreg), external
// disks from diskutil and the processes using them from lsof.
type darwinUsbSource struct {
	mu   sync.Mutex
	info map[string]map[string]any // whole disk -> diskutil info (cached while connected)
}

func newUsbSource() usbSource { return &darwinUsbSource{info: map[string]map[string]any{}} }

var reWholeDisk = regexp.MustCompile(`^disk\d+$`)
var reDiskPart = regexp.MustCompile(`^(disk\d+)s\d+$`)

type ioUsbDisk struct {
	device   string
	stats    map[string]any
	hasStats bool
}

func (s *darwinUsbSource) Sample(ctx context.Context) (usbSample, error) {
	var out usbSample
	devices, bsd, err := ioregUsbDevices(ctx)
	if err != nil {
		out.Notes = append(out.Notes, "USB 장치 목록 확인 불가: "+err.Error())
	}
	out.Devices = devices

	disks, err := s.externalDisks(ctx)
	if err != nil {
		out.Notes = append(out.Notes, "외장 디스크 목록 확인 불가: "+err.Error())
	}
	for i := range disks {
		k := &disks[i]
		if b, ok := bsd[k.Disk]; ok {
			k.DeviceID = b.device
			if b.hasStats {
				k.ReadBytes = uint64(pInt(b.stats, "Bytes (Read)"))
				k.WriteBytes = uint64(pInt(b.stats, "Bytes (Write)"))
				k.StatsKnown = true
			}
		}
	}
	if note := fillOccupantsLsof(ctx, disks); note != "" {
		out.Notes = append(out.Notes, note)
	}
	out.Disks = disks
	return out, nil
}

// ioregUsbDevices walks every IOUSBHostDevice subtree: interface classes,
// user clients (processes that opened the device) and the disks it backs.
func ioregUsbDevices(ctx context.Context) ([]UsbDevice, map[string]ioUsbDisk, error) {
	raw, err := runCmd(ctx, 15*time.Second, "ioreg", "-r", "-c", "IOUSBHostDevice", "-l", "-w0", "-a")
	if err != nil {
		return nil, nil, err
	}
	bsd := map[string]ioUsbDisk{}
	if strings.TrimSpace(raw) == "" {
		return nil, bsd, nil
	}
	v, err := parsePlist([]byte(raw))
	if err != nil {
		return nil, nil, err
	}
	nodes, _ := v.([]any)
	var devices []UsbDevice
	for _, n := range nodes {
		m, ok := n.(map[string]any)
		if !ok {
			continue
		}
		if pInt(m, "bDeviceClass") == 9 { // hub
			continue
		}
		dev := UsbDevice{
			ID:        fmt.Sprintf("usb-%08x", pInt(m, "locationID")),
			Name:      firstNonEmpty(pStr(m, "USB Product Name"), pStr(m, "kUSBProductString"), pStr(m, "IORegistryEntryName")),
			Vendor:    firstNonEmpty(pStr(m, "USB Vendor Name"), pStr(m, "kUSBVendorString")),
			Serial:    firstNonEmpty(pStr(m, "USB Serial Number"), pStr(m, "kUSBSerialNumberString")),
			VendorID:  int(pInt(m, "idVendor")),
			ProductID: int(pInt(m, "idProduct")),
			Speed:     usbSpeedText(pInt(m, "USBSpeed")),
		}
		kinds := map[string]bool{}
		if k := usbClassKind(pInt(m, "bDeviceClass"), 0, 0); k != "" {
			kinds[k] = true
		}
		var clients []UsbProc
		var walk func(n map[string]any, stats map[string]any)
		walk = func(n map[string]any, stats map[string]any) {
			if _, ok := n["bInterfaceClass"]; ok && pStr(n, "IOObjectClass") == "IOUSBHostInterface" {
				if k := usbClassKind(pInt(n, "bInterfaceClass"), pInt(n, "bInterfaceSubClass"), pInt(n, "bInterfaceProtocol")); k != "" {
					kinds[k] = true
				}
			}
			if st, ok := n["Statistics"].(map[string]any); ok {
				stats = st
			}
			if c := pStr(n, "IOUserClientCreator"); c != "" {
				if p, ok := parseUserClientCreator(c); ok {
					p.Name = firstNonEmpty(pStr(n, "IORegistryEntryName"), p.Name)
					clients = append(clients, p)
				}
			}
			if name := pStr(n, "BSD Name"); reWholeDisk.MatchString(name) {
				if _, seen := bsd[name]; !seen {
					bsd[name] = ioUsbDisk{device: dev.ID, stats: stats, hasStats: stats != nil}
					dev.Disks = append(dev.Disks, name)
					kinds[UsbStorage] = true
				}
				return // partitions below
			}
			for _, c := range pMaps(n, "IORegistryEntryChildren") {
				walk(c, stats)
			}
		}
		walk(m, nil)
		for _, k := range []string{UsbStorage, UsbMTP, UsbKeyboard, UsbMouse, UsbHID, UsbNetwork, UsbSerial, UsbAudio, UsbVideo} {
			if kinds[k] {
				dev.Kinds = append(dev.Kinds, k)
			}
		}
		if len(dev.Kinds) == 0 {
			dev.Kinds = []string{UsbOther}
		}
		dev.Clients = mergeUsbProcs(clients)
		fillProcInfo(dev.Clients)
		devices = append(devices, dev)
	}
	return devices, bsd, nil
}

// parseUserClientCreator parses "pid 94029, OpenMTP".
func parseUserClientCreator(s string) (UsbProc, bool) {
	rest, ok := strings.CutPrefix(s, "pid ")
	if !ok {
		return UsbProc{}, false
	}
	pidStr, name, _ := strings.Cut(rest, ",")
	pid, err := strconv.Atoi(strings.TrimSpace(pidStr))
	if err != nil || pid <= 0 {
		return UsbProc{}, false
	}
	return UsbProc{PID: pid, Name: strings.TrimSpace(name), Count: 1}, true
}

// fillProcInfo adds user / exe from ps (user clients only carry pid + name).
func fillProcInfo(ps []UsbProc) {
	if len(ps) == 0 {
		return
	}
	var pids []string
	for _, p := range ps {
		pids = append(pids, strconv.Itoa(p.PID))
	}
	out, _ := runCmd(context.Background(), 5*time.Second, "ps", "-o", "pid=,user=,comm=", "-p", strings.Join(pids, ","))
	info := map[int][2]string{}
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		pid, _ := strconv.Atoi(f[0])
		_, comm, _ := strings.Cut(strings.TrimSpace(line)[len(f[0]):], f[1])
		info[pid] = [2]string{f[1], strings.TrimSpace(comm)}
	}
	for i := range ps {
		if v, ok := info[ps[i].PID]; ok {
			ps[i].User, ps[i].Exe = v[0], v[1]
			if ps[i].Name == "" {
				ps[i].Name = baseName(v[1])
			}
		}
	}
}

func usbSpeedText(v int64) string {
	switch v {
	case 0:
		return "1.5 Mb/s"
	case 1:
		return "12 Mb/s"
	case 2:
		return "480 Mb/s"
	case 3:
		return "5 Gb/s"
	case 4:
		return "10 Gb/s"
	case 5:
		return "20 Gb/s"
	}
	return ""
}

// externalDisks lists physical external disks with their volumes (APFS
// volumes of synthesized containers are attached to the physical disk).
func (s *darwinUsbSource) externalDisks(ctx context.Context) ([]UsbDisk, error) {
	raw, err := runCmd(ctx, 15*time.Second, "diskutil", "list", "-plist", "external")
	if err != nil {
		return nil, err
	}
	v, err := parsePlist([]byte(raw))
	if err != nil {
		return nil, err
	}
	root, _ := v.(map[string]any)
	entries := pMaps(root, "AllDisksAndPartitions")

	s.mu.Lock()
	defer s.mu.Unlock()
	present := map[string]bool{}
	var disks []UsbDisk
	idx := map[string]int{}
	var synthesized []map[string]any
	for _, e := range entries {
		id := pStr(e, "DeviceIdentifier")
		present[id] = true
		if stores := pMaps(e, "APFSPhysicalStores"); len(stores) > 0 {
			synthesized = append(synthesized, e)
			continue
		}
		info := s.diskInfo(ctx, id, pInt(e, "Size"))
		if info == nil || pStr(info, "VirtualOrPhysical") == "Virtual" || pStr(info, "BusProtocol") == "Disk Image" {
			continue
		}
		k := UsbDisk{Disk: id, Name: firstNonEmpty(pStr(info, "MediaName"), pStr(info, "IORegistryEntryName")),
			Bus: pStr(info, "BusProtocol"), Size: uint64(pInt(e, "Size")),
			Removable: pBool(info, "Removable") || pBool(info, "RemovableMedia") || pBool(info, "Ejectable")}
		k.Volumes = diskutilVolumes(e)
		idx[id] = len(disks)
		disks = append(disks, k)
	}
	for _, e := range synthesized {
		for _, st := range pMaps(e, "APFSPhysicalStores") {
			m := reDiskPart.FindStringSubmatch(pStr(st, "DeviceIdentifier"))
			if m == nil {
				continue
			}
			if i, ok := idx[m[1]]; ok {
				// the container partition itself is not a user volume
				disks[i].Volumes = slices.DeleteFunc(disks[i].Volumes, func(v UsbVolume) bool { return v.ID == pStr(st, "DeviceIdentifier") })
				disks[i].Volumes = append(disks[i].Volumes, diskutilVolumes(e)...)
			}
		}
	}
	for id := range s.info {
		if !present[strings.SplitN(id, "|", 2)[0]] {
			delete(s.info, id)
		}
	}
	return disks, nil
}

func (s *darwinUsbSource) diskInfo(ctx context.Context, id string, size int64) map[string]any {
	key := fmt.Sprintf("%s|%d", id, size)
	if m, ok := s.info[key]; ok {
		return m
	}
	raw, err := runCmd(ctx, 10*time.Second, "diskutil", "info", "-plist", id)
	if err != nil {
		return nil
	}
	v, err := parsePlist([]byte(raw))
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	s.info[key] = m
	return m
}

func diskutilVolumes(e map[string]any) []UsbVolume {
	var out []UsbVolume
	add := func(m map[string]any) {
		if c := pStr(m, "Content"); c == "EFI" || c == "Apple_APFS_ISC" {
			return
		}
		v := UsbVolume{ID: pStr(m, "DeviceIdentifier"), Name: pStr(m, "VolumeName"), MountPoint: pStr(m, "MountPoint"), Size: uint64(pInt(m, "Size"))}
		if v.Name == "" && v.MountPoint == "" && pStr(m, "Content") == "" {
			return
		}
		if v.MountPoint != "" {
			var st syscall.Statfs_t
			if syscall.Statfs(v.MountPoint, &st) == nil {
				v.FS = cString(st.Fstypename[:])
				v.Size = st.Blocks * uint64(st.Bsize)
				v.Free = st.Bavail * uint64(st.Bsize)
				v.ReadOnly = st.Flags&0x1 != 0 // MNT_RDONLY
			}
		} else if v.FS == "" {
			v.FS = pStr(m, "Content")
		}
		out = append(out, v)
	}
	if pStr(e, "MountPoint") != "" {
		add(e)
	}
	for _, p := range pMaps(e, "Partitions") {
		add(p)
	}
	for _, p := range pMaps(e, "APFSVolumes") {
		add(p)
	}
	return out
}

func cString(b []int8) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

// fillOccupantsLsof finds processes with files open on each disk's mounted
// volumes or its raw device nodes.
func fillOccupantsLsof(ctx context.Context, disks []UsbDisk) string {
	type target struct {
		disk   int
		prefix string // mount point or device path
		mount  bool
	}
	var targets []target
	var args []string
	for i, k := range disks {
		devs := []string{k.Disk}
		for _, v := range k.Volumes {
			if v.ID != "" {
				devs = append(devs, v.ID)
			}
			if v.MountPoint != "" {
				targets = append(targets, target{i, v.MountPoint, true})
				args = append(args, v.MountPoint)
			}
		}
		for _, d := range devs {
			for _, p := range []string{"/dev/" + d, "/dev/r" + d} {
				if _, err := os.Stat(p); err == nil {
					targets = append(targets, target{i, p, false})
					args = append(args, p)
				}
			}
		}
	}
	if len(args) == 0 {
		return ""
	}
	raw, err := runCmd(ctx, 15*time.Second, "lsof", append([]string{"-nP", "-w", "-F", "pcLfn"}, args...)...)
	if err != nil && exitCode(err) != 1 { // 1 = nothing open
		return "점유 프로세스 확인 불가: " + err.Error()
	}
	occ := make([][]UsbProc, len(disks))
	for _, rec := range parseLsofF(raw) {
		for _, f := range rec.files {
			for _, t := range targets {
				hit := f == t.prefix
				if t.mount {
					hit = hit || strings.HasPrefix(f, strings.TrimSuffix(t.prefix, "/")+"/")
				}
				if hit {
					occ[t.disk] = append(occ[t.disk], UsbProc{PID: rec.pid, Name: rec.cmd, User: rec.user, Files: []string{f}, Count: 1})
					break
				}
			}
		}
	}
	for i := range disks {
		disks[i].Occupants = mergeUsbProcs(occ[i])
		fillProcInfo(disks[i].Occupants)
	}
	return ""
}

type lsofRec struct {
	pid   int
	cmd   string
	user  string
	files []string
}

// parseLsofF parses `lsof -F pcLfn` output (one field per line, p starts a process).
func parseLsofF(out string) []lsofRec {
	var recs []lsofRec
	var cur *lsofRec
	for line := range strings.Lines(out) {
		line = strings.TrimRight(line, "\n")
		if len(line) < 2 {
			continue
		}
		v := line[1:]
		switch line[0] {
		case 'p':
			pid, _ := strconv.Atoi(v)
			recs = append(recs, lsofRec{pid: pid})
			cur = &recs[len(recs)-1]
		case 'c':
			if cur != nil {
				cur.cmd = v
			}
		case 'L':
			if cur != nil {
				cur.user = v
			}
		case 'n':
			if cur != nil {
				cur.files = append(cur.files, v)
			}
		}
	}
	return recs
}

// usbEjectDisk unmounts and ejects a disk. force unmounts with open files.
func usbEjectDisk(ctx context.Context, k UsbDisk, force bool) []UsbStep {
	var steps []UsbStep
	if force {
		out, err := runCmdCombined(ctx, 60*time.Second, "diskutil", "unmountDisk", "force", k.Disk)
		steps = append(steps, UsbStep{Action: "force_unmount", Target: k.Disk, OK: err == nil, Detail: cmdDetail(out, err)})
		if err != nil {
			return steps
		}
	}
	out, err := runCmdCombined(ctx, 60*time.Second, "diskutil", "eject", k.Disk)
	steps = append(steps, UsbStep{Action: "eject", Target: k.Disk, OK: err == nil, Detail: cmdDetail(out, err)})
	return steps
}
