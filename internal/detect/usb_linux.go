package detect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// linuxUsbSource reads USB devices and disks from sysfs, mounts from
// /proc/self/mountinfo and occupying processes from /proc/<pid>/fd, cwd, root.
type linuxUsbSource struct{}

func newUsbSource() usbSource { return linuxUsbSource{} }

const sysUsb = "/sys/bus/usb/devices"

func sysRead(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func sysHex(path string) int64 {
	n, _ := strconv.ParseInt(sysRead(path), 16, 64)
	return n
}

func (linuxUsbSource) Sample(context.Context) (usbSample, error) {
	var out usbSample
	entries, err := os.ReadDir(sysUsb)
	if err != nil {
		return out, fmt.Errorf("read %s: %w", sysUsb, err)
	}
	devByName := map[string]*UsbDevice{}
	devNode := map[string]string{} // /dev/bus/usb/BBB/DDD -> device id
	for _, e := range entries {
		name := e.Name()
		if strings.Contains(name, ":") || strings.HasPrefix(name, "usb") {
			continue // interfaces and root hubs
		}
		dir := filepath.Join(sysUsb, name)
		if sysRead(dir+"/idVendor") == "" || sysHex(dir+"/bDeviceClass") == 9 {
			continue
		}
		dev := &UsbDevice{
			ID: "usb-" + name, Name: sysRead(dir + "/product"), Vendor: sysRead(dir + "/manufacturer"), Serial: sysRead(dir + "/serial"),
			VendorID: int(sysHex(dir + "/idVendor")), ProductID: int(sysHex(dir + "/idProduct")),
		}
		if sp := sysRead(dir + "/speed"); sp != "" {
			dev.Speed = sp + " Mb/s"
		}
		kinds := map[string]bool{}
		if k := usbClassKind(sysHex(dir+"/bDeviceClass"), 0, 0); k != "" {
			kinds[k] = true
		}
		ifaces, _ := filepath.Glob(filepath.Join(sysUsb, name+":*"))
		for _, ifc := range ifaces {
			if k := usbClassKind(sysHex(ifc+"/bInterfaceClass"), sysHex(ifc+"/bInterfaceSubClass"), sysHex(ifc+"/bInterfaceProtocol")); k != "" {
				kinds[k] = true
			}
		}
		for _, k := range []string{UsbStorage, UsbMTP, UsbKeyboard, UsbMouse, UsbHID, UsbNetwork, UsbSerial, UsbAudio, UsbVideo} {
			if kinds[k] {
				dev.Kinds = append(dev.Kinds, k)
			}
		}
		if len(dev.Kinds) == 0 {
			dev.Kinds = []string{UsbOther}
		}
		bus, _ := strconv.Atoi(sysRead(dir + "/busnum"))
		num, _ := strconv.Atoi(sysRead(dir + "/devnum"))
		if bus > 0 && num > 0 {
			devNode[fmt.Sprintf("/dev/bus/usb/%03d/%03d", bus, num)] = dev.ID
		}
		devByName[name] = dev
	}

	// disks backed by a USB device
	mounts := readMountinfo()
	labels := diskLabels()
	blocks, _ := os.ReadDir("/sys/block")
	for _, b := range blocks {
		real, err := filepath.EvalSymlinks(filepath.Join("/sys/block", b.Name()))
		if err != nil || !strings.Contains(real, "/usb") {
			continue
		}
		var owner *UsbDevice
		for _, comp := range strings.Split(real, "/") {
			if d, ok := devByName[comp]; ok {
				owner = d
			}
		}
		sz, _ := strconv.ParseUint(sysRead(filepath.Join(real, "size")), 10, 64)
		if sz == 0 {
			continue // card reader without media
		}
		k := UsbDisk{Disk: b.Name(), Bus: "USB", Size: sz * 512, Removable: sysRead(filepath.Join(real, "removable")) == "1",
			Name: strings.TrimSpace(sysRead(filepath.Join(real, "device/vendor")) + " " + sysRead(filepath.Join(real, "device/model")))}
		if owner != nil {
			k.DeviceID = owner.ID
			owner.Disks = append(owner.Disks, k.Disk)
			if !strings.Contains(strings.Join(owner.Kinds, ","), UsbStorage) {
				owner.Kinds = append([]string{UsbStorage}, owner.Kinds...)
			}
		}
		if f := strings.Fields(sysRead(filepath.Join(real, "stat"))); len(f) >= 7 {
			r, _ := strconv.ParseUint(f[2], 10, 64)
			w, _ := strconv.ParseUint(f[6], 10, 64)
			k.ReadBytes, k.WriteBytes, k.StatsKnown = r*512, w*512, true
		}
		parts, _ := filepath.Glob(filepath.Join(real, b.Name()+"*"))
		vols := []string{b.Name()}
		for _, p := range parts {
			vols = append(vols, filepath.Base(p))
		}
		for _, id := range vols {
			v := UsbVolume{ID: id, Name: labels[id]}
			if m, ok := mounts["/dev/"+id]; ok {
				v.MountPoint, v.FS = m[0], m[1]
				var st syscall.Statfs_t
				if syscall.Statfs(v.MountPoint, &st) == nil {
					v.Size = st.Blocks * uint64(st.Bsize)
					v.Free = st.Bavail * uint64(st.Bsize)
					v.ReadOnly = st.Flags&0x1 != 0 // ST_RDONLY
				}
			} else if id == b.Name() && len(parts) > 0 {
				continue // whole disk with a partition table
			} else {
				psz, _ := strconv.ParseUint(sysRead(filepath.Join(real, id, "size")), 10, 64)
				v.Size = psz * 512
			}
			k.Volumes = append(k.Volumes, v)
		}
		out.Disks = append(out.Disks, k)
	}

	// processes holding a disk / USB device node open
	occ, clients := scanProcHolders(out.Disks, devNode)
	for i := range out.Disks {
		out.Disks[i].Occupants = mergeUsbProcs(occ[i])
	}
	for _, d := range devByName {
		d.Clients = mergeUsbProcs(clients[d.ID])
		out.Devices = append(out.Devices, *d)
	}
	if os.Geteuid() != 0 {
		out.Notes = append(out.Notes, "다른 사용자의 /proc/<pid>/fd 는 root 만 읽을 수 있음")
	}
	return out, nil
}

// readMountinfo: device -> [mount point, fs type].
func readMountinfo() map[string][2]string {
	out := map[string][2]string{}
	raw := sysRead("/proc/self/mountinfo")
	for line := range strings.Lines(raw) {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		f, g := strings.Fields(pre), strings.Fields(post)
		if len(f) < 5 || len(g) < 2 {
			continue
		}
		if _, seen := out[g[1]]; !seen {
			out[g[1]] = [2]string{unescapeMount(f[4]), g[0]}
		}
	}
	return out
}

func unescapeMount(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

func diskLabels() map[string]string {
	out := map[string]string{}
	links, _ := os.ReadDir("/dev/disk/by-label")
	for _, l := range links {
		t, err := filepath.EvalSymlinks(filepath.Join("/dev/disk/by-label", l.Name()))
		if err == nil {
			out[filepath.Base(t)] = unescapeMount(strings.ReplaceAll(l.Name(), `\x20`, " "))
		}
	}
	return out
}

func scanProcHolders(disks []UsbDisk, devNode map[string]string) ([][]UsbProc, map[string][]UsbProc) {
	occ := make([][]UsbProc, len(disks))
	clients := map[string][]UsbProc{}
	type target struct {
		disk   int
		prefix string
		mount  bool
	}
	var targets []target
	for i, k := range disks {
		targets = append(targets, target{i, "/dev/" + k.Disk, false})
		for _, v := range k.Volumes {
			targets = append(targets, target{i, "/dev/" + v.ID, false})
			if v.MountPoint != "" {
				targets = append(targets, target{i, v.MountPoint, true})
			}
		}
	}
	if len(targets) == 0 && len(devNode) == 0 {
		return occ, clients
	}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range dirs {
		pid, err := strconv.Atoi(filepath.Base(dir))
		if err != nil {
			continue
		}
		var paths []string
		for _, l := range []string{"cwd", "root", "exe"} {
			if p, err := os.Readlink(filepath.Join(dir, l)); err == nil && p != "/" {
				paths = append(paths, p)
			}
		}
		fds, _ := os.ReadDir(filepath.Join(dir, "fd"))
		for _, fd := range fds {
			if p, err := os.Readlink(filepath.Join(dir, "fd", fd.Name())); err == nil && strings.HasPrefix(p, "/") {
				paths = append(paths, p)
			}
		}
		var p *UsbProc
		mk := func(f string) UsbProc {
			if p == nil {
				p = &UsbProc{PID: pid, Name: sysRead(dir + "/comm")}
				p.Exe, _ = os.Readlink(dir + "/exe")
				if fi, err := os.Stat(dir); err == nil {
					if st, ok := fi.Sys().(*syscall.Stat_t); ok {
						p.User = uidName(st.Uid)
					}
				}
			}
			q := *p
			q.Files, q.Count = []string{f}, 1
			return q
		}
		for _, f := range paths {
			if id, ok := devNode[f]; ok {
				clients[id] = append(clients[id], mk(f))
				continue
			}
			for _, t := range targets {
				if f == t.prefix || (t.mount && strings.HasPrefix(f, strings.TrimSuffix(t.prefix, "/")+"/")) {
					occ[t.disk] = append(occ[t.disk], mk(f))
					break
				}
			}
		}
	}
	return occ, clients
}

var (
	uidMu    sync.Mutex
	uidNames = map[uint32]string{}
)

func uidName(uid uint32) string {
	uidMu.Lock()
	defer uidMu.Unlock()
	if n, ok := uidNames[uid]; ok {
		return n
	}
	n := strconv.Itoa(int(uid))
	if u, err := user.LookupId(n); err == nil {
		n = u.Username
	}
	uidNames[uid] = n
	return n
}

// usbEjectDisk unmounts every mounted volume (udisksctl when present, so
// desktop users need no root), then powers the disk off.
func usbEjectDisk(ctx context.Context, k UsbDisk, force bool) []UsbStep {
	var steps []UsbStep
	_, errU := exec.LookPath("udisksctl")
	hasUdisks := errU == nil
	ok := true
	for _, v := range k.Volumes {
		if v.MountPoint == "" {
			continue
		}
		dev := "/dev/" + v.ID
		var out string
		var err error
		action := "unmount"
		switch {
		case force:
			action = "force_unmount"
			out, err = runCmdCombined(ctx, 60*time.Second, "umount", "-f", v.MountPoint)
			if err != nil { // busy: detach now, clean up when no longer used
				out, err = runCmdCombined(ctx, 60*time.Second, "umount", "-l", v.MountPoint)
			}
		case hasUdisks:
			out, err = runCmdCombined(ctx, 60*time.Second, "udisksctl", "unmount", "-b", dev)
		default:
			out, err = runCmdCombined(ctx, 60*time.Second, "umount", v.MountPoint)
		}
		steps = append(steps, UsbStep{Action: action, Target: dev, OK: err == nil, Detail: cmdDetail(out, err)})
		ok = ok && err == nil
	}
	if !ok {
		return steps
	}
	dev := "/dev/" + k.Disk
	var out string
	var err error
	if hasUdisks {
		out, err = runCmdCombined(ctx, 60*time.Second, "udisksctl", "power-off", "-b", dev)
	} else {
		out, err = runCmdCombined(ctx, 60*time.Second, "eject", dev)
	}
	steps = append(steps, UsbStep{Action: "eject", Target: dev, OK: err == nil, Detail: cmdDetail(out, err)})
	return steps
}
