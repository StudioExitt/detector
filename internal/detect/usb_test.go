package detect

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"detector/internal/config"
	"detector/internal/db"
)

func TestParsePlist(t *testing.T) {
	raw := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>USB Product Name</key><string>Cruzer &amp; Co</string>
		<key>idVendor</key><integer>1921</integer>
		<key>Built-In</key><false/>
		<key>Blob</key><data>AAEC</data>
		<key>IORegistryEntryChildren</key>
		<array><dict><key>BSD Name</key><string>disk4</string><key>Whole</key><true/></dict></array>
	</dict>
</array>
</plist>`
	v, err := parsePlist([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	arr := v.([]any)
	m := arr[0].(map[string]any)
	if pStr(m, "USB Product Name") != "Cruzer & Co" || pInt(m, "idVendor") != 1921 || pBool(m, "Built-In") {
		t.Fatalf("unexpected: %v", m)
	}
	if b := m["Blob"].([]byte); len(b) != 3 {
		t.Fatalf("data: %v", b)
	}
	kids := pMaps(m, "IORegistryEntryChildren")
	if len(kids) != 1 || pStr(kids[0], "BSD Name") != "disk4" || !pBool(kids[0], "Whole") {
		t.Fatalf("children: %v", kids)
	}
}

func TestUsbClassKind(t *testing.T) {
	cases := []struct {
		class, sub, proto int64
		want              string
	}{
		{8, 6, 0x50, UsbStorage}, {3, 1, 1, UsbKeyboard}, {3, 1, 2, UsbMouse}, {3, 0, 0, UsbHID},
		{6, 1, 1, UsbMTP}, {2, 2, 1, UsbSerial}, {2, 6, 0, UsbNetwork}, {0xff, 0, 0, ""},
	}
	for _, c := range cases {
		if got := usbClassKind(c.class, c.sub, c.proto); got != c.want {
			t.Errorf("class %x/%x/%x: %q, want %q", c.class, c.sub, c.proto, got, c.want)
		}
	}
}

func TestMergeUsbProcs(t *testing.T) {
	got := mergeUsbProcs([]UsbProc{
		{PID: 10, Name: "mds", Files: []string{"/Volumes/X/.Spotlight-V100"}, Count: 1},
		{PID: 20, Name: "cp", Files: []string{"/Volumes/X/a"}, Count: 1},
		{PID: 20, Name: "cp", Files: []string{"/Volumes/X/b"}, Count: 1},
	})
	if len(got) != 2 || got[0].PID != 20 || got[0].Count != 2 || len(got[0].Files) != 2 || !got[1].System {
		t.Fatalf("got %+v", got)
	}
}

type fakeUsbSource struct{ s usbSample }

func (f *fakeUsbSource) Sample(context.Context) (usbSample, error) { return f.s, nil }

func TestUsbDetectorFindings(t *testing.T) {
	ctx := context.Background()
	sqlDB, err := db.Open(ctx, config.DatabaseConfig{DBType: "sqlite3", FilePath: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	env := &Env{State: &State{db: sqlDB, detector: "usb"}, Log: slog.Default(), FirstRun: true}

	stick := UsbDevice{ID: "usb-1", Name: "Cruzer", VendorID: 0x0781, ProductID: 0x5583, Serial: "S1", Kinds: []string{UsbStorage}, Disks: []string{"disk4"}}
	kbd := UsbDevice{ID: "usb-2", Name: "Keyboard", VendorID: 0x05ac, ProductID: 0x0250, Kinds: []string{UsbKeyboard}}
	src := &fakeUsbSource{s: usbSample{Devices: []UsbDevice{stick}}}
	d := newUsbDetector(config.UsbDetectConfig{WriteMB: 1}).(*usbDetector)
	d.src = src

	// first run: baseline only
	rep, err := d.Check(ctx, env)
	if err != nil || len(rep.Findings) != 0 {
		t.Fatalf("first run: %v %+v", err, rep.Findings)
	}

	// a new keyboard appears -> BadUSB warning; the stick disk writes 2 MiB
	env.FirstRun = false
	src.s = usbSample{Devices: []UsbDevice{stick, kbd}, Disks: []UsbDisk{{Disk: "disk4", DeviceID: "usb-1", StatsKnown: true, WriteBytes: 1000}}}
	if rep, err = d.Check(ctx, env); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Rule != "usb.new_keyboard" || rep.Findings[0].Severity != SevHigh {
		t.Fatalf("keyboard: %+v", rep.Findings)
	}
	d.writes["usb-1|disk4"][0].At = time.Now().Add(-time.Minute)
	src.s.Disks[0].WriteBytes = 1000 + 2<<20
	if rep, err = d.Check(ctx, env); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Rule != "usb.bulk_write" {
		t.Fatalf("bulk write: %+v", rep.Findings)
	}
	snap := rep.Snapshot.(UsbSnapshot)
	if snap.Disks[0].Write10m != 2<<20 || snap.Disks[0].WriteBps <= 0 {
		t.Fatalf("write stats: %+v", snap.Disks[0])
	}

	// stick unplugged and plugged back: known device -> low severity connect event
	src.s = usbSample{Devices: []UsbDevice{kbd}}
	if _, err = d.Check(ctx, env); err != nil {
		t.Fatal(err)
	}
	src.s = usbSample{Devices: []UsbDevice{kbd, stick}}
	if rep, err = d.Check(ctx, env); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Rule != "usb.storage_connected" || rep.Findings[0].Severity != SevLow {
		t.Fatalf("reconnect: %+v", rep.Findings)
	}
	kinds := map[string]int{}
	for _, a := range rep.Snapshot.(UsbSnapshot).Recent {
		kinds[a.Kind]++
	}
	if kinds["connect"] != 2 || kinds["disconnect"] != 1 {
		t.Fatalf("recent: %v", kinds)
	}

	// restart with an existing baseline: an unknown device connected while down is reported
	d2 := newUsbDetector(config.UsbDetectConfig{TrustedDevices: []string{"05ac:0250"}}).(*usbDetector)
	other := UsbDevice{ID: "usb-3", Name: "Phone", VendorID: 0x04e8, ProductID: 0x6860, Serial: "P", Kinds: []string{UsbMTP}}
	d2.src = &fakeUsbSource{s: usbSample{Devices: []UsbDevice{stick, kbd, other}}}
	env.FirstRun = true
	if rep, err = d2.Check(ctx, env); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Rule != "usb.mtp_connected" || rep.Findings[0].Severity != SevMedium {
		t.Fatalf("restart: %+v", rep.Findings)
	}
}
