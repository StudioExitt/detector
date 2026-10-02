package detect

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"detector/internal/config"
	"detector/internal/db"
)

func testEnv(t *testing.T, detector string) *Env {
	t.Helper()
	database, err := db.Open(context.Background(), config.DatabaseConfig{DBType: "sqlite3", FilePath: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return &Env{State: &State{db: database, detector: detector}, Host: "test"}
}

func netCfg() config.NetworkDetectConfig {
	return config.NetworkDetectConfig{SuspiciousPorts: []int{4444, 3333}, MaxConnsPerProcess: 200, MaxRemoteHosts: 100, UploadMB: 500}
}

func rules(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.Rule]++
	}
	return m
}

func TestIPScope(t *testing.T) {
	for ip, want := range map[string]string{
		"127.0.0.1": "loopback", "::1": "loopback", "192.168.0.5": "private", "10.1.2.3": "private",
		"100.100.100.100": "private", "fd7a:115c:a1e0::53": "private", "fe80::1": "private",
		"8.8.8.8": "public", "2606:4700::1111": "public",
	} {
		if got := ipScope(ip); got != want {
			t.Errorf("%s: %s want %s", ip, got, want)
		}
	}
}

func TestNetworkConnectionFindings(t *testing.T) {
	d := newNetworkDetector(netCfg()).(*networkDetector)
	env := testEnv(t, "network")
	now := time.Now()

	conns := []NetConn{
		{RemoteIP: "203.0.113.9", RemotePort: 4444, State: "ESTABLISHED", PID: 10, Process: "bash", Exe: "/bin/bash"},
		{RemoteIP: "198.51.100.7", RemotePort: 443, State: "ESTABLISHED", PID: 11, Process: "agent", Exe: "/tmp/.x/agent"},
		{RemoteIP: "8.8.8.8", RemotePort: 443, State: "ESTABLISHED", PID: 12, Process: "Safari", Exe: "/System/Applications/Safari.app/x"},
	}
	// scanner: 60 SYN_SENT to distinct hosts
	for i := range 60 {
		conns = append(conns, NetConn{RemoteIP: fmt.Sprintf("203.0.113.%d", i+1), RemotePort: 22, State: "SYN_SENT", PID: 20, Process: "scan", Exe: "/usr/local/bin/scan"})
	}
	// bot: 120 established connections to distinct public hosts
	for i := range 120 {
		conns = append(conns, NetConn{RemoteIP: fmt.Sprintf("198.18.%d.%d", i/250, i%250+1), RemotePort: 80, State: "ESTABLISHED", PID: 30, Process: "bot", Exe: "/opt/bot"})
	}
	for i := range conns {
		conns[i].Remote = hostPort(conns[i].RemoteIP, conns[i].RemotePort)
		conns[i].Local = "192.168.0.2:50000"
	}
	snap := NetworkSnapshot{}
	got := rules(d.connectionFindings(env, netRaw{Conns: conns}, &snap, now))
	for _, r := range []string{"net.suspicious_port", "net.suspicious_process", "net.outbound_scan", "net.many_hosts"} {
		if got[r] == 0 {
			t.Errorf("expected %s, got %v", r, got)
		}
	}
	if snap.External == 0 || len(snap.Processes) == 0 {
		t.Errorf("snapshot not filled: %+v", snap)
	}
}

func TestNetworkLargeUpload(t *testing.T) {
	d := newNetworkDetector(netCfg()).(*networkDetector)
	env := testEnv(t, "network")
	start := time.Now()
	conn := func(tx uint64) netRaw {
		return netRaw{HasBytes: true, Conns: []NetConn{{Local: "192.168.0.2:50001", Remote: "203.0.113.50:443", RemoteIP: "203.0.113.50",
			RemotePort: 443, State: "ESTABLISHED", PID: 40, Process: "rclone", Exe: "/usr/local/bin/rclone", TxBytes: tx}}}
	}
	var last map[string]int
	for i, tx := range []uint64{0, 200 << 20, 400 << 20, 650 << 20} {
		snap := NetworkSnapshot{}
		last = rules(d.connectionFindings(env, conn(tx), &snap, start.Add(time.Duration(i)*time.Minute)))
	}
	if last["net.large_upload"] == 0 {
		t.Fatalf("650MB within 3 minutes should be flagged, got %v", last)
	}
}

func TestNetworkConfigChanges(t *testing.T) {
	d := newNetworkDetector(netCfg()).(*networkDetector)
	env := testEnv(t, "network")
	ctx := context.Background()
	base := netRaw{Gateway: "192.168.0.1", GatewayMAC: "aa:aa:aa:aa:aa:aa", Interface: "en0", DNS: []string{"1.1.1.1"}}

	if f, err := d.configFindings(ctx, env, base, NetworkSnapshot{}); err != nil || len(f) != 0 {
		t.Fatalf("baseline: %v %v", err, f)
	}
	changed := base
	changed.DNS = []string{"45.9.20.1"}
	changed.Proxies = []string{"HTTPS 45.9.20.2:8080"}
	changed.GatewayMAC = "bb:bb:bb:bb:bb:bb"
	f, err := d.configFindings(ctx, env, changed, NetworkSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	got := rules(f)
	for _, r := range []string{"net.dns_changed", "net.proxy_changed", "net.gateway_mac_changed"} {
		if got[r] != 1 {
			t.Errorf("expected %s, got %v", r, got)
		}
	}
}
