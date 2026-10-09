package detect

import (
	"testing"
	"time"

	"detector/internal/config"
)

func TestParseSSHD(t *testing.T) {
	tests := []struct {
		msg  string
		ok   bool
		kind authKind
		user string
		ip   string
	}{
		{"Failed password for root from 203.0.113.7 port 51234 ssh2", true, authSSHFail, "root", "203.0.113.7"},
		{"Failed publickey for psb from 10.0.0.5 port 22 ssh2: RSA SHA256:x", true, authSSHFail, "psb", "10.0.0.5"},
		{"Invalid user admin from 198.51.100.9 port 4444", true, authSSHFail, "admin", "198.51.100.9"},
		// counted via the preceding "Invalid user" line
		{"Failed password for invalid user admin from 198.51.100.9 port 4444 ssh2", false, 0, "", ""},
		{"Accepted publickey for psb from 192.168.0.10 port 50000 ssh2: ED25519 SHA256:x", true, authSSHSuccess, "psb", "192.168.0.10"},
		{"Accepted password for root from 2001:db8::1 port 50000 ssh2", true, authSSHSuccess, "root", "2001:db8::1"},
		{"Connection closed by 1.2.3.4 port 22 [preauth]", false, 0, "", ""},
	}
	for _, tt := range tests {
		ev, ok := parseSSHD(tt.msg)
		if ok != tt.ok {
			t.Errorf("%q: ok=%v want %v", tt.msg, ok, tt.ok)
			continue
		}
		if ok && (ev.Kind != tt.kind || ev.User != tt.user || ev.IP != tt.ip) {
			t.Errorf("%q: got %+v", tt.msg, ev)
		}
	}
}

func TestParseSudo(t *testing.T) {
	ev, ok := parseSudo("     psb : 3 incorrect password attempts ; TTY=ttys001 ; PWD=/Users/psb ; USER=root ; COMMAND=/bin/ls")
	if !ok || ev.Kind != authSudoFail || ev.User != "psb" || ev.Count != 3 {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
	ev, ok = parseSudo("guest : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/guest ; USER=root ; COMMAND=/bin/bash")
	if !ok || ev.Kind != authSudoNotAllow || ev.User != "guest" {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
	if _, ok := parseSudo("psb : TTY=ttys001 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"); ok {
		t.Fatal("successful sudo must not match")
	}
}

func TestParseSyslogAuth(t *testing.T) {
	lines := map[string]string{
		"Oct  2 17:00:00 web01 sshd[1234]: Failed password for root from 203.0.113.7 port 2222 ssh2":                        "203.0.113.7",
		"2026-10-02T17:00:00.123456+09:00 web01 sshd-session[99]: Invalid user test from 198.51.100.1 port 5555":            "198.51.100.1",
		"2026-10-02T17:00:00+00:00 web01 sudo:     bob : 2 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=x": "",
	}
	for line, ip := range lines {
		ev, ok := parseSyslogAuth(line)
		if !ok || ev.IP != ip {
			t.Errorf("%q: got %+v ok=%v", line, ev, ok)
		}
	}
	if _, ok := parseSyslogAuth("Oct  2 17:00:00 web01 CRON[1]: pam_unix(cron:session): session opened"); ok {
		t.Error("cron line must not match")
	}
}

func TestDecodeProcAddr(t *testing.T) {
	tests := map[string]struct {
		addr string
		port int
	}{
		"0100007F:0277":                         {"127.0.0.1", 631},
		"00000000:1F90":                         {"0.0.0.0", 8080},
		"00000000000000000000000000000000:0016": {"::", 22},
		"00000000000000000000000001000000:0035": {"::1", 53},
	}
	for in, want := range tests {
		a, p, ok := decodeProcAddr(in)
		if !ok || a != want.addr || p != want.port {
			t.Errorf("%s: got %s:%d ok=%v, want %s:%d", in, a, p, ok, want.addr, want.port)
		}
	}
}

func TestAuthTrackerBruteforceAndSuccessAfterFail(t *testing.T) {
	d := &authDetector{
		cfg:       config.AuthDetectConfig{FailThreshold: 3, FailWindow: 5 * time.Minute},
		fails:     map[string][]time.Time{},
		failUsers: map[string]map[string]struct{}{},
	}
	now := time.Now()
	for i := range 3 {
		if n := d.addFail("ssh:1.2.3.4", "root", now.Add(time.Duration(i)*time.Second), 1); i == 2 && n != 3 {
			t.Fatalf("count=%d want 3", n)
		}
	}
	if n := d.count("ssh:1.2.3.4", now.Add(10*time.Minute)); n != 0 {
		t.Fatalf("failures outside the window must expire, got %d", n)
	}
	d.prune(now.Add(10 * time.Minute))
	if len(d.fails) != 0 {
		t.Fatal("prune should drop expired keys")
	}
}

func TestBrowserLoadExtension(t *testing.T) {
	args := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --load-extension=/Users/x/Library/Application Support/abc --profile-directory=Default"
	m := reBrowserLoadExt.FindStringSubmatch(args)
	if m == nil || m[2] != "/Users/x/Library/Application" {
		t.Fatalf("got %v", m)
	}
	if reBrowserLoadExt.MatchString("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --type=renderer") {
		t.Fatal("normal renderer must not match")
	}
}
