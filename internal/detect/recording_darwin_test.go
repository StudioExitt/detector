package detect

import (
	"os"
	"strconv"
	"testing"
	"time"
)

func TestDarwinSensorLog(t *testing.T) {
	s := newRecSource().(*darwinRecSource)
	now := time.Now()
	s.apply(`Sorted active attributions from SystemStatus update: [[scr] Ghostty (com.mitchellh.ghostty)]`, now, false)
	s.apply(`Active activity attributions changed to ["scr:com.mitchellh.ghostty", "loc:com.apple.weather", "mic:us.zoom.xos"]`, now, false)

	if len(s.active) != 2 || !s.active["scr:com.mitchellh.ghostty"].Equal(now) {
		t.Fatalf("active: %v", s.active)
	}
	if s.names["com.mitchellh.ghostty"] != "Ghostty" {
		t.Errorf("names: %v", s.names)
	}

	// a capture that ends before the next sample is still reported once
	s.apply(`Active activity attributions changed to ["mic:us.zoom.xos"]`, now, false)
	if _, ok := s.missed["scr:com.mitchellh.ghostty"]; !ok {
		t.Errorf("missed: %v", s.missed)
	}

	// unattributed capture: the PID comes from the audit token
	s.apply(`Failed to create scr ActivityAttribution. Cannot get executable path or display name for attribution <STActivityAttribution: 0x6> {
    attributedEntity = <STAttributedEntity: 0x6> {
        executableIdentity = <STExecutableIdentity: 0x6> {
            auditToken = <BSAuditToken: 0x6; AUID: 501; EUID: 501; EGID: 20; RUID: 501; RGID: 20; PID: `+strconv.Itoa(os.Getpid())+`; ASID: 100003; PIDVersion: 3617442>;`, now, false)
	h, ok := s.hidden[RecScreen+"|"+strconv.Itoa(os.Getpid())]
	if !ok || !h.Hidden || h.PID != os.Getpid() {
		t.Errorf("hidden: %v", s.hidden)
	}
}
