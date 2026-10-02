package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadSampleConfig(t *testing.T) {
	cfg, err := Load("../../config.toml")
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Detect
	if d.Auth.Interval != 30*time.Second || d.Auth.FailThreshold != 5 || d.Auth.FailWindow != 5*time.Minute {
		t.Errorf("auth: %+v", d.Auth)
	}
	if d.FIM.Interval != 5*time.Minute || d.Posture.Interval != 10*time.Minute || d.Cooldown != time.Hour {
		t.Errorf("detect: %+v", d)
	}
}

func TestDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte("[common]\n[detect.process]\nenabled = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Common.APIPort != 8088 || cfg.Common.LogLevel != "info" {
		t.Errorf("common defaults: %+v", cfg.Common)
	}
	if cfg.Detect.Process.IsEnabled() || !cfg.Detect.Auth.IsEnabled() || !cfg.Detect.IsEnabled() {
		t.Error("enabled flags")
	}
	if cfg.Detect.Listeners.Interval != time.Minute || len(cfg.Detect.Auth.LogFiles) != 2 {
		t.Errorf("detect defaults: %+v", cfg.Detect)
	}
}

func TestRejectsTooShortInterval(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.toml")
	_ = os.WriteFile(p, []byte("[detect.fim]\ninterval = \"1s\"\n"), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for 1s interval")
	}
}
