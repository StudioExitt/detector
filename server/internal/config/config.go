package config

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	DefaultAPIPort  = 8088
	DefaultLogLevel = "info"
	DefaultLogDir   = "logs"
	DefaultDBType   = "sqlite3"
	DefaultDBPath   = "detector.db"
)

type Config struct {
	Common   CommonConfig   `toml:"common"`
	Log      LogConfig      `toml:"log"`
	Database DatabaseConfig `toml:"database"`
	Detect   DetectConfig   `toml:"detect"`
}

type CommonConfig struct {
	APIPort  int    `toml:"apiPort"`
	LogLevel string `toml:"logLevel"`
	TimeZone string `toml:"timeZone"`
}

type LogConfig struct {
	Dir    string `toml:"dir"`
	Prefix string `toml:"prefix"`
	Stdout bool   `toml:"stdout"`
}

type DatabaseConfig struct {
	DBType   string `toml:"dbType"`
	FilePath string `toml:"filePath"`
}

// DetectConfig controls the host intrusion detectors. Each detector can be
// switched off or given its own interval; unsupported detectors for the
// running OS are skipped.
type DetectConfig struct {
	Enabled  *bool         `toml:"enabled"`
	Cooldown time.Duration `toml:"cooldown"` // suppress duplicate findings for this long
	// how long time-series metrics (CPU, memory, network ...) are kept
	MetricsRetention time.Duration `toml:"metricsRetention"`

	Auth      AuthDetectConfig      `toml:"auth"`
	FIM       FIMDetectConfig       `toml:"fim"`
	Listeners ListenersDetectConfig `toml:"listeners"`
	Process   DetectorConfig        `toml:"process"`
	Accounts  DetectorConfig        `toml:"accounts"`
	Posture   DetectorConfig        `toml:"posture"`
	Resources ResourcesDetectConfig `toml:"resources"`
	Network   NetworkDetectConfig   `toml:"network"`
	// macOS only
	Clipboard  ClipboardDetectConfig  `toml:"clipboard"`
	Extensions ExtensionsDetectConfig `toml:"extensions"`
}

// ResourcesDetectConfig: CPU / memory / disk usage anomalies.
type ResourcesDetectConfig struct {
	DetectorConfig
	ProcCPUPercent   float64       `toml:"procCpuPercent"`   // per process, 100 = one core
	SystemCPUPercent float64       `toml:"systemCpuPercent"` // whole machine
	Sustain          time.Duration `toml:"sustain"`          // how long high usage must last
	ProcMemPercent   float64       `toml:"procMemPercent"`   // one process using this share of RAM
	DiskWarnPercent  float64       `toml:"diskWarnPercent"`
	DiskCritPercent  float64       `toml:"diskCritPercent"`
	DiskGrowthGB     float64       `toml:"diskGrowthGB"` // growth within 10 minutes
	IgnoreProcesses  []string      `toml:"ignoreProcesses"`
}

// NetworkDetectConfig: connectivity and outbound connection anomalies.
type NetworkDetectConfig struct {
	DetectorConfig
	ProbeTargets       []string `toml:"probeTargets"` // host:port for reachability; [] disables
	SuspiciousPorts    []int    `toml:"suspiciousPorts"`
	MaxConnsPerProcess int      `toml:"maxConnsPerProcess"`
	MaxRemoteHosts     int      `toml:"maxRemoteHosts"`
	UploadMB           float64  `toml:"uploadMB"` // per process within 10 minutes (macOS)
}

type ExtensionsDetectConfig struct {
	DetectorConfig
	TrustedIDs    []string `toml:"trustedIds"`    // never reported (risk still shown)
	BlockedIDs    []string `toml:"blockedIds"`    // always critical when installed
	BlocklistFile string   `toml:"blocklistFile"` // extra blocked IDs, one per line (# comments)
}

// ClipboardDetectConfig: the pasteboard is polled every PollInterval in the
// background; Interval only controls how often status/findings are collected.
type ClipboardDetectConfig struct {
	DetectorConfig
	PollInterval time.Duration `toml:"pollInterval"`
	SwapWindow   time.Duration `toml:"swapWindow"` // address A replaced by address B within this time = swap
	CanaryWait   time.Duration `toml:"canaryWait"` // per-address wait in the canary test
}

type DetectorConfig struct {
	Enabled  *bool         `toml:"enabled"`
	Interval time.Duration `toml:"interval"`
}

func (d DetectorConfig) IsEnabled() bool { return d.Enabled == nil || *d.Enabled }

type AuthDetectConfig struct {
	DetectorConfig
	FailThreshold int           `toml:"failThreshold"`
	FailWindow    time.Duration `toml:"failWindow"`
	LogFiles      []string      `toml:"logFiles"` // linux: auth log candidates (first existing is used)
}

type FIMDetectConfig struct {
	DetectorConfig
	ExtraPaths []string `toml:"extraPaths"`
}

type ListenersDetectConfig struct {
	DetectorConfig
	IgnorePorts []int `toml:"ignorePorts"`
}

func (d DetectConfig) IsEnabled() bool { return d.Enabled == nil || *d.Enabled }

// Load reads the TOML config file and fills in defaults.
func Load(path string) (*Config, error) {
	cfg := &Config{}
	md, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		slog.Warn("unknown config keys", "keys", fmt.Sprint(undecoded))
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Common.APIPort == 0 {
		c.Common.APIPort = DefaultAPIPort
	}
	if c.Common.LogLevel == "" {
		c.Common.LogLevel = DefaultLogLevel
	}
	if c.Log.Dir == "" {
		c.Log.Dir = DefaultLogDir
	}
	if c.Log.Prefix == "" {
		c.Log.Prefix = "detector"
	}
	if c.Database.DBType == "" {
		c.Database.DBType = DefaultDBType
	}
	if c.Database.FilePath == "" {
		c.Database.FilePath = DefaultDBPath
	}

	d := &c.Detect
	if d.Cooldown == 0 {
		d.Cooldown = time.Hour
	}
	if d.MetricsRetention == 0 {
		d.MetricsRetention = 7 * 24 * time.Hour
	}
	setInterval(&d.Auth.DetectorConfig, 30*time.Second)
	setInterval(&d.FIM.DetectorConfig, 5*time.Minute)
	setInterval(&d.Listeners.DetectorConfig, time.Minute)
	setInterval(&d.Process, time.Minute)
	setInterval(&d.Accounts, 5*time.Minute)
	setInterval(&d.Posture, 10*time.Minute)
	setInterval(&d.Resources.DetectorConfig, 30*time.Second)
	setInterval(&d.Network.DetectorConfig, 30*time.Second)
	r := &d.Resources
	r.ProcCPUPercent = orDefault(r.ProcCPUPercent, 80)
	r.SystemCPUPercent = orDefault(r.SystemCPUPercent, 90)
	r.ProcMemPercent = orDefault(r.ProcMemPercent, 25)
	r.DiskWarnPercent = orDefault(r.DiskWarnPercent, 90)
	r.DiskCritPercent = orDefault(r.DiskCritPercent, 95)
	r.DiskGrowthGB = orDefault(r.DiskGrowthGB, 5)
	if r.Sustain == 0 {
		r.Sustain = 5 * time.Minute
	}
	n := &d.Network
	if n.ProbeTargets == nil {
		n.ProbeTargets = []string{"1.1.1.1:443", "8.8.8.8:443"}
	}
	if n.SuspiciousPorts == nil {
		// Metasploit/backdoors, IRC C2, Tor, common mining pool (stratum) ports
		n.SuspiciousPorts = []int{1337, 31337, 4444, 6666, 6667, 6668, 6669, 6697, 9001, 9030, 9050, 9150,
			3333, 3334, 5555, 7777, 14433, 14444, 45560, 45700}
	}
	if n.MaxConnsPerProcess == 0 {
		n.MaxConnsPerProcess = 200
	}
	if n.MaxRemoteHosts == 0 {
		n.MaxRemoteHosts = 100
	}
	n.UploadMB = orDefault(n.UploadMB, 500)
	setInterval(&d.Clipboard.DetectorConfig, 10*time.Second)
	setInterval(&d.Extensions.DetectorConfig, 10*time.Minute)
	if d.Clipboard.PollInterval == 0 {
		d.Clipboard.PollInterval = 50 * time.Millisecond
	}
	if d.Clipboard.SwapWindow == 0 {
		d.Clipboard.SwapWindow = time.Second
	}
	if d.Clipboard.CanaryWait == 0 {
		d.Clipboard.CanaryWait = 1500 * time.Millisecond
	}
	if d.Auth.FailThreshold == 0 {
		d.Auth.FailThreshold = 5
	}
	if d.Auth.FailWindow == 0 {
		d.Auth.FailWindow = 5 * time.Minute
	}
	if len(d.Auth.LogFiles) == 0 {
		d.Auth.LogFiles = []string{"/var/log/auth.log", "/var/log/secure"}
	}
}

func orDefault(v, def float64) float64 {
	if v == 0 {
		return def
	}
	return v
}

func setInterval(d *DetectorConfig, def time.Duration) {
	if d.Interval == 0 {
		d.Interval = def
	}
}

func (c *Config) validate() error {
	if c.Common.APIPort < 1 || c.Common.APIPort > 65535 {
		return fmt.Errorf("invalid common.apiPort: %d", c.Common.APIPort)
	}
	if _, err := c.SlogLevel(); err != nil {
		return err
	}
	if _, err := c.Location(); err != nil {
		return err
	}
	for name, iv := range map[string]time.Duration{
		"auth": c.Detect.Auth.Interval, "fim": c.Detect.FIM.Interval, "listeners": c.Detect.Listeners.Interval,
		"process": c.Detect.Process.Interval, "accounts": c.Detect.Accounts.Interval, "posture": c.Detect.Posture.Interval,
		"clipboard": c.Detect.Clipboard.Interval, "extensions": c.Detect.Extensions.Interval,
		"resources": c.Detect.Resources.Interval, "network": c.Detect.Network.Interval,
	} {
		if iv < 5*time.Second {
			return fmt.Errorf("detect.%s.interval must be >= 5s, got %s", name, iv)
		}
	}
	if p := c.Detect.Clipboard.PollInterval; p < 10*time.Millisecond || p > 5*time.Second {
		return fmt.Errorf("detect.clipboard.pollInterval must be 10ms..5s, got %s", p)
	}
	if c.Database.DBType != "sqlite3" {
		return fmt.Errorf("unsupported database.dbType: %q", c.Database.DBType)
	}
	return nil
}

func (c *Config) SlogLevel() (slog.Level, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(strings.ToUpper(c.Common.LogLevel))); err != nil {
		return 0, fmt.Errorf("invalid common.logLevel %q: %w", c.Common.LogLevel, err)
	}
	return lv, nil
}

// Location returns the configured time zone, or the local zone when unset.
func (c *Config) Location() (*time.Location, error) {
	if c.Common.TimeZone == "" {
		return time.Local, nil
	}
	loc, err := time.LoadLocation(c.Common.TimeZone)
	if err != nil {
		return nil, fmt.Errorf("invalid common.timeZone %q: %w", c.Common.TimeZone, err)
	}
	return loc, nil
}
