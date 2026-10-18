// Package detect runs host intrusion detectors on a schedule and stores
// their findings as events. Data sources differ per OS (macOS unified log,
// dscl, netstat / Linux auth.log, /proc ...), so each detector delegates
// collection to platform-specific files (*_darwin.go, *_linux.go).
package detect

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	"detector/internal/config"
)

const (
	CategoryIntrusion     = "intrusion"
	CategoryResourceAbuse = "resource_abuse"
	CategoryVulnScan      = "vulnerability_scan"

	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"

	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckFail = "fail"
)

// Finding is a single detection result that becomes an event.
type Finding struct {
	Rule     string // e.g. "auth.ssh_bruteforce"
	Category string
	Severity string
	Source   string // host, IP, path ...
	Message  string
	// Key identifies "the same finding" for cooldown-based de-duplication.
	// Defaults to Source.
	Key string
}

// Check is a point-in-time status line shown in the detector status view.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Report struct {
	Findings []Finding
	Summary  string
	Checks   []Check
	// optional: time-series values stored in the metrics table
	Metrics map[string]float64
	// optional: latest structured state served by the status APIs
	Snapshot any
}

type Detector interface {
	Name() string
	Check(ctx context.Context, env *Env) (Report, error)
}

// Starter is implemented by detectors that also need a long-running
// background task (e.g. the clipboard watcher). Start is called once before
// the first Check with the manager's lifetime context.
type Starter interface {
	Start(ctx context.Context, env *Env)
}

// compactSuccessRuns is implemented by detectors whose successful runs are
// not worth a history row each (clipboard runs every few seconds, accounts
// rarely change): only the latest successful run is kept, while runs with
// findings or errors are always kept.
type compactSuccessRuns interface {
	CompactSuccessfulRuns() bool
}

func compactsSuccess(d Detector) bool {
	c, ok := d.(compactSuccessRuns)
	return ok && c.CompactSuccessfulRuns()
}

// canaryTester is implemented by the clipboard detector.
type canaryTester interface {
	CanaryTest(ctx context.Context) (CanaryResult, []Finding, error)
}

// ErrUnavailable is returned when a feature is not supported on this platform
// or its detector is disabled.
var ErrUnavailable = errors.New("not available on this platform or disabled")

// Env is passed to a detector on every run.
type Env struct {
	State *State // persistent key/value storage scoped to the detector
	Log   *slog.Logger
	Host  string
	// FirstRun is true for the first run since process start.
	FirstRun bool
}

type Status struct {
	Name         string
	Interval     time.Duration
	LastRunAt    time.Time
	LastDuration time.Duration
	LastError    string
	Findings     int64 // findings stored since process start
	Summary      string
	Checks       []Check
	// CompactSuccess: only the latest successful run is kept in the history
	CompactSuccess bool
}

type entry struct {
	det      Detector
	interval time.Duration

	mu       sync.Mutex
	status   Status
	snapshot any
}

type Manager struct {
	db        *sql.DB
	log       *slog.Logger
	host      string
	cooldown  time.Duration
	retention time.Duration
	entries   []*entry

	emitMu sync.Mutex // serializes the check-then-insert in emit
}

func NewManager(db *sql.DB, log *slog.Logger, cfg config.DetectConfig) *Manager {
	host, _ := os.Hostname()
	m := &Manager{
		db:        db,
		log:       log.With("component", "detect"),
		host:      host,
		cooldown:  cfg.Cooldown,
		retention: cfg.MetricsRetention,
	}
	if !cfg.IsEnabled() {
		return m
	}
	for _, r := range buildDetectors(cfg) {
		m.entries = append(m.entries, &entry{
			det:      r.det,
			interval: r.interval,
			status:   Status{Name: r.det.Name(), Interval: r.interval, CompactSuccess: compactsSuccess(r.det)},
		})
	}
	return m
}

type registered struct {
	det      Detector
	interval time.Duration
}

func buildDetectors(cfg config.DetectConfig) []registered {
	var out []registered
	add := func(c config.DetectorConfig, d Detector) {
		if c.IsEnabled() && d != nil {
			out = append(out, registered{d, c.Interval})
		}
	}
	add(cfg.Auth.DetectorConfig, newAuthDetector(cfg.Auth))
	add(cfg.FIM.DetectorConfig, newFIMDetector(cfg.FIM))
	add(cfg.Listeners.DetectorConfig, newListenerDetector(cfg.Listeners))
	add(cfg.Process, newProcessDetector())
	add(cfg.Accounts, newAccountsDetector())
	add(cfg.Posture, newPostureDetector())
	add(cfg.Firewall, newFirewallDetector())
	add(cfg.Recording.DetectorConfig, newRecordingDetector(cfg.Recording))
	add(cfg.Resources.DetectorConfig, newResourcesDetector(cfg.Resources))
	add(cfg.Network.DetectorConfig, newNetworkDetector(cfg.Network))
	add(cfg.Clipboard.DetectorConfig, newClipboardDetector(cfg.Clipboard))
	add(cfg.Extensions.DetectorConfig, newExtensionsDetector(cfg.Extensions))
	return out
}

// Sources describes the data sources a detector reads on this platform.
func Sources(name string) []string { return detectorSources(name) }

func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

func (m *Manager) Host() string { return m.host }

// Run starts every detector and blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	names := make([]string, 0, len(m.entries))
	for _, e := range m.entries {
		names = append(names, e.det.Name())
	}
	m.log.Info("detectors started", "platform", Platform(), "detectors", names)
	for _, e := range m.entries {
		if compactsSuccess(e.det) {
			// keep only the latest successful run recorded before this policy existed
			_, _ = m.db.ExecContext(ctx, `DELETE FROM detect_runs WHERE detector = ? AND error = '' AND findings = 0
				AND id < (SELECT MAX(id) FROM detect_runs WHERE detector = ? AND error = '' AND findings = 0)`,
				e.det.Name(), e.det.Name())
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.pruneMetricsLoop(ctx)
	}()
	for _, e := range m.entries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.loop(ctx, e)
		}()
	}
	wg.Wait()
}

func (m *Manager) loop(ctx context.Context, e *entry) {
	state := &State{db: m.db, detector: e.det.Name()}
	if st, ok := e.det.(Starter); ok {
		st.Start(ctx, &Env{State: state, Log: m.log.With("detector", e.det.Name()), Host: m.host, FirstRun: true})
	}
	first := true
	t := time.NewTicker(e.interval)
	defer t.Stop()
	for {
		m.runOnce(ctx, e, &Env{State: state, Log: m.log.With("detector", e.det.Name()), Host: m.host, FirstRun: first})
		first = false
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Manager) runOnce(ctx context.Context, e *entry, env *Env) {
	start := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, max(e.interval, 30*time.Second))
	defer cancel()

	rep, err := m.safeCheck(runCtx, e.det, env)
	stored := int64(0)
	for _, f := range rep.Findings {
		ok, serr := m.emit(ctx, e.det.Name(), f)
		if serr != nil {
			env.Log.Error("store finding failed", "rule", f.Rule, "err", serr)
			continue
		}
		if ok {
			stored++
		}
	}

	e.mu.Lock()
	e.status.LastRunAt = start
	e.status.LastDuration = time.Since(start)
	e.status.Findings += stored
	if err != nil {
		e.status.LastError = err.Error()
	} else {
		e.status.LastError = ""
		e.status.Summary = rep.Summary
		e.status.Checks = rep.Checks
		if rep.Snapshot != nil {
			e.snapshot = rep.Snapshot
		}
	}
	e.mu.Unlock()

	if len(rep.Metrics) > 0 && ctx.Err() == nil {
		if merr := m.storeMetrics(ctx, start, rep.Metrics); merr != nil {
			env.Log.Error("store metrics failed", "err", merr)
		}
	}

	if ctx.Err() == nil {
		replaceOK := err == nil && stored == 0 && compactsSuccess(e.det)
		if rerr := m.recordRun(ctx, e.det.Name(), start, time.Since(start), err, rep, stored, replaceOK); rerr != nil {
			env.Log.Error("record run failed", "err", rerr)
		}
	}

	if err != nil && ctx.Err() == nil {
		env.Log.Warn("detector run failed", "err", err)
	} else {
		env.Log.Debug("detector run", "findings", len(rep.Findings), "stored", stored, "duration", time.Since(start).String())
	}
}

func (m *Manager) safeCheck(ctx context.Context, d Detector, env *Env) (rep Report, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("panic: %v", v)
		}
	}()
	return d.Check(ctx, env)
}

// emit stores a finding unless one with the same fingerprint was stored
// within the cooldown. The check uses the events table so it survives restarts.
func (m *Manager) emit(ctx context.Context, detector string, f Finding) (bool, error) {
	key := f.Key
	if key == "" {
		key = f.Source
	}
	fp := detector + "|" + f.Rule + "|" + key
	now := time.Now()

	m.emitMu.Lock()
	defer m.emitMu.Unlock()

	var n int
	err := m.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM events WHERE fingerprint = ? AND detected_at > ?",
		fp, now.Add(-m.cooldown).UTC().Format(time.RFC3339Nano)).Scan(&n)
	if err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}

	_, err = m.db.ExecContext(ctx,
		`INSERT INTO events (category, severity, source, message, detected_at, detector, rule, fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.Category, f.Severity, f.Source, f.Message, now.UTC().Format(time.RFC3339Nano), detector, f.Rule, fp)
	if err != nil {
		return false, err
	}
	m.log.Info("finding", "detector", detector, "rule", f.Rule, "severity", f.Severity, "source", f.Source, "message", f.Message)
	return true, nil
}

// CanaryTest runs the clipboard canary test and stores any findings.
func (m *Manager) CanaryTest(ctx context.Context) (CanaryResult, error) {
	for _, e := range m.entries {
		ct, ok := e.det.(canaryTester)
		if !ok {
			continue
		}
		res, findings, err := ct.CanaryTest(ctx)
		if err != nil {
			return res, err
		}
		for _, f := range findings {
			if stored, err := m.emit(ctx, e.det.Name(), f); err != nil {
				m.log.Error("store finding failed", "rule", f.Rule, "err", err)
			} else if stored {
				e.mu.Lock()
				e.status.Findings++
				e.mu.Unlock()
			}
		}
		return res, nil
	}
	return CanaryResult{}, ErrUnavailable
}

// Snapshot returns the latest structured state of a detector (nil if none yet).
func (m *Manager) Snapshot(name string) (any, bool) {
	for _, e := range m.entries {
		if e.det.Name() == name {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.snapshot, true
		}
	}
	return nil, false
}

// Status returns the current status of one detector.
func (m *Manager) Status(name string) (Status, bool) {
	for _, e := range m.entries {
		if e.det.Name() == name {
			e.mu.Lock()
			defer e.mu.Unlock()
			s := e.status
			s.Checks = append([]Check(nil), e.status.Checks...)
			return s, true
		}
	}
	return Status{}, false
}

func (m *Manager) Statuses() []Status {
	out := make([]Status, 0, len(m.entries))
	for _, e := range m.entries {
		e.mu.Lock()
		s := e.status
		s.Checks = append([]Check(nil), e.status.Checks...)
		e.mu.Unlock()
		out = append(out, s)
	}
	return out
}
