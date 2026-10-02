package detect

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// runsPerDetector is how many run records are kept per detector.
const runsPerDetector = 500

// Run is one recorded detector execution.
type Run struct {
	ID         int64
	StartedAt  time.Time
	Duration   time.Duration
	Error      string
	Summary    string
	Findings   int64
	ChecksOK   int
	ChecksWarn int
	ChecksFail int
	Checks     []Check // only filled by RunDetail
}

var ErrNotFound = errors.New("not found")

// recordRun stores a run. With replaceOK the previous successful runs of the
// detector are removed first, so only the latest one remains.
func (m *Manager) recordRun(ctx context.Context, name string, start time.Time, dur time.Duration, runErr error, rep Report, stored int64, replaceOK bool) error {
	var ok, warn, fail int
	for _, c := range rep.Checks {
		switch c.Status {
		case CheckOK:
			ok++
		case CheckWarn:
			warn++
		default:
			fail++
		}
	}
	checks, err := json.Marshal(rep.Checks)
	if err != nil {
		return err
	}
	if rep.Checks == nil {
		checks = []byte("[]")
	}
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
	}
	if replaceOK {
		if _, err := m.db.ExecContext(ctx,
			"DELETE FROM detect_runs WHERE detector = ? AND error = '' AND findings = 0", name); err != nil {
			return err
		}
	}
	res, err := m.db.ExecContext(ctx,
		`INSERT INTO detect_runs (detector, started_at, duration_ms, error, summary, findings, checks_ok, checks_warn, checks_fail, checks)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		name, start.UTC().Format(time.RFC3339Nano), dur.Milliseconds(), errMsg, rep.Summary, stored, ok, warn, fail, string(checks))
	if err != nil {
		return err
	}
	// prune occasionally to keep the table bounded
	if id, _ := res.LastInsertId(); id%50 == 0 {
		_, err = m.db.ExecContext(ctx,
			`DELETE FROM detect_runs WHERE detector = ? AND id <= (
			   SELECT id FROM detect_runs WHERE detector = ? ORDER BY id DESC LIMIT 1 OFFSET ?)`,
			name, name, runsPerDetector)
	}
	return err
}

// Runs lists recorded runs of a detector, newest first (without checks).
func (m *Manager) Runs(ctx context.Context, name string, limit, offset int) ([]Run, int64, error) {
	var total int64
	if err := m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM detect_runs WHERE detector = ?", name).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count runs: %w", err)
	}
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, started_at, duration_ms, error, summary, findings, checks_ok, checks_warn, checks_fail
		 FROM detect_runs WHERE detector = ? ORDER BY id DESC LIMIT ? OFFSET ?`, name, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query runs: %w", err)
	}
	defer rows.Close()
	runs := []Run{}
	for rows.Next() {
		r, err := scanRun(rows, false)
		if err != nil {
			return nil, 0, err
		}
		runs = append(runs, r)
	}
	return runs, total, rows.Err()
}

// RunDetail returns one run including the checks recorded at that time.
func (m *Manager) RunDetail(ctx context.Context, name string, id int64) (Run, error) {
	row := m.db.QueryRowContext(ctx,
		`SELECT id, started_at, duration_ms, error, summary, findings, checks_ok, checks_warn, checks_fail, checks
		 FROM detect_runs WHERE detector = ? AND id = ?`, name, id)
	r, err := scanRun(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	return r, err
}

type scanner interface{ Scan(...any) error }

func scanRun(s scanner, withChecks bool) (Run, error) {
	var (
		r       Run
		started string
		durMs   int64
		checks  string
	)
	dest := []any{&r.ID, &started, &durMs, &r.Error, &r.Summary, &r.Findings, &r.ChecksOK, &r.ChecksWarn, &r.ChecksFail}
	if withChecks {
		dest = append(dest, &checks)
	}
	if err := s.Scan(dest...); err != nil {
		return Run{}, err
	}
	r.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	r.Duration = time.Duration(durMs) * time.Millisecond
	if withChecks {
		if err := json.Unmarshal([]byte(checks), &r.Checks); err != nil {
			return Run{}, fmt.Errorf("decode checks: %w", err)
		}
	}
	return r, nil
}
