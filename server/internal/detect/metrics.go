package detect

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (m *Manager) storeMetrics(ctx context.Context, at time.Time, values map[string]float64) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO metrics (ts, name, value) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for name, v := range values {
		if _, err := stmt.ExecContext(ctx, at.Unix(), name, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (m *Manager) pruneMetricsLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		cutoff := time.Now().Add(-m.retention).Unix()
		if _, err := m.db.ExecContext(ctx, "DELETE FROM metrics WHERE ts < ?", cutoff); err != nil && ctx.Err() == nil {
			m.log.Warn("prune metrics failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type MetricPoint struct {
	At    time.Time
	Value float64
}

type MetricSeries struct {
	Name   string
	Points []MetricPoint
}

// QueryMetrics returns series for names within [now-window, now], averaged
// into at most maxPoints buckets so charts stay light for long ranges.
func (m *Manager) QueryMetrics(ctx context.Context, names []string, window time.Duration, maxPoints int) ([]MetricSeries, error) {
	if len(names) == 0 {
		return nil, nil
	}
	if maxPoints < 10 {
		maxPoints = 10
	}
	now := time.Now()
	from := now.Add(-window).Unix()
	bucket := max(int64(window.Seconds())/int64(maxPoints), 1)

	args := []any{bucket, bucket, from}
	for _, n := range names {
		args = append(args, n)
	}
	q := fmt.Sprintf(`SELECT name, (ts / ?) * ? AS b, AVG(value) FROM metrics
		WHERE ts >= ? AND name IN (%s) GROUP BY name, b ORDER BY name, b`,
		strings.TrimSuffix(strings.Repeat("?,", len(names)), ","))
	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byName := map[string]*MetricSeries{}
	for rows.Next() {
		var (
			name string
			b    int64
			v    float64
		)
		if err := rows.Scan(&name, &b, &v); err != nil {
			return nil, err
		}
		s, ok := byName[name]
		if !ok {
			s = &MetricSeries{Name: name}
			byName[name] = s
		}
		s.Points = append(s.Points, MetricPoint{At: time.Unix(b, 0), Value: v})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]MetricSeries, 0, len(names))
	for _, n := range names {
		if s, ok := byName[n]; ok {
			out = append(out, *s)
		} else {
			out = append(out, MetricSeries{Name: n})
		}
	}
	return out, nil
}
