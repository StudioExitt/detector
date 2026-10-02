package detect

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// State persists detector baselines (known files, listeners, accounts ...)
// in the detect_state table so restarts don't re-report everything.
type State struct {
	db       *sql.DB
	detector string
}

// Load decodes the JSON value stored under key into v. It reports false when
// the key does not exist yet.
func (s *State) Load(ctx context.Context, key string, v any) (bool, error) {
	var raw string
	err := s.db.QueryRowContext(ctx,
		"SELECT value FROM detect_state WHERE detector = ? AND key = ?", s.detector, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load state %s/%s: %w", s.detector, key, err)
	}
	if err := json.Unmarshal([]byte(raw), v); err != nil {
		return false, fmt.Errorf("decode state %s/%s: %w", s.detector, key, err)
	}
	return true, nil
}

func (s *State) Save(ctx context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode state %s/%s: %w", s.detector, key, err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO detect_state (detector, key, value) VALUES (?, ?, ?)
		 ON CONFLICT(detector, key) DO UPDATE SET value = excluded.value,
		 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`,
		s.detector, key, string(raw))
	if err != nil {
		return fmt.Errorf("save state %s/%s: %w", s.detector, key, err)
	}
	return nil
}
