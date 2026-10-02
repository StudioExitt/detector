package detect

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"detector/internal/config"
)

// unifiedLogSource reads macOS unified logging (`log show`) for:
//   - opendirectoryd "Authentication failed for ..." (every local password check:
//     screen unlock, sudo, System Settings prompts, SSH password via PAM)
//   - sshd / sshd-session accepted / failed logins
//   - sudo incorrect password attempts, NOT in sudoers
type unifiedLogSource struct {
	uuidUsers map[string]string // GeneratedUID -> short name
}

func newAuthSource(config.AuthDetectConfig) authSource {
	return &unifiedLogSource{uuidUsers: map[string]string{}}
}

func (s *unifiedLogSource) Name() string { return "macOS unified log" }

const unifiedLogPredicate = `(subsystem == "com.apple.opendirectoryd" AND category == "auth" AND eventMessage BEGINSWITH "Authentication failed for")` +
	` OR ((process == "sshd" OR process == "sshd-session") AND (eventMessage BEGINSWITH "Failed " OR eventMessage BEGINSWITH "Invalid user" OR eventMessage BEGINSWITH "Accepted "))` +
	` OR (process == "sudo" AND (eventMessage CONTAINS "incorrect password attempt" OR eventMessage CONTAINS "NOT in sudoers" OR eventMessage CONTAINS "not allowed to execute"))`

const (
	ulogTimeLayout = "2006-01-02 15:04:05.000000-0700"
	ulogCursorKey  = "cursor"
	firstLookback  = 10 * time.Minute
	maxLookback    = 24 * time.Hour
)

var reODAuthFailed = regexp.MustCompile(`^Authentication failed for (.+?) \(([0-9A-Fa-f-]{36})\): (\S+)`)

type ulogEntry struct {
	Timestamp        string `json:"timestamp"`
	ProcessImagePath string `json:"processImagePath"`
	Subsystem        string `json:"subsystem"`
	EventMessage     string `json:"eventMessage"`
}

func (s *unifiedLogSource) Fetch(ctx context.Context, env *Env) ([]authEvent, error) {
	var cursor string
	if _, err := env.State.Load(ctx, ulogCursorKey, &cursor); err != nil {
		return nil, err
	}
	start := time.Now().Add(-firstLookback)
	if cursor != "" {
		if t, err := time.Parse(ulogTimeLayout, cursor); err == nil {
			// `log show --start` has second precision; entries <= cursor are skipped below.
			start = t.Truncate(time.Second)
		}
	}
	if since := time.Since(start); since > maxLookback {
		start = time.Now().Add(-maxLookback)
	}

	runStart := time.Now()
	out, err := runCmd(ctx, 60*time.Second, "/usr/bin/log", "show",
		"--style", "ndjson",
		"--start", start.Local().Format("2006-01-02 15:04:05"),
		"--predicate", unifiedLogPredicate)
	if err != nil {
		return nil, err
	}

	var events []authEvent
	last := cursor
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e ulogEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.EventMessage == "" || e.Timestamp == "" {
			continue // trailing {"count":..,"finished":1} line
		}
		if cursor != "" && e.Timestamp <= cursor {
			continue
		}
		if e.Timestamp > last {
			last = e.Timestamp
		}
		ts, _ := time.Parse(ulogTimeLayout, e.Timestamp)

		var (
			ev authEvent
			ok bool
		)
		switch proc := filepath.Base(e.ProcessImagePath); {
		case e.Subsystem == "com.apple.opendirectoryd":
			ev, ok = s.parseODFailure(ctx, e.EventMessage)
		case proc == "sshd" || proc == "sshd-session":
			ev, ok = parseSSHD(e.EventMessage)
		case proc == "sudo":
			ev, ok = parseSudo(e.EventMessage)
		}
		if ok {
			ev.Time = ts
			events = append(events, ev)
		}
	}

	// Advance the cursor even when nothing matched so the query window stays
	// short. Keep a small margin for entries that reach the log store late.
	if safe := runStart.Add(-5 * time.Second).Format(ulogTimeLayout); safe > last {
		last = safe
	}
	if last != cursor {
		if err := env.State.Save(ctx, ulogCursorKey, last); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (s *unifiedLogSource) parseODFailure(ctx context.Context, msg string) (authEvent, bool) {
	m := reODAuthFailed.FindStringSubmatch(msg)
	if m == nil {
		return authEvent{}, false
	}
	user := m[1]
	if user == "<private>" {
		user = s.userForUUID(ctx, strings.ToUpper(m[2]))
	}
	return authEvent{Kind: authLocalFail, User: user, Method: m[3]}, true
}

// userForUUID maps a GeneratedUID to the account short name (user names are
// redacted as <private> in the unified log).
func (s *unifiedLogSource) userForUUID(ctx context.Context, uuid string) string {
	if u, ok := s.uuidUsers[uuid]; ok {
		return u
	}
	out, err := runCmd(ctx, 10*time.Second, "dscl", ".", "-list", "/Users", "GeneratedUID")
	if err == nil {
		for line := range strings.Lines(out) {
			f := strings.Fields(line)
			if len(f) == 2 {
				s.uuidUsers[strings.ToUpper(f[1])] = f[0]
			}
		}
	}
	if u, ok := s.uuidUsers[uuid]; ok {
		return u
	}
	return fmt.Sprintf("uuid:%s", uuid)
}
