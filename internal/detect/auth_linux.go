package detect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"detector/internal/config"
)

// linuxAuthSource tails the syslog auth file (/var/log/auth.log on Debian/Ubuntu,
// /var/log/secure on RHEL family). When no file is readable it falls back to
// journald (journalctl -t sshd -t sshd-session -t sudo).
type linuxAuthSource struct {
	files []string
	used  string
}

func newAuthSource(cfg config.AuthDetectConfig) authSource {
	return &linuxAuthSource{files: cfg.LogFiles}
}

func (s *linuxAuthSource) Name() string {
	if s.used == "" {
		return "linux auth log"
	}
	return s.used
}

type fileCursor struct {
	Path   string `json:"path"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

const maxReadPerRun = 16 << 20

func (s *linuxAuthSource) Fetch(ctx context.Context, env *Env) ([]authEvent, error) {
	var readErrs []string
	for _, p := range s.files {
		f, err := os.Open(p)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				readErrs = append(readErrs, err.Error())
			}
			continue
		}
		defer f.Close()
		s.used = p
		return s.fetchFile(ctx, env, f, p)
	}
	evs, err := s.fetchJournal(ctx, env)
	if err == nil {
		s.used = "journald"
		return evs, nil
	}
	if len(readErrs) > 0 {
		return nil, fmt.Errorf("auth log not readable (run as root or add the user to group adm): %s; journald: %v",
			strings.Join(readErrs, "; "), err)
	}
	return nil, fmt.Errorf("no auth log found (%s) and journald unavailable: %w", strings.Join(s.files, ", "), err)
}

func (s *linuxAuthSource) fetchFile(ctx context.Context, env *Env, f *os.File, path string) ([]authEvent, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	var inode uint64
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		inode = st.Ino
	}

	var cur fileCursor
	found, err := env.State.Load(ctx, "file_cursor", &cur)
	if err != nil {
		return nil, err
	}
	switch {
	case !found || cur.Path != path:
		// first run: start from the end so old history isn't reported
		cur = fileCursor{Path: path, Inode: inode, Offset: fi.Size()}
		return nil, env.State.Save(ctx, "file_cursor", cur)
	case cur.Inode != inode || fi.Size() < cur.Offset:
		// rotated or truncated
		cur = fileCursor{Path: path, Inode: inode, Offset: 0}
	}

	if _, err := f.Seek(cur.Offset, io.SeekStart); err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(io.LimitReader(f, maxReadPerRun))
	if err != nil {
		return nil, err
	}
	// only consume complete lines
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		buf = buf[:i+1]
	} else {
		buf = nil
	}

	var events []authEvent
	sc := bufio.NewScanner(bytes.NewReader(buf))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if ev, ok := parseSyslogAuth(sc.Text()); ok {
			events = append(events, ev)
		}
	}

	cur.Offset += int64(len(buf))
	cur.Inode = inode
	return events, env.State.Save(ctx, "file_cursor", cur)
}

type journalEntry struct {
	Cursor     string `json:"__CURSOR"`
	Realtime   string `json:"__REALTIME_TIMESTAMP"`
	Identifier string `json:"SYSLOG_IDENTIFIER"`
	Message    any    `json:"MESSAGE"` // string, or byte array for non-UTF8
}

func (s *linuxAuthSource) fetchJournal(ctx context.Context, env *Env) ([]authEvent, error) {
	var cursor string
	if _, err := env.State.Load(ctx, "journal_cursor", &cursor); err != nil {
		return nil, err
	}
	// until the first matching entry gives us a cursor, query by time
	var since int64
	if _, err := env.State.Load(ctx, "journal_since", &since); err != nil {
		return nil, err
	}
	runStart := time.Now()
	args := []string{"--no-pager", "-q", "-o", "json", "-t", "sshd", "-t", "sshd-session", "-t", "sudo"}
	switch {
	case cursor != "":
		args = append(args, "--after-cursor", cursor)
	case since > 0:
		args = append(args, "--since", fmt.Sprintf("@%d", since))
	default:
		args = append(args, "--since", "-10min")
	}
	out, err := runCmd(ctx, 60*time.Second, "journalctl", args...)
	if err != nil {
		return nil, err
	}

	var events []authEvent
	last := cursor
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e journalEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		last = e.Cursor
		msg, ok := e.Message.(string)
		if !ok {
			continue
		}
		ev, ok := parseLinuxAuth(e.Identifier, msg)
		if !ok {
			continue
		}
		if us, err := strconv.ParseInt(e.Realtime, 10, 64); err == nil {
			ev.Time = time.UnixMicro(us)
		}
		events = append(events, ev)
	}
	if last != cursor && last != "" {
		if err := env.State.Save(ctx, "journal_cursor", last); err != nil {
			return nil, err
		}
	} else if last == "" {
		if err := env.State.Save(ctx, "journal_since", runStart.Unix()); err != nil {
			return nil, err
		}
	}
	return events, nil
}
