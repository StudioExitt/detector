package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DailyWriter writes to <dir>/<prefix>-YYYY-MM-DD.log and switches files when the date changes.
type DailyWriter struct {
	dir    string
	prefix string
	loc    *time.Location

	mu      sync.Mutex
	curDate string
	file    *os.File
}

func NewDailyWriter(dir, prefix string, loc *time.Location) (*DailyWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	w := &DailyWriter{dir: dir, prefix: prefix, loc: loc}
	if err := w.rotate(time.Now().In(loc).Format(time.DateOnly)); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *DailyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if date := time.Now().In(w.loc).Format(time.DateOnly); date != w.curDate {
		if err := w.rotate(date); err != nil {
			return 0, err
		}
	}
	return w.file.Write(p)
}

func (w *DailyWriter) rotate(date string) error {
	name := filepath.Join(w.dir, fmt.Sprintf("%s-%s.log", w.prefix, date))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	if w.file != nil {
		_ = w.file.Close()
	}
	w.file = f
	w.curDate = date
	return nil
}

func (w *DailyWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

type Options struct {
	Dir    string
	Prefix string
	Level  slog.Level
	Loc    *time.Location
	Stdout bool
}

// New builds a JSON slog logger backed by a daily log file (and optionally stdout).
func New(opts Options) (*slog.Logger, io.Closer, error) {
	dw, err := NewDailyWriter(opts.Dir, opts.Prefix, opts.Loc)
	if err != nil {
		return nil, nil, err
	}
	var out io.Writer = dw
	if opts.Stdout {
		out = io.MultiWriter(dw, os.Stdout)
	}
	h := slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level: opts.Level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				a.Value = slog.StringValue(a.Value.Time().In(opts.Loc).Format(time.RFC3339Nano))
			}
			return a
		},
	})
	return slog.New(h), dw, nil
}
