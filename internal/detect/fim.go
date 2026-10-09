package detect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"detector/internal/config"
)

// fimRule is a watched path (glob allowed). Directories are walked.
type fimRule struct {
	Pattern  string
	Severity string // severity for add/modify
	Note     string // why it matters, shown in the message
}

type fimEntry struct {
	Hash string      `json:"h"` // sha256, or "meta:<size>:<mtime>" when unreadable
	Mode fs.FileMode `json:"m"`
	Rule int         `json:"r"` // index into rules
}

const (
	fimMaxFileSize = 32 << 20
	fimMaxFiles    = 20000
	fimMaxDepth    = 4
	fimBaselineKey = "baseline"
)

type fimDetector struct {
	rules []fimRule
}

func newFIMDetector(cfg config.FIMDetectConfig) Detector {
	rules := fimRules()
	for _, p := range cfg.ExtraPaths {
		rules = append(rules, fimRule{Pattern: p, Severity: SevMedium, Note: "사용자 지정 감시 경로"})
	}
	if len(rules) == 0 {
		return nil
	}
	return &fimDetector{rules: rules}
}

func (d *fimDetector) Name() string { return "fim" }

func (d *fimDetector) Check(ctx context.Context, env *Env) (Report, error) {
	cur, unreadable := d.scan(ctx)

	var prev map[string]fimEntry
	found, err := env.State.Load(ctx, fimBaselineKey, &prev)
	if err != nil {
		return Report{}, err
	}
	if err := env.State.Save(ctx, fimBaselineKey, cur); err != nil {
		return Report{}, err
	}
	checks := d.ruleChecks(cur, unreadable)
	if !found {
		return Report{Summary: fmt.Sprintf("기준선 생성: 파일 %d개 (읽기 불가 %d개는 크기/수정시각으로 감시)", len(cur), unreadable), Checks: checks}, nil
	}

	var findings []Finding
	var added, modified, removed int
	for _, path := range sortedKeys(cur) {
		e := cur[path]
		rule := d.rule(e.Rule)
		p, existed := prev[path]
		switch {
		case !existed:
			added++
			msg := fmt.Sprintf("새 파일 생성: %s — %s", path, rule.Note)
			sev := rule.Severity
			if extra, bump := fimEnrich(ctx, path); extra != "" {
				msg += " | " + extra
				if bump {
					sev = SevCritical
				}
			}
			findings = append(findings, Finding{Rule: "fim.added", Category: CategoryIntrusion, Severity: sev, Source: path, Message: msg})
		case p.Hash != e.Hash:
			modified++
			msg := fmt.Sprintf("파일 변경: %s — %s", path, rule.Note)
			sev := rule.Severity
			if extra, bump := fimEnrich(ctx, path); extra != "" {
				msg += " | " + extra
				if bump {
					sev = SevCritical
				}
			}
			findings = append(findings, Finding{Rule: "fim.modified", Category: CategoryIntrusion, Severity: sev, Source: path, Message: msg, Key: path + "|" + e.Hash})
		case p.Mode != e.Mode:
			modified++
			sev := SevMedium
			if e.Mode&(fs.ModeSetuid|fs.ModeSetgid) != 0 && p.Mode&(fs.ModeSetuid|fs.ModeSetgid) == 0 {
				sev = SevHigh
			}
			findings = append(findings, Finding{Rule: "fim.mode_changed", Category: CategoryIntrusion, Severity: sev, Source: path,
				Message: fmt.Sprintf("권한 변경: %s (%s → %s) — %s", path, p.Mode, e.Mode, rule.Note), Key: path + "|" + e.Mode.String()})
		}
	}
	for _, path := range sortedKeys(prev) {
		if _, ok := cur[path]; ok {
			continue
		}
		removed++
		rule := d.rule(prev[path].Rule)
		findings = append(findings, Finding{Rule: "fim.removed", Category: CategoryIntrusion, Severity: lower(rule.Severity), Source: path,
			Message: fmt.Sprintf("파일 삭제: %s — %s", path, rule.Note)})
	}

	return Report{
		Findings: findings,
		Summary:  fmt.Sprintf("파일 %d개 감시 (읽기 불가 %d) — 추가 %d, 변경 %d, 삭제 %d", len(cur), unreadable, added, modified, removed),
		Checks:   checks,
	}, nil
}

func (d *fimDetector) rule(i int) fimRule {
	if i >= 0 && i < len(d.rules) {
		return d.rules[i]
	}
	return fimRule{Severity: SevMedium}
}

func (d *fimDetector) scan(ctx context.Context) (map[string]fimEntry, int) {
	out := map[string]fimEntry{}
	unreadable := 0
	add := func(path string, fi fs.FileInfo, rule int) {
		if len(out) >= fimMaxFiles || !fi.Mode().IsRegular() {
			return
		}
		if _, dup := out[path]; dup {
			return
		}
		h, err := hashFile(path, fi)
		if err != nil {
			unreadable++
			h = fmt.Sprintf("meta:%d:%d", fi.Size(), fi.ModTime().UnixNano())
		}
		out[path] = fimEntry{Hash: h, Mode: fi.Mode(), Rule: rule}
	}

	for i, r := range d.rules {
		if ctx.Err() != nil {
			break
		}
		matches, _ := filepath.Glob(r.Pattern)
		for _, m := range matches {
			root, err := filepath.EvalSymlinks(m) // e.g. /etc -> /private/etc on macOS
			if err != nil {
				continue
			}
			fi, err := os.Stat(root)
			if err != nil {
				continue
			}
			if !fi.IsDir() {
				add(m, fi, i)
				continue
			}
			depth0 := strings.Count(root, string(os.PathSeparator))
			_ = filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
				if err != nil {
					if de != nil && de.IsDir() && p != root {
						unreadable++
					}
					return nil
				}
				if de.IsDir() {
					if strings.Count(p, string(os.PathSeparator))-depth0 >= fimMaxDepth {
						return filepath.SkipDir
					}
					return nil
				}
				if info, err := de.Info(); err == nil {
					// report with the user-facing prefix (/etc rather than /private/etc)
					add(filepath.Join(m, strings.TrimPrefix(p, root)), info, i)
				}
				return nil
			})
		}
	}
	return out, unreadable
}

func (d *fimDetector) ruleChecks(cur map[string]fimEntry, unreadable int) []Check {
	counts := make([]int, len(d.rules))
	for _, e := range cur {
		if e.Rule >= 0 && e.Rule < len(counts) {
			counts[e.Rule]++
		}
	}
	var checks []Check
	for i, r := range d.rules {
		if counts[i] == 0 {
			continue
		}
		checks = append(checks, Check{Name: r.Pattern, Status: CheckOK, Detail: fmt.Sprintf("%d개 — %s", counts[i], r.Note)})
	}
	if unreadable > 0 {
		checks = append(checks, Check{Name: "unreadable", Status: CheckWarn,
			Detail: fmt.Sprintf("%d개는 권한 부족으로 내용 대신 크기/수정시각만 비교 (root 실행 권장)", unreadable)})
	}
	return checks
}

func hashFile(path string, fi fs.FileInfo) (string, error) {
	if fi.Size() > fimMaxFileSize {
		return "", errors.New("too large")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func lower(sev string) string {
	switch sev {
	case SevCritical:
		return SevHigh
	case SevHigh:
		return SevMedium
	default:
		return SevLow
	}
}
