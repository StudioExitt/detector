package detect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"detector/internal/config"
)

// clipboardDetector watches the macOS pasteboard for "clipper" malware that
// replaces a copied wallet address with the attacker's. macOS has no change
// notification, so clippers poll too; polling faster (50ms) lets us observe
// the original address before it is replaced.
//
// Privacy: only values that parse as a wallet address are kept (in memory,
// masked in status). Other clipboard content is never stored or logged.
type clipboardDetector struct {
	cfg  config.ClipboardDetectConfig
	reqs chan canaryReq

	mu         sync.Mutex
	running    bool
	startErr   string
	changes    int64
	addrCopies int64
	swaps      int64
	recent     []clipRecent // newest last
	pending    []Finding
	targets    map[string]int // swap target (normalized) -> times seen
	lastCanary *CanaryResult
}

type clipRecent struct {
	At      time.Time
	Chain   string
	Masked  string
	Verdict clipVerdict
	Self    bool
}

type canaryReq struct {
	resp chan canaryResp
}

type canaryResp struct {
	res      CanaryResult
	findings []Finding
	err      error
}

func newClipboardDetector(cfg config.ClipboardDetectConfig) Detector {
	return &clipboardDetector{cfg: cfg, reqs: make(chan canaryReq), targets: map[string]int{}}
}

func (d *clipboardDetector) Name() string { return "clipboard" }

// CompactSuccessfulRuns: checked every few seconds, so only the latest
// successful run is kept; runs with findings or errors stay in the history.
func (d *clipboardDetector) CompactSuccessfulRuns() bool { return true }

func (d *clipboardDetector) Start(ctx context.Context, env *Env) {
	go d.watch(ctx, env.Log, env.Host)
}

func (d *clipboardDetector) watch(ctx context.Context, log *slog.Logger, host string) {
	// NSAutoreleasePool and pasteboard access stay on one OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pb, err := openPasteboard()
	if err != nil {
		d.mu.Lock()
		d.startErr = err.Error()
		d.mu.Unlock()
		log.Warn("clipboard watcher unavailable", "err", err)
		return
	}
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
	}()

	self := map[int]bool{} // change counts produced by our own writes
	prev := d.observe(pb, pb.ChangeCount(), self)
	prev.Count = max(prev.Count, 1)

	t := time.NewTicker(d.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-d.reqs:
			res, findings, err := d.runCanary(ctx, pb, self, host)
			req.resp <- canaryResp{res, findings, err}
			prev = d.observe(pb, pb.ChangeCount(), self)
		case <-t.C:
			cc := pb.ChangeCount()
			if cc == prev.Count {
				continue
			}
			cur := d.observe(pb, cc, self)
			d.record(prev, cur, host)
			prev = cur
		}
	}
}

// observe reads the clipboard at change count cc.
func (d *clipboardDetector) observe(pb *pasteboard, cc int, self map[int]bool) clipObservation {
	obs := clipObservation{Count: cc, At: time.Now(), Self: self[cc]}
	for k := range self {
		if k <= cc {
			delete(self, k)
		}
	}
	if s, ok := pb.ReadString(); ok {
		obs.Addr = parseCryptoAddr(s)
	}
	return obs
}

func (d *clipboardDetector) record(prev, cur clipObservation, host string) {
	verdict := judgeClipChange(prev, cur, d.cfg.SwapWindow)

	d.mu.Lock()
	defer d.mu.Unlock()
	d.changes++
	if cur.Addr == nil {
		return
	}
	if !cur.Self {
		d.addrCopies++
	}
	d.recent = append(d.recent, clipRecent{At: cur.At, Chain: cur.Addr.Chain, Masked: maskAddr(cur.Addr.Raw), Verdict: verdict, Self: cur.Self})
	if len(d.recent) > 20 {
		d.recent = d.recent[len(d.recent)-20:]
	}

	switch verdict {
	case clipSwapped:
		d.swaps++
		d.targets[cur.Addr.Norm]++
		pre, suf := lookalike(prev.Addr.Raw, cur.Addr.Raw)
		var notes []string
		if pre >= 3 || suf >= 3 {
			notes = append(notes, fmt.Sprintf("앞 %d자·뒤 %d자가 같은 유사 주소 — 육안 비교 회피형", pre, suf))
		}
		if n := d.targets[cur.Addr.Norm]; n > 1 {
			notes = append(notes, fmt.Sprintf("같은 주소로 %d회 교체", n))
		}
		msg := fmt.Sprintf("클립보드 지갑 주소 바꿔치기 의심 (%s): 복사한 주소 %s 가 %dms 만에 %s 로 자동 변경됨",
			cur.Addr.Chain, maskAddr(prev.Addr.Raw), cur.At.Sub(prev.At).Milliseconds(), cur.Addr.Raw)
		if len(notes) > 0 {
			msg += " (" + strings.Join(notes, ", ") + ")"
		}
		d.pending = append(d.pending, Finding{
			Rule: "clipboard.address_swapped", Category: CategoryIntrusion, Severity: SevCritical,
			Source: host, Key: cur.Addr.Norm, Message: msg + " — 붙여넣기 전 주소 전체를 확인하고 클리퍼(자동 실행 항목, 브라우저 확장)를 점검하세요",
		})
	case clipRapidRewrite:
		d.pending = append(d.pending, Finding{
			Rule: "clipboard.rapid_rewrite", Category: CategoryIntrusion, Severity: SevMedium,
			Source: host, Key: cur.Addr.Norm,
			Message: fmt.Sprintf("클립보드가 %s 사이 %d회 변경되었고 결과가 %s 주소 %s — 복사 직후 다른 프로그램이 덮어썼을 가능성",
				d.cfg.PollInterval, cur.Count-prev.Count, cur.Addr.Chain, cur.Addr.Raw),
		})
	}
}

func (d *clipboardDetector) Check(_ context.Context, _ *Env) (Report, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	findings := d.pending
	d.pending = nil

	if d.startErr != "" {
		return Report{Checks: []Check{{Name: "pasteboard", Status: CheckFail, Detail: d.startErr}}}, errors.New(d.startErr)
	}

	checks := []Check{}
	if d.running {
		checks = append(checks, Check{Name: "pasteboard", Status: CheckOK, Detail: "NSPasteboard 감시 중 (purego, no cgo)"})
	} else {
		checks = append(checks, Check{Name: "pasteboard", Status: CheckWarn, Detail: "감시 시작 대기 중"})
	}
	if os.Geteuid() == 0 {
		checks = append(checks, Check{Name: "session", Status: CheckWarn,
			Detail: "root 로 실행 중 — 클립보드는 로그인 사용자 세션에 속하므로 사용자 권한(LaunchAgent)으로 실행해야 정확함"})
	} else if u, err := user.Current(); err == nil {
		checks = append(checks, Check{Name: "session", Status: CheckOK, Detail: "사용자 " + u.Username + " 의 클립보드"})
	}
	checks = append(checks, Check{Name: "settings", Status: CheckOK,
		Detail: fmt.Sprintf("poll %s, swap window %s, canary wait %s", d.cfg.PollInterval, d.cfg.SwapWindow, d.cfg.CanaryWait)})

	if c := d.lastCanary; c != nil {
		st, detail := CheckOK, "이상 없음"
		if c.Swapped {
			st, detail = CheckFail, "미끼 주소가 다른 주소로 바뀜 — 클리퍼 존재"
		}
		checks = append(checks, Check{Name: "canary test " + c.StartedAt.Format("01-02 15:04:05"), Status: st, Detail: detail})
	}
	for i := len(d.recent) - 1; i >= 0; i-- {
		r := d.recent[i]
		st, note := CheckOK, "주소 복사"
		switch {
		case r.Self:
			note = "탐지기 테스트/복원"
		case r.Verdict == clipSwapped:
			st, note = CheckFail, "⚠ 바꿔치기 의심 (교체된 주소)"
		case r.Verdict == clipRapidRewrite:
			st, note = CheckWarn, "연속 변경 후 주소"
		}
		checks = append(checks, Check{Name: r.At.Format("15:04:05.000") + " " + r.Chain, Status: st, Detail: r.Masked + " — " + note})
	}

	return Report{
		Findings: findings,
		Summary: fmt.Sprintf("클립보드 감시 중 (%s 간격): 변경 %d회, 지갑 주소 복사 %d회, 바꿔치기 의심 %d회 (기동 후)",
			d.cfg.PollInterval, d.changes, d.addrCopies, d.swaps),
		Checks: checks,
	}, nil
}

// CanaryTest asks the watcher goroutine (which owns the pasteboard) to run the test.
func (d *clipboardDetector) CanaryTest(ctx context.Context) (CanaryResult, []Finding, error) {
	d.mu.Lock()
	running, startErr := d.running, d.startErr
	d.mu.Unlock()
	if !running {
		if startErr != "" {
			return CanaryResult{}, nil, errors.New(startErr)
		}
		return CanaryResult{}, nil, errors.New("clipboard watcher is not running")
	}
	req := canaryReq{resp: make(chan canaryResp, 1)}
	select {
	case d.reqs <- req:
	case <-ctx.Done():
		return CanaryResult{}, nil, ctx.Err()
	}
	select {
	case r := <-req.resp:
		return r.res, r.findings, r.err
	case <-ctx.Done():
		return CanaryResult{}, nil, ctx.Err()
	}
}

// runCanary puts each bait address on the clipboard, waits for a foreign
// change, then restores the user's original clipboard (all representations).
func (d *clipboardDetector) runCanary(ctx context.Context, pb *pasteboard, self map[int]bool, host string) (CanaryResult, []Finding, error) {
	start := time.Now()
	res := CanaryResult{StartedAt: start}
	before := pb.ChangeCount()
	saved := pb.Snapshot()

	var findings []Finding
	for _, c := range canaryAddrs {
		if ctx.Err() != nil {
			res.Note = "취소됨"
			break
		}
		cc := pb.WriteString(c.addr)
		chk := CanaryCheck{Chain: c.chain, Canary: c.addr}
		written := time.Now()
		for time.Since(written) < d.cfg.CanaryWait {
			time.Sleep(20 * time.Millisecond)
			now := pb.ChangeCount()
			if now == cc {
				continue
			}
			s, _ := pb.ReadString()
			chk.Changed = true
			chk.AfterMs = time.Since(written).Milliseconds()
			chk.Observed, chk.Swapped = judgeCanaryChange(c.chain, c.addr, s)
			break
		}
		if chk.Swapped {
			res.Swapped = true
			findings = append(findings, Finding{
				Rule: "clipboard.canary_swapped", Category: CategoryIntrusion, Severity: SevCritical, Source: host, Key: chk.Observed,
				Message: fmt.Sprintf("클립보드 카나리아 테스트: 미끼 %s 주소 %s 가 %dms 만에 %s 로 바뀜 — 클리퍼 악성코드가 실행 중 (공격자 주소로 추정)",
					c.chain, maskAddr(c.addr), chk.AfterMs, chk.Observed),
			})
		}
		res.Checks = append(res.Checks, chk)
	}

	res.Restored = pb.Restore(saved)
	after := pb.ChangeCount()
	for k := before + 1; k <= after; k++ {
		self[k] = true
	}
	res.DurationMs = time.Since(start).Milliseconds()

	d.mu.Lock()
	r := res
	d.lastCanary = &r
	if res.Swapped {
		d.swaps++
	}
	d.mu.Unlock()
	return res, findings, nil
}
