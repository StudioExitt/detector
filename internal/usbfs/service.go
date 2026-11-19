package usbfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"detector/internal/config"
	"detector/internal/usbfs/mtp"
)

// Location kinds.
const (
	KindPC     = "pc"
	KindVolume = "volume"
	KindMTP    = "mtp"
)

// Location is a place files can be copied from / to.
type Location struct {
	ID       string // pc:<n> / vol:<volume id> / mtp:<device id>:<storage id hex>
	Kind     string
	Name     string
	Detail   string
	Size     int64
	Free     int64
	ReadOnly bool
	Error    string // not usable right now (and why)
}

// Volume is a mounted external disk volume (from the usb detector).
type Volume struct {
	ID         string // disk4s1 / sdb1
	Disk       string // disk4 / sdb
	Name       string
	Device     string // disk / device name
	MountPoint string
	Size       int64
	Free       int64
	ReadOnly   bool
}

// Deps connects the service to the usb detector.
type Deps struct {
	Volumes   func() []Volume
	SelfWrite func(disk string, n uint64) // bytes this service wrote to an external disk
	Record    func(ctx context.Context, target, detail string, ok bool)
	Log       *slog.Logger
}

// Service lists locations and runs one transfer job at a time.
type Service struct {
	dirs []string // resolved PC folders
	raw  []string // as configured (for display)
	deps Deps

	mu     sync.Mutex
	jobs   []*Job
	nextID int
	active *Job
	cache  map[string][]Location // MTP locations seen last (shown while a job holds the device); under mu
	mtpMu  sync.Mutex            // one MTP session at a time (listing or a job)
}

func New(cfg config.TransferConfig, deps Deps) *Service {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	s := &Service{deps: deps, cache: map[string][]Location{}}
	for _, d := range cfg.LocalDirs {
		s.raw = append(s.raw, d)
		s.dirs = append(s.dirs, expandHome(d))
	}
	return s
}

// ── locations ──

func (s *Service) Locations(_ context.Context) ([]Location, []string) {
	var out []Location
	var notes []string
	for i, d := range s.dirs {
		l := Location{ID: "pc:" + strconv.Itoa(i), Kind: KindPC, Name: s.raw[i], Detail: d}
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			l.Error = "폴더가 없음"
		} else {
			l.Size, l.Free = diskSpace(d)
		}
		out = append(out, l)
	}
	if s.deps.Volumes != nil {
		for _, v := range s.deps.Volumes() {
			out = append(out, Location{ID: "vol:" + v.ID, Kind: KindVolume, Name: firstNonEmpty(v.Name, v.ID),
				Detail: v.MountPoint + " · " + firstNonEmpty(v.Device, v.Disk), Size: v.Size, Free: v.Free, ReadOnly: v.ReadOnly})
		}
	}
	mtpLocs, err := s.mtpLocations()
	if err != nil {
		notes = append(notes, "휴대폰(MTP): "+err.Error())
	}
	out = append(out, mtpLocs...)
	return out, notes
}

func (s *Service) mtpLocations() ([]Location, error) {
	devs, err := mtp.Devices()
	if err != nil {
		return nil, err
	}
	if !s.mtpMu.TryLock() {
		var out []Location
		for _, d := range devs {
			if c := s.cachedLocs(d.ID); c != nil {
				out = append(out, c...)
			} else {
				out = append(out, Location{ID: "mtp:" + d.ID + ":", Kind: KindMTP, Name: d.Name, Detail: devDetail(d), Error: "전송 중"})
			}
		}
		return out, nil
	}
	defer s.mtpMu.Unlock()
	var out []Location
	cache := map[string][]Location{}
	for _, d := range devs {
		locs := s.probeMTP(d)
		cache[d.ID] = locs
		out = append(out, locs...)
	}
	s.mu.Lock()
	s.cache = cache
	s.mu.Unlock()
	return out, nil
}

func devDetail(d mtp.Device) string {
	parts := []string{fmt.Sprintf("%04x:%04x", d.VendorID, d.ProductID)}
	if d.Vendor != "" {
		parts = append(parts, d.Vendor)
	}
	return strings.Join(parts, " · ")
}

func (s *Service) probeMTP(d mtp.Device) []Location {
	base := Location{ID: "mtp:" + d.ID + ":", Kind: KindMTP, Name: d.Name, Detail: devDetail(d)}
	sess, err := d.Open()
	if err != nil {
		base.Error = err.Error()
		return []Location{base}
	}
	defer sess.Close()
	sts, err := sess.Storages()
	if err != nil {
		base.Error = err.Error()
		return []Location{base}
	}
	if len(sts) == 0 {
		base.Error = "저장소가 보이지 않음 — 휴대폰 잠금을 풀고 USB 사용 모드를 '파일 전송'으로 선택하세요"
		return []Location{base}
	}
	var out []Location
	for _, st := range sts {
		l := base
		l.ID = fmt.Sprintf("mtp:%s:%08x", d.ID, st.ID)
		l.Name = d.Name + " · " + firstNonEmpty(st.Description, st.Label, fmt.Sprintf("저장소 %08x", st.ID))
		l.Size, l.Free, l.ReadOnly = int64(st.Capacity), int64(st.Free), st.ReadOnly
		out = append(out, l)
	}
	return out
}

// opened is a location opened for use; release must be called.
type opened struct {
	loc     Location
	store   Store
	disk    string // external disk written to (bulk-write accounting)
	release func()
}

func (s *Service) open(ctx context.Context, id string, waitMTP bool) (*opened, error) {
	kind, rest, _ := strings.Cut(id, ":")
	switch kind {
	case "pc":
		i, err := strconv.Atoi(rest)
		if err != nil || i < 0 || i >= len(s.dirs) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		st, err := openLocal(s.dirs[i], true)
		if err != nil {
			return nil, err
		}
		return &opened{loc: Location{ID: id, Kind: KindPC, Name: s.raw[i]}, store: st, release: func() { st.Close() }}, nil
	case "vol":
		if s.deps.Volumes != nil {
			for _, v := range s.deps.Volumes() {
				if v.ID != rest {
					continue
				}
				st, err := openLocal(v.MountPoint, false)
				if err != nil {
					return nil, err
				}
				return &opened{loc: Location{ID: id, Kind: KindVolume, Name: firstNonEmpty(v.Name, v.ID), ReadOnly: v.ReadOnly},
					store: st, disk: v.Disk, release: func() { st.Close() }}, nil
			}
		}
		return nil, fmt.Errorf("%w: %s (분리되었거나 마운트되지 않음)", ErrNotFound, id)
	case "mtp":
		devID, stHex, _ := strings.Cut(rest, ":")
		stID, err := strconv.ParseUint(stHex, 16, 32)
		if err != nil {
			if c := s.cachedError("mtp:" + rest); c != "" {
				return nil, errors.New(c)
			}
			return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		devs, err := mtp.Devices()
		if err != nil {
			return nil, err
		}
		for _, d := range devs {
			if d.ID != devID {
				continue
			}
			if waitMTP {
				s.mtpMu.Lock()
			} else if !s.mtpMu.TryLock() {
				return nil, fmt.Errorf("%w — 끝난 뒤 다시 시도하세요", ErrBusy)
			}
			st, err := openMTP(d, uint32(stID))
			if err != nil {
				s.mtpMu.Unlock()
				return nil, err
			}
			name := d.Name
			for _, l := range s.cachedLocs(d.ID) {
				if l.ID == id {
					name = l.Name
				}
			}
			return &opened{loc: Location{ID: id, Kind: KindMTP, Name: name}, store: st,
				release: func() { st.Close(); s.mtpMu.Unlock() }}, nil
		}
		return nil, mtp.ErrNotFound
	}
	_ = ctx
	return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
}

func (s *Service) cachedLocs(devID string) []Location {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cache[devID]
}

func (s *Service) cachedError(id string) string {
	devID, _, _ := strings.Cut(strings.TrimPrefix(id, "mtp:"), ":")
	for _, l := range s.cachedLocs(devID) {
		if l.Error != "" {
			return l.Error
		}
	}
	return ""
}

// Listing is the content of one folder.
type Listing struct {
	Location Location
	Dir      string
	Entries  []Entry
}

// List returns the folder dir ("" = top) of a location; exts filters files by
// extension (folders are always included).
func (s *Service) List(ctx context.Context, locID, dir string, exts []string) (Listing, error) {
	o, err := s.open(ctx, locID, false)
	if err != nil {
		return Listing{}, err
	}
	defer o.release()
	es, err := o.store.List(ctx, dir)
	if err != nil {
		return Listing{}, err
	}
	if len(exts) > 0 {
		f := es[:0]
		for _, e := range es {
			if e.Dir || hasExt(e.Name, exts) {
				f = append(f, e)
			}
		}
		es = f
	}
	return Listing{Location: o.loc, Dir: dir, Entries: es}, nil
}

func hasExt(name string, exts []string) bool {
	n := strings.ToLower(name)
	for _, x := range exts {
		if x = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(x), ".")); x != "" && strings.HasSuffix(n, "."+x) {
			return true
		}
	}
	return false
}

// ── jobs ──

// Job states.
const (
	JobRunning  = "running"
	JobDone     = "done"
	JobFailed   = "failed"
	JobCanceled = "canceled"
)

type FileResult struct {
	Name  string
	OK    bool
	Error string
}

// Job is a transfer; the fields are copied out under Service.mu.
type Job struct {
	ID         int
	From, To   string // location ids
	FromName   string
	ToName     string
	Move       bool
	State      string
	Files      int
	Folders    int // folders created (or reused) at the destination
	Done       int
	Failed     int
	Skipped    int
	Bytes      int64
	BytesDone  int64
	Current    string
	StartedAt  time.Time
	FinishedAt time.Time
	Results    []FileResult

	cancel context.CancelFunc
}

// Request starts a transfer of items (entry ids in fromDir: files or whole
// folders) into toDir.
type Request struct {
	From      string
	FromDir   string
	Items     []string
	To        string
	ToDir     string
	Move      bool
	Overwrite bool
	// files inside selected folders are filtered by extension (empty = all);
	// subfolders without matching files are not created
	Ext []string
}

// maxPlan bounds the number of files + folders in one job.
const maxPlan = 50000

// Jobs returns recent jobs, newest first.
func (s *Service) Jobs() []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Job, 0, len(s.jobs))
	for i := len(s.jobs) - 1; i >= 0; i-- {
		j := *s.jobs[i]
		j.Results = append([]FileResult(nil), j.Results...)
		out = append(out, j)
	}
	return out
}

func (s *Service) Cancel(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.ID == id {
			if j.State == JobRunning {
				j.cancel()
			}
			return nil
		}
	}
	return fmt.Errorf("%w: job %d", ErrNotFound, id)
}

// ErrInvalid wraps request validation errors.
var ErrInvalid = errors.New("잘못된 요청")

func (s *Service) Start(ctx context.Context, req Request) (Job, error) {
	if len(req.Items) == 0 {
		return Job{}, fmt.Errorf("%w: 선택한 파일이 없음", ErrInvalid)
	}
	if req.From == req.To {
		return Job{}, fmt.Errorf("%w: 보낼 곳과 받을 곳이 같음", ErrInvalid)
	}
	if mtpDev(req.From) != "" && mtpDev(req.From) == mtpDev(req.To) {
		return Job{}, fmt.Errorf("%w: 같은 휴대폰 안에서의 이동은 지원하지 않음", ErrInvalid)
	}
	s.mu.Lock()
	if s.active != nil {
		s.mu.Unlock()
		return Job{}, ErrBusy
	}
	s.nextID++
	jctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	j := &Job{ID: s.nextID, From: req.From, To: req.To, Move: req.Move, State: JobRunning, StartedAt: time.Now(), cancel: cancel}
	s.active = j
	s.jobs = append(s.jobs, j)
	if len(s.jobs) > 20 {
		s.jobs = s.jobs[len(s.jobs)-20:]
	}
	s.mu.Unlock()

	fail := func(err error) (Job, error) {
		cancel()
		s.mu.Lock()
		s.active = nil
		s.jobs = s.jobs[:len(s.jobs)-1]
		s.mu.Unlock()
		return Job{}, err
	}

	// open both sides now so errors (device busy, gone) are reported directly;
	// two MTP devices are opened one after the other under the same lock
	src, err := s.open(jctx, req.From, false)
	if err != nil {
		return fail(err)
	}
	var dst *opened
	if mtpDev(req.From) != "" && mtpDev(req.To) != "" {
		dst, err = s.openSecondMTP(jctx, req.To)
	} else {
		dst, err = s.open(jctx, req.To, false)
	}
	if err != nil {
		src.release()
		return fail(err)
	}
	if dst.loc.ReadOnly {
		src.release()
		dst.release()
		return fail(fmt.Errorf("%w: 받을 곳이 읽기 전용", ErrInvalid))
	}
	s.mu.Lock()
	j.FromName, j.ToName = src.loc.Name, dst.loc.Name
	j.Current = "폴더 내용 확인 중…"
	out := *j
	s.mu.Unlock()

	go s.run(jctx, j, src, dst, req)
	return out, nil
}

// planOp is one step of a job: create a folder or copy a file.
type planOp struct {
	e      Entry
	rel    string // path shown in results (relative to fromDir)
	parent int    // index of the folder op it goes into, -1 = toDir
	dstID  string // folder ops: the destination folder
	failed bool   // folder ops: could not be created (contents fail)
}

// plan expands the selected items (folders recursively) in copy order:
// a folder always comes before its contents.
func plan(ctx context.Context, src Store, fromDir string, ids []string, exts []string) ([]planOp, []FileResult, error) {
	entries, err := src.List(ctx, fromDir)
	if err != nil {
		return nil, nil, err
	}
	byID := map[string]Entry{}
	for _, e := range entries {
		byID[e.ID] = e
	}
	var ops []planOp
	var missing []FileResult
	var walk func(e Entry, parent int, rel string) (bool, error)
	walk = func(e Entry, parent int, rel string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		idx := len(ops)
		ops = append(ops, planOp{e: e, rel: rel, parent: parent})
		children, err := src.List(ctx, e.ID)
		if err != nil {
			return false, fmt.Errorf("%s: %w", rel, err)
		}
		any := false
		for _, c := range children {
			if len(ops) >= maxPlan {
				return false, fmt.Errorf("%w: 파일·폴더가 %d개를 넘음 — 나눠서 옮기세요", ErrInvalid, maxPlan)
			}
			if c.Dir {
				has, err := walk(c, idx, rel+"/"+c.Name)
				if err != nil {
					return false, err
				}
				any = any || has
			} else if len(exts) == 0 || hasExt(c.Name, exts) {
				ops = append(ops, planOp{e: c, rel: rel + "/" + c.Name, parent: idx})
				any = true
			}
		}
		if !any && len(exts) > 0 {
			ops = ops[:idx] // nothing to copy in here
		}
		return any || len(exts) == 0, nil
	}
	for _, id := range ids {
		e, ok := byID[id]
		switch {
		case !ok:
			missing = append(missing, FileResult{Name: id, Error: "파일을 찾을 수 없음"})
		case e.Dir:
			if _, err := walk(e, -1, e.Name); err != nil {
				return nil, nil, err
			}
		default:
			ops = append(ops, planOp{e: e, rel: e.Name, parent: -1})
		}
	}
	return ops, missing, nil
}

func mtpDev(id string) string {
	rest, ok := strings.CutPrefix(id, "mtp:")
	if !ok {
		return ""
	}
	d, _, _ := strings.Cut(rest, ":")
	return d
}

// openSecondMTP opens another MTP device while the first one holds mtpMu.
func (s *Service) openSecondMTP(ctx context.Context, id string) (*opened, error) {
	devID, stHex, _ := strings.Cut(strings.TrimPrefix(id, "mtp:"), ":")
	stID, err := strconv.ParseUint(stHex, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	devs, err := mtp.Devices()
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		if d.ID == devID {
			st, err := openMTP(d, uint32(stID))
			if err != nil {
				return nil, err
			}
			name := d.Name
			for _, l := range s.cachedLocs(d.ID) {
				if l.ID == id {
					name = l.Name
				}
			}
			return &opened{loc: Location{ID: id, Kind: KindMTP, Name: name}, store: st, release: func() { st.Close() }}, nil
		}
	}
	_ = ctx
	return nil, mtp.ErrNotFound
}

type progressReader struct {
	ctx context.Context
	r   io.Reader
	fn  func(n int)
}

func (p *progressReader) Read(b []byte) (int, error) {
	if err := p.ctx.Err(); err != nil {
		return 0, errors.New("취소됨")
	}
	n, err := p.r.Read(b)
	if n > 0 {
		p.fn(n)
	}
	return n, err
}

func (s *Service) run(ctx context.Context, j *Job, src, dst *opened, req Request) {
	defer func() {
		dst.release()
		src.release()
		j.cancel()
	}()
	ops, missing, err := plan(ctx, src.store, req.FromDir, req.Items, req.Ext)
	s.mu.Lock()
	j.Results = append(j.Results, missing...)
	j.Skipped = len(missing)
	if err != nil && ctx.Err() == nil {
		j.Results = append(j.Results, FileResult{Name: "(폴더 내용 확인)", Error: err.Error()})
	}
	for _, op := range ops {
		if !op.e.Dir {
			j.Files++
			j.Bytes += op.e.Size
		}
	}
	s.mu.Unlock()

	var copied int64
	for i := range ops {
		if ctx.Err() != nil {
			break
		}
		op := &ops[i]
		toDir := req.ToDir
		if op.parent >= 0 {
			if ops[op.parent].failed {
				op.failed = true
				if !op.e.Dir {
					s.result(j, op.rel, errors.New("상위 폴더를 만들지 못함"), 0, &copied)
				}
				continue
			}
			toDir = ops[op.parent].dstID
		}
		if op.e.Dir {
			id, err := dst.store.Mkdir(ctx, toDir, op.e.Name)
			s.mu.Lock()
			if err != nil {
				op.failed = true
				j.Results = append(j.Results, FileResult{Name: op.rel + "/", Error: "폴더 만들기 실패: " + err.Error()})
			} else {
				op.dstID = id
				j.Folders++
			}
			s.mu.Unlock()
			continue
		}
		s.mu.Lock()
		j.Current = op.rel
		s.mu.Unlock()
		err := s.copyOne(ctx, j, src, dst, op.e, toDir, req.Overwrite)
		if err == nil && req.Move {
			if derr := src.store.Delete(ctx, op.e.ID); derr != nil {
				err = fmt.Errorf("복사는 완료, 원본 삭제 실패: %w", derr)
			}
		}
		s.result(j, op.rel, err, op.e.Size, &copied)
		if err != nil && ctx.Err() != nil {
			break
		}
	}
	// move: remove the source folders that are now empty (deepest first);
	// anything left behind (filtered out, failed, hidden) keeps its folder
	if req.Move && ctx.Err() == nil {
		for i := len(ops) - 1; i >= 0; i-- {
			if op := ops[i]; op.e.Dir && !op.failed {
				if _, err := src.store.RemoveDirIfEmpty(ctx, op.e.ID); err != nil {
					s.deps.Log.Warn("remove moved folder failed", "folder", op.rel, "err", err)
				}
			}
		}
	}

	s.mu.Lock()
	j.Current = ""
	j.FinishedAt = time.Now()
	switch {
	case ctx.Err() != nil: // only the user's cancel (j.cancel runs after this)
		j.State = JobCanceled
	case j.Done == 0 && j.Folders == 0 && len(j.Results) > 0: // everything failed or was missing
		j.State = JobFailed
	default:
		j.State = JobDone
	}
	s.active = nil
	snap := *j
	s.mu.Unlock()

	verb := "복사"
	if snap.Move {
		verb = "이동"
	}
	detail := fmt.Sprintf("파일 %s %d개 · %s", verb, snap.Done, humanBytes(copied))
	if snap.Folders > 0 {
		detail += fmt.Sprintf(" · 폴더 %d개", snap.Folders)
	}
	if snap.Failed > 0 {
		detail += fmt.Sprintf(" (실패 %d)", snap.Failed)
	}
	if snap.State == JobCanceled {
		detail += " · 취소됨"
	}
	s.deps.Log.Info("usb transfer finished", "from", snap.From, "to", snap.To, "move", snap.Move, "done", snap.Done,
		"failed", snap.Failed, "bytes", copied, "state", snap.State)
	if s.deps.Record != nil {
		s.deps.Record(context.WithoutCancel(ctx), snap.FromName+" → "+snap.ToName, detail, snap.State == JobDone && snap.Failed == 0)
	}
}

func (s *Service) result(j *Job, name string, err error, size int64, copied *int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := FileResult{Name: name, OK: err == nil}
	if err != nil {
		r.Error = err.Error()
		j.Failed++
	} else {
		j.Done++
		*copied += size
	}
	j.Results = append(j.Results, r)
}

func (s *Service) copyOne(ctx context.Context, j *Job, src, dst *opened, e Entry, toDir string, overwrite bool) error {
	pr, pw := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		err := src.store.Read(ctx, e.ID, pw)
		pw.CloseWithError(err)
		errc <- err
	}()
	body := &progressReader{ctx: ctx, r: pr, fn: func(n int) {
		s.mu.Lock()
		j.BytesDone += int64(n)
		s.mu.Unlock()
		if dst.disk != "" && s.deps.SelfWrite != nil {
			s.deps.SelfWrite(dst.disk, uint64(n))
		}
	}}
	werr := dst.store.Write(ctx, toDir, e.Name, e.Size, e.Modified, body, overwrite)
	if werr != nil && ctx.Err() != nil {
		werr = errors.New("취소됨")
	}
	if werr != nil {
		pr.CloseWithError(werr)
	} else {
		pr.Close()
	}
	rerr := <-errc
	switch {
	case werr != nil:
		if rerr != nil && !errors.Is(rerr, io.ErrClosedPipe) && !strings.Contains(werr.Error(), rerr.Error()) {
			return fmt.Errorf("%w (원본: %v)", werr, rerr)
		}
		return werr
	case rerr != nil:
		return fmt.Errorf("원본 읽기 실패: %w", rerr)
	}
	return nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
