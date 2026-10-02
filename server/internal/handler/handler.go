package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"detector/api"
	"detector/internal/detect"
)

var _ api.StrictServerInterface = (*Handler)(nil)

type Handler struct {
	db      *sql.DB
	loc     *time.Location
	version string
	detect  *detect.Manager
}

func New(db *sql.DB, loc *time.Location, version string, dm *detect.Manager) *Handler {
	return &Handler{db: db, loc: loc, version: version, detect: dm}
}

func (h *Handler) ListDetectors(_ context.Context, _ api.ListDetectorsRequestObject) (api.ListDetectorsResponseObject, error) {
	res := api.ListDetectors200JSONResponse{Platform: detect.Platform(), Host: h.detect.Host(), Items: []api.DetectorStatus{}}
	for _, s := range h.detect.Statuses() {
		res.Items = append(res.Items, h.detectorStatus(s))
	}
	return res, nil
}

func (h *Handler) GetDetector(_ context.Context, req api.GetDetectorRequestObject) (api.GetDetectorResponseObject, error) {
	s, ok := h.detect.Status(req.Name)
	if !ok {
		return api.GetDetector404JSONResponse{NotFoundJSONResponse: notFound("detector", req.Name)}, nil
	}
	sources := detect.Sources(req.Name)
	if sources == nil {
		sources = []string{}
	}
	return api.GetDetector200JSONResponse{
		Platform: detect.Platform(),
		Host:     h.detect.Host(),
		Status:   h.detectorStatus(s),
		Sources:  sources,
	}, nil
}

func (h *Handler) ListDetectorRuns(ctx context.Context, req api.ListDetectorRunsRequestObject) (api.ListDetectorRunsResponseObject, error) {
	if _, ok := h.detect.Status(req.Name); !ok {
		return api.ListDetectorRuns404JSONResponse{NotFoundJSONResponse: notFound("detector", req.Name)}, nil
	}
	limit, offset := 50, 0
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if req.Params.Offset != nil {
		offset = *req.Params.Offset
	}
	if limit < 1 || limit > 200 || offset < 0 {
		return api.ListDetectorRuns400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse{
			Message: "limit must be 1..200 and offset >= 0"}}, nil
	}
	runs, total, err := h.detect.Runs(ctx, req.Name, limit, offset)
	if err != nil {
		return nil, err
	}
	items := make([]api.DetectorRun, 0, len(runs))
	for _, r := range runs {
		items = append(items, h.detectorRun(r))
	}
	return api.ListDetectorRuns200JSONResponse{Items: items, Total: total}, nil
}

func (h *Handler) GetDetectorRun(ctx context.Context, req api.GetDetectorRunRequestObject) (api.GetDetectorRunResponseObject, error) {
	r, err := h.detect.RunDetail(ctx, req.Name, req.Id)
	if errors.Is(err, detect.ErrNotFound) {
		return api.GetDetectorRun404JSONResponse{NotFoundJSONResponse: notFound("run", fmt.Sprint(req.Id))}, nil
	}
	if err != nil {
		return nil, err
	}
	out := h.detectorRun(r)
	checks := toAPIChecks(r.Checks)
	out.Checks = &checks
	return api.GetDetectorRun200JSONResponse(out), nil
}

func (h *Handler) RunClipboardTest(ctx context.Context, _ api.RunClipboardTestRequestObject) (api.RunClipboardTestResponseObject, error) {
	res, err := h.detect.CanaryTest(ctx)
	if errors.Is(err, detect.ErrUnavailable) {
		return api.RunClipboardTest404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{
			Message: "clipboard detector is not available (macOS only, detect.clipboard.enabled)"}}, nil
	}
	if err != nil {
		return nil, err
	}
	out := api.RunClipboardTest200JSONResponse{
		StartedAt:  res.StartedAt.In(h.loc),
		DurationMs: res.DurationMs,
		Swapped:    res.Swapped,
		Restored:   res.Restored,
		Checks:     make([]api.ClipboardCanaryCheck, 0, len(res.Checks)),
	}
	if res.Note != "" {
		out.Note = &res.Note
	}
	for _, c := range res.Checks {
		item := api.ClipboardCanaryCheck{Chain: c.Chain, Canary: c.Canary, Changed: c.Changed, Swapped: c.Swapped}
		if c.Changed {
			obs, ms := c.Observed, c.AfterMs
			item.Observed, item.AfterMs = &obs, &ms
		}
		out.Checks = append(out.Checks, item)
	}
	return out, nil
}

func (h *Handler) detectorStatus(s detect.Status) api.DetectorStatus {
	item := api.DetectorStatus{
		Name:            s.Name,
		IntervalSeconds: int(s.Interval.Seconds()),
		Findings:        s.Findings,
		Summary:         s.Summary,
		Checks:          toAPIChecks(s.Checks),
	}
	if s.CompactSuccess {
		item.CompactSuccessRuns = &s.CompactSuccess
	}
	if !s.LastRunAt.IsZero() {
		t := s.LastRunAt.In(h.loc)
		ms := s.LastDuration.Milliseconds()
		item.LastRunAt, item.LastDurationMs = &t, &ms
	}
	if s.LastError != "" {
		item.LastError = &s.LastError
	}
	return item
}

func (h *Handler) detectorRun(r detect.Run) api.DetectorRun {
	out := api.DetectorRun{
		Id:         r.ID,
		StartedAt:  r.StartedAt.In(h.loc),
		DurationMs: r.Duration.Milliseconds(),
		Summary:    r.Summary,
		Findings:   r.Findings,
		ChecksOk:   r.ChecksOK,
		ChecksWarn: r.ChecksWarn,
		ChecksFail: r.ChecksFail,
	}
	if r.Error != "" {
		out.Error = &r.Error
	}
	return out
}

func toAPIChecks(cs []detect.Check) []api.DetectorCheck {
	out := make([]api.DetectorCheck, 0, len(cs))
	for _, c := range cs {
		out = append(out, api.DetectorCheck{Name: c.Name, Status: api.DetectorCheckStatus(c.Status), Detail: c.Detail})
	}
	return out
}

func notFound(kind, id string) api.NotFoundJSONResponse {
	return api.NotFoundJSONResponse{Message: fmt.Sprintf("%s not found: %s", kind, id)}
}

func (h *Handler) GetHealth(ctx context.Context, _ api.GetHealthRequestObject) (api.GetHealthResponseObject, error) {
	status := "ok"
	if err := h.db.PingContext(ctx); err != nil {
		status = "db_unavailable"
	}
	return api.GetHealth200JSONResponse{
		Status:  status,
		Version: h.version,
		Time:    time.Now().In(h.loc),
	}, nil
}

func (h *Handler) ListEvents(ctx context.Context, req api.ListEventsRequestObject) (api.ListEventsResponseObject, error) {
	limit, offset := 50, 0
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if req.Params.Offset != nil {
		offset = *req.Params.Offset
	}
	if limit < 1 || limit > 500 || offset < 0 {
		return badRequestList("limit must be 1..500 and offset >= 0"), nil
	}

	var (
		where []string
		args  []any
	)
	if c := req.Params.Category; c != nil {
		if !c.Valid() {
			return badRequestList(fmt.Sprintf("invalid category: %q", *c)), nil
		}
		where = append(where, "category = ?")
		args = append(args, string(*c))
	}
	if d := req.Params.Detector; d != nil && *d != "" {
		where = append(where, "detector = ?")
		args = append(args, *d)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int64
	if err := h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events"+whereSQL, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}

	rows, err := h.db.QueryContext(ctx,
		"SELECT id, category, severity, source, message, detected_at, detector, rule FROM events"+whereSQL+
			" ORDER BY detected_at DESC, id DESC LIMIT ? OFFSET ?",
		append(args, limit, offset)...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	items := make([]api.Event, 0, limit)
	for rows.Next() {
		var (
			e          api.Event
			source     string
			detectedAt string
			detector   string
			rule       string
		)
		if err := rows.Scan(&e.Id, &e.Category, &e.Severity, &source, &e.Message, &detectedAt, &detector, &rule); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		if source != "" {
			e.Source = &source
		}
		if detector != "" {
			e.Detector = &detector
		}
		if rule != "" {
			e.Rule = &rule
		}
		t, err := time.Parse(time.RFC3339Nano, detectedAt)
		if err != nil {
			return nil, fmt.Errorf("parse detected_at %q: %w", detectedAt, err)
		}
		e.DetectedAt = t.In(h.loc)
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}
	return api.ListEvents200JSONResponse{Items: items, Total: total}, nil
}

func (h *Handler) CreateEvent(ctx context.Context, req api.CreateEventRequestObject) (api.CreateEventResponseObject, error) {
	b := req.Body
	if b == nil {
		return badRequestCreate("request body is required"), nil
	}
	if !b.Category.Valid() {
		return badRequestCreate(fmt.Sprintf("invalid category: %q", b.Category)), nil
	}
	if !b.Severity.Valid() {
		return badRequestCreate(fmt.Sprintf("invalid severity: %q", b.Severity)), nil
	}
	if strings.TrimSpace(b.Message) == "" {
		return badRequestCreate("message is required"), nil
	}

	detectedAt := time.Now()
	if b.DetectedAt != nil {
		detectedAt = *b.DetectedAt
	}
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}

	res, err := h.db.ExecContext(ctx,
		"INSERT INTO events (category, severity, source, message, detected_at, detector, rule) VALUES (?, ?, ?, ?, ?, ?, ?)",
		string(b.Category), string(b.Severity), deref(b.Source), b.Message, detectedAt.UTC().Format(time.RFC3339Nano),
		deref(b.Detector), deref(b.Rule))
	if err != nil {
		return nil, fmt.Errorf("insert event: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("last insert id: %w", err)
	}
	return api.CreateEvent201JSONResponse{
		Id:         id,
		Category:   b.Category,
		Severity:   b.Severity,
		Source:     b.Source,
		Message:    b.Message,
		DetectedAt: detectedAt.In(h.loc),
		Detector:   b.Detector,
		Rule:       b.Rule,
	}, nil
}

func badRequestList(msg string) api.ListEvents400JSONResponse {
	return api.ListEvents400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse{Message: msg}}
}

func badRequestCreate(msg string) api.CreateEvent400JSONResponse {
	return api.CreateEvent400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse{Message: msg}}
}
