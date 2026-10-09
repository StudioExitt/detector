package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"detector/api"
	"detector/internal/swagger"
	"detector/internal/webui"
)

const (
	APIBaseURL    = "/api/v1"
	SwaggerPrefix = "/swagger/"
	// must match VITE_APP_BASE_URL in web/.env.production
	WebPrefix = "/detector/"
)

// NewHandler wires the generated API routes, Swagger UI and middleware.
func NewHandler(ssi api.StrictServerInterface, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	jsonError := func(status int) func(w http.ResponseWriter, r *http.Request, err error) {
		return func(w http.ResponseWriter, r *http.Request, err error) {
			if status >= http.StatusInternalServerError {
				log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
			}
			writeJSON(w, status, api.Error{Message: err.Error()})
		}
	}

	strict := api.NewStrictHandlerWithOptions(ssi, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  jsonError(http.StatusBadRequest),
		ResponseErrorHandlerFunc: jsonError(http.StatusInternalServerError),
	})
	api.HandlerWithOptions(strict, api.StdHTTPServerOptions{
		BaseURL:          APIBaseURL,
		BaseRouter:       mux,
		ErrorHandlerFunc: jsonError(http.StatusBadRequest),
	})

	mux.Handle(SwaggerPrefix, swagger.Handler(SwaggerPrefix, api.Spec))
	mux.Handle("GET /swagger", http.RedirectHandler(SwaggerPrefix, http.StatusMovedPermanently))

	mux.Handle(WebPrefix, webui.Handler(WebPrefix))
	mux.Handle("GET /detector", http.RedirectHandler(WebPrefix, http.StatusFound))
	mux.Handle("GET /{$}", http.RedirectHandler(WebPrefix, http.StatusFound))

	return recoverer(log, accessLog(log, mux))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func accessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		log.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.bytes,
			"remote", r.RemoteAddr,
			"duration", time.Since(start).String(),
		)
	})
}

func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Error("panic recovered", "method", r.Method, "path", r.URL.Path, "panic", v)
				writeJSON(w, http.StatusInternalServerError, api.Error{Message: "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
