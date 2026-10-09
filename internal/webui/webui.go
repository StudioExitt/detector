// Package webui serves the React build (web/dist) embedded in the binary.
// `make web` copies the build into ./dist before `go build`.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

const notBuilt = `<!doctype html><meta charset="utf-8"><title>Detector</title>
<body style="font-family:sans-serif;padding:2rem">
<h2>웹 UI 가 빌드에 포함되지 않았습니다</h2>
<p>프로젝트 루트에서 <code>make build</code> 로 다시 빌드하세요. (API 는 <a href="/swagger/">/swagger/</a> 에서 사용 가능)</p>`

// Built reports whether the embedded build contains index.html.
func Built() bool {
	_, err := fs.Stat(distFS, "dist/index.html")
	return err == nil
}

// Handler serves the app under prefix (e.g. "/detector/"). Unknown paths fall
// back to index.html so client-side routes (/detector/system ...) work on reload.
func Handler(prefix string) http.Handler {
	sub, _ := fs.Sub(distFS, "dist")
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !Built() {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(notBuilt))
			return
		}
		// file names are not content-hashed, so always revalidate
		w.Header().Set("Cache-Control", "no-cache")
		name := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, prefix)), "/")
		if name == "" || name == "index.html" {
			serveIndex(w, r, sub)
			return
		}
		if _, err := fs.Stat(sub, name); err != nil {
			serveIndex(w, r, sub)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + name
		files.ServeHTTP(w, r2)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	b, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "index.html missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
