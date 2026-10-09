// Package swagger serves Swagger UI from assets embedded in the binary.
package swagger

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed dist
var distFS embed.FS

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Detector API - Swagger UI</title>
  <link rel="stylesheet" href="swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="swagger-ui-bundle.js"></script>
  <script src="swagger-ui-standalone-preset.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: "openapi.yaml",
      dom_id: "#swagger-ui",
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
      layout: "StandaloneLayout",
    });
  </script>
</body>
</html>`

// Handler serves Swagger UI under prefix (e.g. "/swagger/") with the given OpenAPI spec.
func Handler(prefix string, spec []byte) http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	assets := http.StripPrefix(prefix, http.FileServerFS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, prefix) {
		case "", "index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(indexHTML))
		case "openapi.yaml":
			w.Header().Set("Content-Type", "application/yaml")
			_, _ = w.Write(spec)
		default:
			assets.ServeHTTP(w, r)
		}
	})
}
