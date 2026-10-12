package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

// prefix is where the page lives on the admin listener.
const prefix = "/admin/"

// contentSecurityPolicy lets the page load only its own files and talk only to its own origin.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// Handler serves the embedded build.
func Handler() http.Handler {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic(err) // the directory is part of the embed pattern
	}
	return NewHandler(sub)
}

// Built reports whether the embedded build holds a page.
func Built() bool {
	_, err := fs.Stat(embedded, "dist/index.html")
	return err == nil
}

// NewHandler serves the files of fsys below /admin/: index.html for the page itself and the hashed
// files under assets/. Anything else is not found; the page routes in the URL fragment, so no path
// needs a fallback to index.html.
func NewHandler(fsys fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		name := strings.TrimPrefix(r.URL.Path, prefix)
		switch {
		case name == "" || name == "index.html":
			name = "index.html"
			h.Set("Cache-Control", "no-cache")
		case strings.HasPrefix(name, "assets/"):
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			http.NotFound(w, r)
			return
		}
		clean := path.Clean(name)
		if clean != name || strings.Contains(name, "..") {
			http.NotFound(w, r)
			return
		}
		file, err := fsys.Open(clean)
		if err != nil {
			if clean == "index.html" {
				h.Set("Cache-Control", "no-store")
				h.Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("The admin page is not built into this binary: put a build of it in internal/transport/http/admin/ui/dist and rebuild. The API works.\n"))
				return
			}
			http.NotFound(w, r)
			return
		}
		defer func() { _ = file.Close() }()
		info, err := file.Stat()
		if err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		seeker, ok := file.(interface {
			Read([]byte) (int, error)
			Seek(int64, int) (int64, error)
		})
		if !ok {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.ServeContent(w, r, clean, info.ModTime(), seeker)
	})
}
