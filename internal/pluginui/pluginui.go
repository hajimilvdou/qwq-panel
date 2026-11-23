// SPDX-License-Identifier: AGPL-3.0-only

// Package pluginui serves the static files of installed plugin versions under
// the versioned prefix /plugin-ui/{plugin_id}/{version}/{path} (ADR-0018).
//
// The prefix is deliberately outside /api/v1: the content has no session and
// no credentials, and the gateway lets it through without the Origin check a
// sandboxed iframe cannot pass (its origin is the opaque "null"). The URL is
// versioned, so responses are immutable and cached for a year.
//
// What may be served is minimal: the ui/ subtree of the package, plus the
// single icon file the signed manifest declares. Everything is read through
// os.Root inside the published version directory, so neither a crafted request
// path nor a symlink in the tree can escape it. The response carries the CSP
// that keeps the sandbox: scripts and styles from the package itself, no
// network except the connect sources the manifest declared.
package pluginui

import (
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Prefix is the URL prefix of the plugin static subtree.
const Prefix = "/plugin-ui/"

// Version describes one installed, retained plugin version.
type Version struct {
	// Dir is the published version directory (<plugins_root>/<id>/<version>).
	Dir string
	// Icon is the package-relative icon path of the manifest ("" for none).
	// It is the one file outside ui/ that may be served.
	Icon string
	// ConnectSources are the HTTPS origins the sandboxed page may connect to
	// (manifest ui.connect_sources).
	ConnectSources []string
}

// Resolver reports the published directory of one installed retained version.
// Implementations must answer from host-owned records only; the request never
// names a filesystem path.
type Resolver interface {
	Version(pluginID, version string) (Version, bool)
}

// pluginIDPattern is the manifest id grammar; versionPattern is the manifest
// version grammar. Both double as safe path components.
var (
	pluginIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*([.-][a-z0-9]+)*$`)
	versionPattern  = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*([-+][0-9A-Za-z.+-]+)?$`)
)

// contentTypes overrides what mime.TypeByExtension may not know everywhere.
var contentTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".htm":  "text/html; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".mjs":  "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".json": "application/json",
	".svg":  "image/svg+xml",
}

// NewHandler returns the handler for the /plugin-ui subtree. r must not be
// nil; the handler fails every request with 404 when r reports nothing.
func NewHandler(r Resolver) http.Handler {
	return &handler{resolver: r}
}

type handler struct {
	resolver Resolver
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if serveSharedKit(w, req) {
		return
	}
	pluginID, version, rel, ok := splitPath(req.URL.Path)
	if !ok {
		http.NotFound(w, req)
		return
	}
	v, ok := h.resolve(pluginID, version)
	if !ok {
		http.NotFound(w, req)
		return
	}
	// Only the ui/ subtree and the manifest icon are ever served.
	if !strings.HasPrefix(rel, "ui/") && (v.Icon == "" || rel != v.Icon) {
		http.NotFound(w, req)
		return
	}
	root, err := os.OpenRoot(v.Dir)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	defer root.Close() //nolint:errcheck // read only
	info, err := root.Lstat(rel)
	if err != nil || !info.Mode().IsRegular() {
		// Missing, a directory or a symlink: published trees contain no
		// symlinks, so one here is an intrusion, not content.
		http.NotFound(w, req)
		return
	}
	f, err := root.Open(rel)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	defer f.Close() //nolint:errcheck // read only

	header := w.Header()
	header.Set("Content-Type", contentType(rel))
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Cache-Control", "public, max-age=31536000, immutable")
	header.Set("Content-Security-Policy", csp(v.ConnectSources))
	// ServeContent handles HEAD, ranges and conditional requests without a
	// directory index or a redirect; no http.FileServer (ENG §12).
	http.ServeContent(w, req, path.Base(rel), info.ModTime(), f)
}

func (h *handler) resolve(pluginID, version string) (Version, bool) {
	if h.resolver == nil {
		return Version{}, false
	}
	if !pluginIDPattern.MatchString(pluginID) || len(pluginID) > 128 {
		return Version{}, false
	}
	if !versionPattern.MatchString(version) || len(version) > 128 {
		return Version{}, false
	}
	return h.resolver.Version(pluginID, version)
}

// splitPath cuts /plugin-ui/{plugin_id}/{version}/{path} into its parts. The
// caller already rejected non-canonical request paths (isCleanPath); the
// segment checks plus fs.ValidPath make "..", empty and absolute paths
// impossible regardless.
func splitPath(urlPath string) (pluginID, version, rel string, ok bool) {
	rest, found := strings.CutPrefix(urlPath, Prefix)
	if !found {
		return "", "", "", false
	}
	pluginID, rest, found = strings.Cut(rest, "/")
	if !found {
		return "", "", "", false
	}
	version, rel, found = strings.Cut(rest, "/")
	if !found || rel == "" {
		return "", "", "", false
	}
	if !fs.ValidPath(rel) {
		return "", "", "", false
	}
	return pluginID, version, rel, true
}

func contentType(rel string) string {
	if ct, ok := contentTypes[strings.ToLower(filepath.Ext(rel))]; ok {
		return ct
	}
	if ct := mime.TypeByExtension(filepath.Ext(rel)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// csp is the response CSP of every plugin asset (GAPS gap 3): the page runs
// sandboxed with scripts and styles from its own package, images from itself
// or data: URLs, fonts and connections only as declared, and can be framed by
// the panel itself but nothing else.
func csp(connectSources []string) string {
	connect := "'none'"
	if len(connectSources) > 0 {
		connect = strings.Join(connectSources, " ")
	}
	return "sandbox allow-scripts allow-forms allow-downloads; " +
		"default-src 'none'; script-src 'self'; style-src 'self'; " +
		"img-src 'self' data:; font-src 'self'; connect-src " + connect + "; " +
		"frame-ancestors 'self'; base-uri 'none'; form-action 'none'"
}
