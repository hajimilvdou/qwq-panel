// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/agentsession"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Interactive Agent File Exchange Folder routes (/api/v1/agent-exchange/*):
// Governed by host.agent_sessions:read (GET) and host.agent_sessions:write
// (POST/PUT/DELETE) so any authorized Agent user (admin or operator) can
// upload source files, create task subfolders, preview/edit files, and download
// deliverables produced by AI agents.

func (a *api) agentExchangeManager(r *http.Request, permission string) (*agentsession.ExchangeManager, actor.Actor, error) {
	act, err := a.caller(r)
	if err != nil {
		return nil, actor.Actor{}, err
	}
	if err := a.authorize(r.Context(), act, permission, ""); err != nil {
		return nil, actor.Actor{}, err
	}
	svc, err := a.agentSessions()
	if err != nil {
		return nil, actor.Actor{}, err
	}
	ex := svc.Exchange()
	if ex == nil || ex.RootDir() == "" {
		return nil, actor.Actor{}, problem.New(problem.Unavailable, "Agent interactive exchange folder is not configured on this host.")
	}
	return ex, act, nil
}

// listAgentExchangeEntries implements GET /api/v1/agent-exchange/entries?path=<dir>.
func (a *api) listAgentExchangeEntries(w http.ResponseWriter, r *http.Request) {
	ex, _, err := a.agentExchangeManager(r, "host.agent_sessions:read")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := ex.List(r.URL.Query().Get("path"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, res, fields)
}

// mkdirAgentExchange implements POST /api/v1/agent-exchange/mkdir.
func (a *api) mkdirAgentExchange(w http.ResponseWriter, r *http.Request) {
	ex, _, err := a.agentExchangeManager(r, "host.agent_sessions:write")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	entry, err := ex.Mkdir(req.Path)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusCreated, entry, nil)
}

// uploadAgentExchange implements POST /api/v1/agent-exchange/upload (multipart/form-data).
// Accepts form field `dir` (optional target subfolder) and one or more `files`
// (or `file`) parts, plus optional matching `relative_paths` form values so
// users can drop entire local folders into a subfolder while keeping hierarchy.
func (a *api) uploadAgentExchange(w http.ResponseWriter, r *http.Request) {
	ex, _, err := a.agentExchangeManager(r, "host.agent_sessions:write")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/files", Code: "INVALID", Message: "Expected multipart/form-data upload.",
		}))
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	targetDir := strings.TrimSpace(r.FormValue("dir"))
	if targetDir == "" {
		targetDir = strings.TrimSpace(r.URL.Query().Get("dir"))
	}
	cleanedDir, err := agentsession.CleanExchangeRelPath(targetDir, true, "/dir")
	if err != nil {
		a.fail(w, r, err)
		return
	}

	headers := r.MultipartForm.File["files"]
	if len(headers) == 0 {
		headers = r.MultipartForm.File["file"]
	}
	if len(headers) == 0 {
		a.fail(w, r, problem.Validation(problem.Violation{
			Pointer: "/files", Code: "REQUIRED", Message: "At least one file part is required.",
		}))
		return
	}
	relPaths := r.MultipartForm.Value["relative_paths"]

	uploaded := make([]agentsession.ExchangeEntry, 0, len(headers))
	for i, fh := range headers {
		f, err := fh.Open()
		if err != nil {
			a.fail(w, r, problem.Wrap(err))
			return
		}
		var destRel string
		if i < len(relPaths) && strings.TrimSpace(relPaths[i]) != "" {
			cleanSub, cerr := agentsession.CleanExchangeRelPath(relPaths[i], false, "/relative_paths")
			if cerr != nil {
				_ = f.Close()
				a.fail(w, r, cerr)
				return
			}
			destRel = cleanSub
		} else {
			destRel = agentsession.SanitizeUploadFilename(fh.Filename)
		}
		if cleanedDir != "" {
			destRel = cleanedDir + "/" + destRel
		}
		entry, saveErr := ex.SaveStream(destRel, f, 50<<20)
		_ = f.Close()
		if saveErr != nil {
			a.fail(w, r, saveErr)
			return
		}
		uploaded = append(uploaded, entry)
	}
	a.writeResource(w, r, http.StatusCreated, map[string]any{
		"dir":   cleanedDir,
		"items": uploaded,
		"total": len(uploaded),
	}, nil)
}

// previewAgentExchange implements GET /api/v1/agent-exchange/preview?path=<file>.
func (a *api) previewAgentExchange(w http.ResponseWriter, r *http.Request) {
	ex, _, err := a.agentExchangeManager(r, "host.agent_sessions:read")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := ex.Preview(r.URL.Query().Get("path"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fields, err := a.fields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, res, fields)
}

// putAgentExchangeFile implements PUT /api/v1/agent-exchange/file (inline text create/edit).
func (a *api) putAgentExchangeFile(w http.ResponseWriter, r *http.Request) {
	ex, _, err := a.agentExchangeManager(r, "host.agent_sessions:write")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	entry, err := ex.WriteText(req.Path, req.Content)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, entry, nil)
}

// renameAgentExchange implements POST /api/v1/agent-exchange/rename.
func (a *api) renameAgentExchange(w http.ResponseWriter, r *http.Request) {
	ex, _, err := a.agentExchangeManager(r, "host.agent_sessions:write")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var req struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := a.decodeJSON(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	entry, err := ex.Rename(req.From, req.To)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeResource(w, r, http.StatusOK, entry, nil)
}

// deleteAgentExchangeEntry implements DELETE /api/v1/agent-exchange/entry?path=<path>.
func (a *api) deleteAgentExchangeEntry(w http.ResponseWriter, r *http.Request) {
	ex, _, err := a.agentExchangeManager(r, "host.agent_sessions:write")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := ex.Delete(r.URL.Query().Get("path")); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// downloadAgentExchange implements GET /api/v1/agent-exchange/download?path=<path>&inline=1.
// Regular files are downloaded directly (or served inline for image previews);
// directories are streamed on the fly as a .zip archive.
func (a *api) downloadAgentExchange(w http.ResponseWriter, r *http.Request) {
	ex, _, err := a.agentExchangeManager(r, "host.agent_sessions:read")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	full, info, cleaned, err := ex.ResolveDownload(r.URL.Query().Get("path"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if info.IsDir() {
		zipName := "agent-exchange.zip"
		if cleaned != "" {
			zipName = path.Base(cleaned) + ".zip"
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", buildContentDisposition("attachment", zipName))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if zerr := ex.WriteZipArchive(w, full); zerr != nil {
			a.d.Logger.Warn("api: stream exchange zip", "path", cleaned, "error", zerr)
		}
		return
	}
	f, err := os.Open(full)
	if err != nil {
		a.fail(w, r, problem.Wrap(err))
		return
	}
	defer f.Close()

	name := path.Base(cleaned)
	disp := "attachment"
	if r.URL.Query().Get("inline") == "1" && isSafeInlineImage(name) {
		disp = "inline"
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Content-Disposition", buildContentDisposition(disp, name))
	w.Header().Set("Content-Security-Policy", "sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, info.ModTime(), f)
}

func isSafeInlineImage(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".avif":
		return true
	default:
		return false
	}
}

func buildContentDisposition(kind, filename string) string {
	ascii := asciiFallbackFilename(filename)
	escaped := url.PathEscape(filename)
	return fmt.Sprintf(`%s; filename="%s"; filename*=UTF-8''%s`, kind, ascii, escaped)
}

func asciiFallbackFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r >= 0x20 && r <= 0x7e && r != '"' && r != '\\' && r != ';' {
			b.WriteRune(r)
		} else if r > 0x7e {
			b.WriteByte('_')
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "download"
	}
	return out
}
