// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/privateexport"
)

func (a *api) preparePrivateExport(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.PrivateExports == nil {
		a.fail(w, r, problem.New(problem.Unavailable, "私密交付服务未配置"))
		return
	}
	var request privateexport.CreateRequest
	if err := a.decodeJSON(r, &request); err != nil {
		a.fail(w, r, err)
		return
	}
	grant, err := a.d.PrivateExports.Create(r.Context(), act, request)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	a.writeResource(w, r, http.StatusCreated, grant, nil)
}

// consumePrivateExport 直接写一次性二进制，任何 JSON/事件/幂等缓存都拿不到 PEM。
func (a *api) consumePrivateExport(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.PrivateExports == nil {
		a.fail(w, r, problem.New(problem.Unavailable, "私密交付服务未配置"))
		return
	}
	secret, err := a.d.PrivateExports.Consume(r.Context(), act, r.PathValue("export_id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	defer secret.Clear()
	private := secret.Bytes()
	defer clear(private)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="qwq-private-key.pem"`)
	w.WriteHeader(http.StatusOK)
	// 消耗已提交；断连和短写不重新发行私钥，客户端按失败处理并管理对应公钥。
	written, writeErr := w.Write(private)
	if writeErr != nil || written != len(private) {
		a.d.Logger.DebugContext(r.Context(), "private export connection interrupted", "export_id", r.PathValue("export_id"))
		return
	}
}

func (a *api) cancelPrivateExport(w http.ResponseWriter, r *http.Request) {
	act, err := a.caller(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if a.d.PrivateExports == nil {
		a.fail(w, r, problem.New(problem.Unavailable, "私密交付服务未配置"))
		return
	}
	if err := a.d.PrivateExports.Cancel(r.Context(), act, r.PathValue("export_id")); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
