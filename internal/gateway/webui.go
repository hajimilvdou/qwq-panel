// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"net/http"
	"strings"
)

// MountShell 将页面接在现有 fallback 后，保留完整的全局中间件和 API 路由。
// 发布包启动时调用一次；未挂载时保持原有的 JSON 404 行为。
func (g *Gateway) MountShell(h http.Handler) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.shell = h
}

func reservedShellPath(p string) bool {
	for _, prefix := range []string{"/api", "/plugin-ui", "/p", "/healthz", "/readyz"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}
