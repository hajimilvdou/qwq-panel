// SPDX-License-Identifier: AGPL-3.0-only

package privateexport

import (
	"context"
	"strings"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/catalog"
	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// CatalogAuthorization 复用当前动作权限及已验签能力，grant 不产生新的授权。
func CatalogAuthorization(actions *catalog.Catalog, authorizer *authz.Authorizer) Authorization {
	return func(ctx context.Context, act actor.Actor, request CreateRequest) error {
		if actions == nil || authorizer == nil {
			return problem.New(problem.Unavailable, "导出授权服务未配置")
		}
		entry, ok := actions.Get(request.Action)
		if !ok || entry.Source != catalog.Plugin || entry.PluginID != request.PluginID || entry.Effect == "read" {
			return problem.New(problem.PermissionDenied, "动作不允许生成此私密材料")
		}
		user := strings.TrimSuffix(strings.TrimPrefix(request.Subject, "account/"), "/keys")
		allowed := false
		for _, capability := range entry.Capabilities {
			if capability.Name == "system.account.keys" && (capability.Scope == user || capability.Scope == "all") {
				allowed = true
			}
		}
		if !allowed || request.Purpose != SSHPrivateKey {
			return problem.New(problem.PermissionDenied, "动作能力不包含此导出资源")
		}
		permission, err := authz.ParsePermission(entry.Permission)
		if err != nil {
			return problem.New(problem.Unavailable, "动作权限无效")
		}
		return authorizer.Authorize(ctx, act, string(permission), authz.Resource{Name: string(permission.Resource()), NodeID: request.NodeID, Action: entry.ID})
	}
}
