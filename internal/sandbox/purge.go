// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// ============================================================================
// 固定插件范围的持久数据删除；根来自宿主配置，叶节点来自已校验 ID。
// ============================================================================

// PurgePluginData 删除每个配置根下的本插件子树。链接只删自身，不跟随目标；
// 根必须满足原可信目录策略，缺失目录属于幂等完成，其余错误返回调用方。
func PurgePluginData(ctx context.Context, trust TrustPolicy, pluginID string, roots ...string) ([]string, error) {
	if err := ValidateID(pluginID); err != nil {
		return nil, err
	}
	for _, root := range roots {
		if _, err := checkDirPath("plugin data root", root); err != nil {
			return nil, err
		}
		if root == string(filepath.Separator) {
			return nil, fmt.Errorf("sandbox: plugin data root must be a dedicated directory")
		}
	}
	var removed []string
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		dir, err := trust.Open(root)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return removed, fmt.Errorf("sandbox: plugin data root: %w", err)
		}
		present, removeErr := RemoveAllIn(dir, pluginID)
		closeErr := dir.Close()
		if removeErr != nil {
			return removed, fmt.Errorf("sandbox: plugin data removal: %w", removeErr)
		}
		if closeErr != nil {
			return removed, fmt.Errorf("sandbox: plugin data root close: %w", closeErr)
		}
		if present {
			removed = append(removed, filepath.Join(root, pluginID))
		}
	}
	return removed, nil
}
