// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
)

// DefaultPrivatePluginDataRoot 是 systemd 为 DynamicUser 保存状态的真实私有根。
// 单元继续声明逻辑 StateDirectory；插件在自己的挂载视图使用此根。
const DefaultPrivatePluginDataRoot = "/var/lib/private/qwq-plugin-data"

// RuntimePluginDataDir 把宿主的固定逻辑目录转换成同一实例的真实私有路径。
// 本函数只做路径推导，不跟随磁盘上的链接；插件仍须校验属主、权限和真实目录。
// 显式配置的其他宿主数据根保持原路径，不猜测它们采用哪种 systemd 布局。
func RuntimePluginDataDir(dataDir, pluginID string) (string, error) {
	if dataDir == "" {
		return "", nil
	}
	if err := ValidateID(pluginID); err != nil {
		return "", err
	}
	dir, err := checkDirPath("data dir", dataDir)
	if err != nil {
		return "", err
	}
	logical := filepath.Join(DefaultPluginDataRoot, pluginID, "default")
	private := filepath.Join(DefaultPrivatePluginDataRoot, pluginID, "default")
	if dir == logical || dir == private {
		return private, nil
	}
	for _, root := range []string{DefaultPluginDataRoot, DefaultPrivatePluginDataRoot} {
		if dir == root || strings.HasPrefix(dir, root+string(filepath.Separator)) {
			return "", fmt.Errorf("sandbox: data dir must belong to the current plugin's default instance")
		}
	}
	return dir, nil
}
