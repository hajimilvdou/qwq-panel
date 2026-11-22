// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// ============================================================================
// 彻底卸载独立于版本删除；更新或回滚不能顺带清空用户数据。
// ============================================================================

// PurgeData 清理配置派生的本插件持久树与宿主 KV。先关闭旧 host channel，
// 再清理文件；任何失败返回 updater，由其保留数据库边界以供重试。
func (i *PluginInstaller) PurgeData(ctx context.Context, pluginID string) error {
	if err := sandbox.ValidateID(pluginID); err != nil {
		return problem.New(problem.ValidationFailed, "A valid plugin id is required.")
	}
	if i.StateDir == "" || !filepath.IsAbs(i.StateDir) || filepath.Clean(i.StateDir) != i.StateDir || i.StateDir == string(filepath.Separator) {
		return problem.New(problem.Unavailable, "The persistent plugin state root is not configured correctly.")
	}
	if err := i.requireStoppedPlugin(ctx, pluginID); err != nil {
		return err
	}
	if i.HostChannels != nil {
		i.HostChannels.ReleaseHostChannel(pluginID)
	}
	if i.Helper != nil {
		_, err := i.removeWithHelper(ctx, sandbox.HelperRemove{ID: pluginID, PurgeData: true})
		if err != nil {
			return wrapInstallerFailure(fmt.Sprintf("The persistent data of plugin %s could not be removed.", pluginID), err)
		}
	} else if i.DataRoot != "" {
		roots := []string{i.DataRoot}
		if i.DataRoot == sandbox.DefaultPluginDataRoot {
			roots = append(roots, sandbox.DefaultPrivatePluginDataRoot)
		}
		if _, err := sandbox.PurgePluginData(ctx, i.Sandbox.Trust, pluginID, roots...); err != nil {
			return wrapInstallerFailure(fmt.Sprintf("The persistent data of plugin %s could not be removed.", pluginID), err)
		}
	}
	// 宿主状态由当前 agent 持有，不套用 root helper 的属主策略；仍复用同一
	// 句柄与根链接检查，避免旧 store 或路径替换把删除导向其他插件。
	trust := sandbox.TrustPolicy{UID: os.Geteuid(), StopAt: i.StateDir}
	if _, err := sandbox.PurgePluginData(ctx, trust, pluginID, i.StateDir); err != nil {
		return wrapInstallerFailure(fmt.Sprintf("The host state of plugin %s could not be removed.", pluginID), err)
	}
	return nil
}

// requireStoppedPlugin 共用版本删除与持久数据删除的真实进程门禁。
func (i *PluginInstaller) requireStoppedPlugin(ctx context.Context, pluginID string) error {
	if i.Systemctl == nil {
		return nil
	}
	unit, _, err := sandbox.UnitNames(pluginID)
	if err != nil {
		return problem.New(problem.ValidationFailed, "Plugin %q cannot be managed as a systemd unit.", pluginID)
	}
	state, err := i.Systemctl.Show(ctx, unit)
	if err != nil {
		return &problem.Error{Code: problem.Unavailable, Detail: fmt.Sprintf("The systemd state of plugin %q could not be read; its files were retained.", pluginID), Cause: err}
	}
	if state.MainPID > 0 {
		return problem.New(problem.PreconditionFailed, "Plugin %q is still running (main PID %d); its files cannot be removed.", pluginID, state.MainPID)
	}
	return nil
}

// removeWithHelper 保留原 shadow 更新失败后的单次幂等重试，两个删除入口复用。
func (i *PluginInstaller) removeWithHelper(ctx context.Context, req sandbox.HelperRemove) (sandbox.RemoveResult, error) {
	result, err := i.Helper.Remove(ctx, req)
	if err == nil {
		return result, nil
	}
	i.logger().WarnContext(ctx, "plugin removal failed; retrying once", "plugin_id", req.ID, "version", req.Version, "error", err)
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	case <-timer.C:
		return i.Helper.Remove(ctx, req)
	}
}
