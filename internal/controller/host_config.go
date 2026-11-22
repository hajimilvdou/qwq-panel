// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"slices"
	"strconv"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
)

// ======================== 本插件的已提交配置视图 ========================
// 配置已经应用给插件时可以成为 desired；核心运行指针仍由消费者独立提交。
type hostConfigSource struct {
	read func(context.Context) (string, []byte, error)
}

func (s hostConfigSource) Current(ctx context.Context) (string, []byte, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if s.read == nil {
		return "", nil, problem.New(problem.Unavailable, "The plugin configuration source is not available.")
	}
	revision, snapshot, err := s.read(ctx)
	if err != nil {
		return "", nil, err
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	return revision, slices.Clone(snapshot), nil
}

// pluginConfigSource 捕获宿主验证的 pluginID，每次读取当前 updater 的配置快照。
// updater 在启动后接线或替换时，既有通道也读取新来源；不提供其他插件的查询参数。
func (c *Controller) pluginConfigSource(pluginID string) hostsvc.ConfigSource {
	return hostConfigSource{read: func(ctx context.Context) (string, []byte, error) {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		u := c.Updater()
		if u == nil {
			return "", nil, problem.New(problem.Unavailable, "The plugin updater is not available.")
		}
		config, ok := u.ActiveConfig(pluginID)
		if !ok {
			// 已配置的 updater 尚无该插件配置，和 Initialize 的空文档/版本0一致。
			return "0", []byte("{}"), nil
		}
		if config.PluginID != pluginID || config.Revision < 0 {
			return "", nil, problem.New(problem.Internal, "The plugin configuration snapshot is invalid.")
		}
		return strconv.FormatInt(config.Revision, 10), config.Config, nil
	}}
}
