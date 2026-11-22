// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

func (i *instance) plan(ctx context.Context, request pluginsdk.Request) (pluginsdk.Plan, error) {
	input, err := decodeApplyInput(request.Payload)
	if err != nil {
		return pluginsdk.Plan{}, err
	}
	if i.driver == nil {
		return pluginsdk.Plan{}, skeletonError()
	}
	if request.Host() == nil || request.Host().Conn() == nil {
		return pluginsdk.Plan{}, pluginsdk.Errorf("NO_HOST", "宿主连接不可用")
	}
	result, err := i.driver.controller.Plan(ctx, apply.Request{Host: request.Host(), ConfigRevision: input.ConfigRevision, ExpectedRunningRevision: input.ExpectedRunningRevision})
	if err != nil {
		return pluginsdk.Plan{}, mapApplyError(err)
	}
	if !i.driver.trusted {
		result.Warnings = append(result.Warnings, pluginsdk.FieldViolation{Code: "CORE_BINARY_MISMATCH", Message: "包内核心尚不可用；执行前必须通过二进制核验"})
	}
	return result, nil
}
