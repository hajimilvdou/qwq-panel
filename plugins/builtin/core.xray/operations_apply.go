// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

type applyInput struct {
	ConfigRevision          string
	ExpectedRunningRevision *string
}

// decodeApplyInput 只接受版本；严格拒绝未知、重复、null 或原生配置字段。
func decodeApplyInput(payload []byte) (applyInput, error) {
	invalid := pluginsdk.Errorf("INVALID_REQUEST", "应用请求字段或版本无效")
	if len(payload) > 1024 {
		return applyInput{}, invalid
	}
	var fields map[string]json.RawMessage
	if sandbox.DecodeHelperDocument(payload, &fields) != nil || len(fields) < 1 || len(fields) > 2 {
		return applyInput{}, invalid
	}
	var input applyInput
	for name, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return applyInput{}, invalid
		}
		switch name {
		case "config_revision":
			if json.Unmarshal(value, &input.ConfigRevision) != nil || !state.ValidRevision(input.ConfigRevision) {
				return applyInput{}, invalid
			}
		case "expected_running_revision":
			var revision string
			if json.Unmarshal(value, &revision) != nil || revision != "" && !state.ValidRevision(revision) {
				return applyInput{}, invalid
			}
			input.ExpectedRunningRevision = &revision
		default:
			return applyInput{}, invalid
		}
	}
	if !state.ValidRevision(input.ConfigRevision) {
		return applyInput{}, invalid
	}
	return input, nil
}

func (i *instance) apply(ctx context.Context, request pluginsdk.Request, progress pluginsdk.Progress) (pluginsdk.Result, error) {
	input, err := decodeApplyInput(request.Payload)
	if err != nil {
		return pluginsdk.Result{}, err
	}
	if i.driver == nil {
		return pluginsdk.Result{}, skeletonError()
	}
	if !i.driver.trusted {
		return pluginsdk.Result{}, pluginsdk.Errorf("CORE_BINARY_MISMATCH", "包内核心二进制未通过核验")
	}
	if request.Host() == nil || request.Host().Conn() == nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("NO_HOST", "宿主连接不可用")
	}
	if request.OperationID() == "" {
		return pluginsdk.Result{}, pluginsdk.Errorf("MISSING_OPERATION_ID", "应用配置需要已派发的操作")
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	result, err := i.driver.controller.Execute(ctx, apply.Request{
		Host: request.Host(), ConfigRevision: input.ConfigRevision, ExpectedRunningRevision: input.ExpectedRunningRevision,
		Preconditions: request.Preconditions, OperationID: request.OperationID(), Attempt: request.Attempt,
		Progress: func(step apply.Step) error {
			steps := apply.Steps()
			for index, current := range steps {
				if current == step {
					return progress(pluginsdk.ProgressUpdate{Step: string(step), StepIndex: uint32(index + 1), StepCount: uint32(len(steps)), Percent: uint32(index * 100 / len(steps)), Message: applyProgressMessage(step)})
				}
			}
			return pluginsdk.Errorf("INTERNAL", "未知进度阶段")
		},
	})
	if err != nil {
		if apply.ErrorCode(err) == "RECOVERY_FAILED" && i.fail != nil {
			i.fail(err)
		}
		return pluginsdk.Result{}, mapApplyError(err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return pluginsdk.Result{}, pluginsdk.Errorf("INTERNAL", "运行结果不可用")
	}
	return pluginsdk.Result{Payload: payload}, nil
}

func applyProgressMessage(step apply.Step) string {
	switch step {
	case apply.LoadDesired, apply.CheckPreconditions:
		return "正在检查期望配置和运行版本"
	case apply.RevealSecrets, apply.RenderCandidate:
		return "正在准备受保护的配置"
	case apply.WriteWork, apply.NativeTest, apply.InstallGeneration, apply.SnapshotLastGood:
		return "正在验证并保存候选配置"
	case apply.StopOld, apply.StartCandidate, apply.WaitHealth:
		return "正在切换代理并确认健康状态"
	case apply.CommitState, apply.CommitHost, apply.ReportChanges:
		return "正在确认运行状态与变更记录"
	default:
		return "正在清理本次工作文件"
	}
}

func mapApplyError(err error) error {
	if err == nil {
		return nil
	}
	var domain *pluginsdk.Error
	if errors.As(err, &domain) {
		return domain
	}
	var failure *apply.Error
	if errors.As(err, &failure) {
		details, marshalErr := json.Marshal(struct {
			RollbackPerformed bool   `json:"rollback_performed"`
			RunningRevision   string `json:"running_revision,omitempty"`
		}{failure.RollbackPerformed, failure.RunningRevision})
		if marshalErr != nil {
			return pluginsdk.Errorf("INTERNAL", "运行错误详情不可用")
		}
		message := "代理配置操作未完成，请核对当前运行状态"
		if failure.Code == "CORE_PORT_UNAVAILABLE" {
			message = "目标监听端口当前不可用，请核对占用或更换监听地址"
		}
		return &pluginsdk.Error{Code: failure.Code, Message: message, DetailsJSON: details}
	}
	if errors.Is(err, state.ErrCorrupt) {
		return pluginsdk.Errorf("SNAPSHOT_CORRUPT", "已提交快照损坏，代理不可用")
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return pluginsdk.Errorf("CORE_STATE_UNAVAILABLE", "运行状态暂不可用")
}
