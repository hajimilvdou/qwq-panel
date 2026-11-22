// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"net"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ======================== generation 客户端：真实 root peer、精确回应、无业务重试 ========================

func checkGenerationRootPeer(connection net.Conn) error {
	uid, err := HelperPeerUID(connection)
	if err != nil || uid != 0 {
		return problem.New(problem.Unauthenticated, "The generation helper connection has no verified root peer.")
	}
	return nil
}

// ObserveGeneration 取得强 active proof；缺失/零 proof 或错误插件响应均拒绝。
func (client *HelperClient) ObserveGeneration(ctx context.Context, pluginID string) (ProcessProof, error) {
	request := GenerationObserveRequest{Op: HelperOpGenerationObserve, ID: pluginID}
	if err := request.Validate(); err != nil {
		return ProcessProof{}, err
	}
	var response GenerationObserveResponse
	if err := client.exchangeChecked(ctx, request, &response, checkGenerationRootPeer); err != nil {
		return ProcessProof{}, err
	}
	if !response.OK {
		return ProcessProof{}, generationRemoteFailure(response.GenerationResponseStatus)
	}
	if response.Observed == nil || response.Observed.Validate(pluginID) != nil {
		return ProcessProof{}, ErrGenerationDocument
	}
	return *response.Observed, nil
}

// StopGeneration 只消费传入目标副本；不能把读响应失败自动重试成另一代次。
func (client *HelperClient) StopGeneration(ctx context.Context, request GenerationStopRequest) (GenerationCompletion, error) {
	request.Op = HelperOpGenerationStop
	if err := request.Validate(); err != nil {
		return GenerationCompletion{}, err
	}
	var response GenerationStopResponse
	if err := client.exchangeChecked(ctx, request, &response, checkGenerationRootPeer); err != nil {
		return GenerationCompletion{}, err
	}
	if !response.OK {
		return GenerationCompletion{}, generationRemoteFailure(response.GenerationResponseStatus)
	}
	if response.Stopped == nil || response.Stopped.ValidateFor(request) != nil {
		return GenerationCompletion{}, ErrGenerationDocument
	}
	return *response.Stopped, nil
}

// RetireGeneration 只确认相同完成记录的退休；返回的每个引用必须与请求全等。
func (client *HelperClient) RetireGeneration(ctx context.Context, request GenerationRetireRequest) (GenerationRecordRef, error) {
	request.Op = HelperOpGenerationRetire
	if err := request.Validate(); err != nil {
		return GenerationRecordRef{}, err
	}
	var response GenerationRetireResponse
	if err := client.exchangeChecked(ctx, request, &response, checkGenerationRootPeer); err != nil {
		return GenerationRecordRef{}, err
	}
	if !response.OK {
		return GenerationRecordRef{}, generationRemoteFailure(response.GenerationResponseStatus)
	}
	if response.Retired == nil || *response.Retired != request.Reference() {
		return GenerationRecordRef{}, ErrGenerationDocument
	}
	return *response.Retired, nil
}

func generationRemoteFailure(status GenerationResponseStatus) error {
	return helperRemoteFailure(HelperResponse{Code: status.Code, Error: status.Error, UID: status.UID})
}
