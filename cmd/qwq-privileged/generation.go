// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"os"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// ======================== typed 装配边界：未装配后端不观察、不发信号、不写记录 ========================

type generationHelperBackend interface {
	ObserveGeneration(context.Context, string) (sandbox.ProcessProof, error)
	StopGeneration(context.Context, sandbox.GenerationStopRequest) (sandbox.GenerationCompletion, error)
	RetireGeneration(context.Context, sandbox.GenerationRetireRequest) (sandbox.GenerationRecordRef, error)
}

func (server *helperServer) handleGeneration(ctx context.Context, request sandbox.DecodedHelperRequest) (response any) {
	status := sandbox.GenerationResponseStatus{UID: os.Geteuid()}
	defer func() {
		if recover() != nil {
			status.OK, status.Code, status.Error = false, string(problem.Internal), "The generation helper failed to handle the request."
			response = generationFailure(request, status)
		}
	}()
	if server.generation == nil || ctx.Err() != nil {
		status.Code, status.Error = string(problem.Unavailable), "The fixed generation backend is unavailable."
		return generationFailure(request, status)
	}
	switch {
	case request.Observe != nil:
		if request.Observe.Validate() != nil {
			break
		}
		proof, err := server.generation.ObserveGeneration(ctx, request.Observe.ID)
		if err != nil {
			return generationBackendFailure(request, status, err)
		}
		if proof.Validate(request.Observe.ID) != nil || len(proof.Cgroup) > 4096 {
			break
		}
		status.OK = true
		return sandbox.GenerationObserveResponse{GenerationResponseStatus: status, Observed: &proof}
	case request.Stop != nil:
		if request.Stop.Validate() != nil {
			break
		}
		completion, err := server.generation.StopGeneration(ctx, *request.Stop)
		if err != nil {
			return generationBackendFailure(request, status, err)
		}
		if completion.ValidateFor(*request.Stop) != nil {
			break
		}
		status.OK = true
		return sandbox.GenerationStopResponse{GenerationResponseStatus: status, Stopped: &completion}
	case request.Retire != nil:
		if request.Retire.Validate() != nil {
			break
		}
		reference, err := server.generation.RetireGeneration(ctx, *request.Retire)
		if err != nil {
			return generationBackendFailure(request, status, err)
		}
		if reference.Validate() != nil || reference != request.Retire.Reference() {
			break
		}
		status.OK = true
		return sandbox.GenerationRetireResponse{GenerationResponseStatus: status, Retired: &reference}
	}
	status.Code, status.Error = string(problem.Internal), "The generation helper returned an invalid bound result."
	return generationFailure(request, status)
}

func generationBackendFailure(request sandbox.DecodedHelperRequest, status sandbox.GenerationResponseStatus, err error) any {
	status.Code = string(problem.From(err).Code)
	status.Error = "The generation helper could not confirm the requested bound operation."
	return generationFailure(request, status)
}

func generationFailure(request sandbox.DecodedHelperRequest, status sandbox.GenerationResponseStatus) any {
	switch {
	case request.Stop != nil:
		return sandbox.GenerationStopResponse{GenerationResponseStatus: status}
	case request.Retire != nil:
		return sandbox.GenerationRetireResponse{GenerationResponseStatus: status}
	default:
		return sandbox.GenerationObserveResponse{GenerationResponseStatus: status}
	}
}
