// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// ============================================================================
// 真实 SDK 恢复上下文；私有 epoch 与宿主投影一致，恢复期间不读取秘密。
// ============================================================================

type activationHostConnection struct {
	*fakeApplyConnection
	mu              sync.Mutex
	bootstrapWrites int
	denyBootstrap   bool
}

func (c *activationHostConnection) Invoke(ctx context.Context, method string, input, output any, options ...grpc.CallOption) error {
	if method == pb.HostStateService_PutState_FullMethodName {
		request := input.(*pb.PutStateRequest)
		if request.GetContext().GetInstanceHandle() != "test-handle" {
			return status.Error(codes.PermissionDenied, "the state writer has no bound instance")
		}
		if request.GetContext().GetOperationId() == "" {
			c.mu.Lock()
			c.bootstrapWrites++
			deny := c.denyBootstrap
			c.mu.Unlock()
			if deny {
				return status.Error(codes.PermissionDenied, "the bootstrap state write was denied")
			}
		}
	}
	return c.fakeApplyConnection.Invoke(ctx, method, input, output, options...)
}

func TestFakeSDKActivationSynchronizesHostEpoch(t *testing.T) {
	for _, lostResponse := range []bool{false, true} {
		name := "ordinary"
		if lostResponse {
			name = "lost-CAS-response"
		}
		t.Run(name, func(t *testing.T) {
			var connection *activationHostConnection
			f, server := sdkApplyFixtureWithHost(t, func(base *fakeApplyConnection) grpc.ClientConnInterface {
				connection = &activationHostConnection{fakeApplyConnection: base}
				return connection
			})
			if terminal := runSDKApply(t, server, "1"); terminal.GetError() != nil {
				t.Fatal("baseline Apply failed")
			}
			old, err := f.store.Committed(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			reveals := len(f.host.revealed)
			if _, err := server.Deactivate(t.Context(), &pb.DeactivateRequest{Context: testContext()}); err != nil {
				t.Fatal(err)
			}
			f.host.putLost = lostResponse
			if _, err := server.Activate(t.Context(), &pb.ActivateRequest{Context: testContext()}); err != nil {
				t.Fatalf("SDK recovery failed: %v", err)
			}
			current, err := f.store.Committed(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var record struct {
				ResetEpoch      string `json:"reset_epoch"`
				RunningRevision string `json:"running_revision"`
			}
			if json.Unmarshal(f.host.kv, &record) != nil || current.ResetEpoch == old.ResetEpoch ||
				record.ResetEpoch != current.ResetEpoch || record.RunningRevision != current.Current.Revision {
				t.Fatal("recovered private epoch and host running/current disagree")
			}
			connection.mu.Lock()
			writes := connection.bootstrapWrites
			connection.mu.Unlock()
			if writes != 1 || len(f.host.revealed) != reveals {
				t.Fatalf("bootstrap did not use one bounded original CAS without secrets: writes=%d", writes)
			}
		})
	}
}

func TestFakeSDKActivationRejectsUnconfirmedHostState(t *testing.T) {
	var connection *activationHostConnection
	f, server := sdkApplyFixtureWithHost(t, func(base *fakeApplyConnection) grpc.ClientConnInterface {
		connection = &activationHostConnection{fakeApplyConnection: base}
		return connection
	})
	if terminal := runSDKApply(t, server, "1"); terminal.GetError() != nil {
		t.Fatal("baseline Apply failed")
	}
	if _, err := server.Deactivate(t.Context(), &pb.DeactivateRequest{Context: testContext()}); err != nil {
		t.Fatal(err)
	}
	connection.mu.Lock()
	connection.denyBootstrap = true
	connection.mu.Unlock()
	if _, err := server.Activate(t.Context(), &pb.ActivateRequest{Context: testContext()}); err == nil {
		t.Fatal("failed host synchronization was advertised as a successful SDK activation")
	}
	if f.process.Snapshot(t.Context()).State != "STOPPED" || f.engine.Active() {
		t.Fatal("failed bootstrap synchronization left an unowned active process")
	}
}
