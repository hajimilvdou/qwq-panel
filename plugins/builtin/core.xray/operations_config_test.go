// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// fakeConfigConnection 只替代传输；Host.GetConfig 的真实 SDK 代码仍会执行。
type fakeConfigConnection struct {
	mu           sync.Mutex
	config       []byte
	revision     string
	err          error
	methods      []string
	lastRevision string
}

func (f *fakeConfigConnection) Invoke(ctx context.Context, method string, input, output any, _ ...grpc.CallOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, method)
	if method != pb.HostConfigService_GetConfig_FullMethodName {
		return status.Error(codes.Unimplemented, "fake accepts read config only")
	}
	request, ok := input.(*pb.GetConfigRequest)
	if !ok || request.GetContext().GetInstanceHandle() == "" {
		return errors.New("fake config request has no instance context")
	}
	f.lastRevision = request.GetRevision()
	if f.err != nil {
		return f.err
	}
	if f.lastRevision != "" && f.lastRevision != f.revision {
		return status.Error(codes.NotFound, "revision is not current")
	}
	response := output.(*pb.GetConfigResponse)
	response.ConfigJson, response.Revision = append([]byte(nil), f.config...), f.revision
	return nil
}

func (*fakeConfigConnection) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("fake config connection has no streams")
}

// ======================== fake Host 与真实 SDK 配置读取 ========================
func TestFakeReadValidateUsesHostAndNeverFallsBackAfterHostFailure(t *testing.T) {
	connection := &fakeConfigConnection{config: testIntent(t), revision: "7"}
	srv, _ := pluginServerWithHost(t, New(), testIntent(t), connection)
	validated := decodeReadResult[validateResult](t, readInvoke(t, srv, "core.validate", `{}`))
	if !validated.Valid || validated.ConfigRevision != "7" || validated.NativePreflightPerformed {
		t.Fatal("validation did not read the authoritative host revision")
	}
	missing := readInvoke(t, srv, "core.validate", `{"config_revision":"1"}`)
	if missing.GetError().GetCode() != "CONFIG_REVISION_NOT_FOUND" {
		t.Fatal("host revision rejection was not preserved")
	}
	connection.mu.Lock()
	connection.err = status.Error(codes.Unavailable, "sensitive upstream diagnostic")
	connection.mu.Unlock()
	failed := readInvoke(t, srv, "core.validate", `{}`)
	if failed.GetError().GetCode() != "CONFIG_UNAVAILABLE" || len(failed.GetPayloadJson()) != 0 || failed.GetError().GetMessage() == "sensitive upstream diagnostic" {
		t.Fatal("failed host read fell back to a cached config or exposed diagnostics")
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if len(connection.methods) != 3 {
		t.Fatal("pure validation performed unexpected host work")
	}
	for _, method := range connection.methods {
		if method != pb.HostConfigService_GetConfig_FullMethodName {
			t.Fatal("pure validation called a side-effecting host service")
		}
	}
}
