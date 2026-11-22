// SPDX-License-Identifier: AGPL-3.0-only

package bridge

import (
	"context"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/sandbox"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeCaller struct{ response sandbox.CapabilityResponse }

func (c fakeCaller) Call(context.Context, sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	return c.response, nil
}

func TestBridgeRejectsContradictoryAndUnknownErrors(t *testing.T) {
	for _, response := range []sandbox.CapabilityResponse{
		{Code: "UNKNOWN_PRIVATE_ERROR", Error: "TEST-ONLY-sensitive-output"},
		{OK: true, Code: "INTERNAL", ResultJSON: []byte(`{}`)},
		{OK: true, ResultJSON: []byte(`{"error":{"code":"INTERNAL"}}`)},
		{Code: "UNAVAILABLE", ResultJSON: []byte(`{"revision":"unexpected"}`)},
	} {
		_, err := Exchange(t.Context(), fakeCaller{response}, sandbox.CapabilityRequest{}, new(sshdv1.SetPortResponse))
		if status.Code(err) != codes.Unavailable || strings.Contains(err.Error(), "TEST-ONLY-sensitive-output") {
			t.Fatal("unsafe helper result accepted or leaked")
		}
	}
	result, err := Exchange(t.Context(), fakeCaller{sandbox.CapabilityResponse{Code: "PRECONDITION_FAILED", Error: "TEST-ONLY-sensitive-output"}}, sandbox.CapabilityRequest{}, new(sshdv1.SetPortResponse))
	if err != nil || result.Error == nil || result.Error.Code != "PRECONDITION_FAILED" || strings.Contains(result.Error.Message, "TEST-ONLY-sensitive-output") {
		t.Fatal("domain error was not safely mapped")
	}
}
