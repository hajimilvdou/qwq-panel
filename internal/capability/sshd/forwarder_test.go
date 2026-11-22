// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/sandbox"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type recordingCaller struct {
	request  sandbox.CapabilityRequest
	response sandbox.CapabilityResponse
	calls    int
}

func (c *recordingCaller) Call(_ context.Context, request sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	c.calls++
	c.request = request
	c.request.ParamsJSON = slices.Clone(request.ParamsJSON)
	return c.response, nil
}

func TestSshdForwarderBindsIdentityAndExplicitStage(t *testing.T) {
	raw, err := protojson.Marshal(&sshdv1.SetPortResponse{Revision: "result"})
	if err != nil {
		t.Fatal(err)
	}
	helper := &recordingCaller{response: sandbox.CapabilityResponse{OK: true, ResultJSON: raw}}
	forwarder := Forwarder{Helper: helper, HostPorts: []uint32{8443}}
	request := &sshdv1.SetPortRequest{Context: &platformv1.HostCallContext{OperationId: "plugin-spoof"}, NewPort: 2233, Stage: sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ADD_NEW}
	call := hostsvc.CapabilityCall{Service: "sshd", Method: "SetPort", PluginID: "security.basic", InstanceID: "default", OperationID: "op_00000000000000000000000001", Request: request}
	result, err := forwarder.Forward(t.Context(), call)
	if err != nil || result.Error != nil {
		t.Fatal("forward failed")
	}
	var mutation PortMutation
	if err := json.Unmarshal(helper.request.ParamsJSON, &mutation); err != nil {
		t.Fatal(err)
	}
	if mutation.OperationID != call.OperationID || mutation.InstanceID != call.InstanceID || mutation.Stage != "ADD_NEW" || !slices.Equal(mutation.HostPorts, forwarder.HostPorts) {
		t.Fatal("host identity or facts came from plugin request")
	}
	request.Stage = sshdv1.PortChangeStage_PORT_CHANGE_STAGE_UNSPECIFIED
	result, err = forwarder.Forward(t.Context(), call)
	if err != nil || result.Error == nil || result.Error.Code != "VALIDATION_FAILED" || helper.calls != 1 {
		t.Fatal("unspecified stage reached helper")
	}
}

func TestRootLoginModeCannotConflictWithLegacyBool(t *testing.T) {
	denied := false
	request := &sshdv1.SetLoginPolicyRequest{PermitRootLogin: &denied, RootLoginMode: sshdv1.RootLoginMode_ROOT_LOGIN_MODE_KEYS_ONLY}
	if _, ok := rootMode(request); ok {
		t.Fatal("conflicting root modes accepted")
	}
	request.PermitRootLogin = nil
	if value, ok := rootMode(request); !ok || value != "prohibit-password" {
		t.Fatal("keys-only root mode not rendered")
	}
}
