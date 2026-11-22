// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"context"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/sandbox"
	firewallv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/firewall/v1"
)

type serviceCaller struct {
	service *Service
	calls   []sandbox.CapabilityRequest
}

func (c *serviceCaller) Call(ctx context.Context, request sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	recorded := request
	recorded.ParamsJSON = append([]byte(nil), request.ParamsJSON...)
	c.calls = append(c.calls, recorded)
	return c.service.Run(ctx, request)
}

func TestFirewallForwarderInjectsFactsAndRejectsOmission(t *testing.T) {
	s, n, _, _ := firewallFixture()
	caller := &serviceCaller{service: s}
	f := Forwarder{Helper: caller, HostPorts: []uint32{9443}}
	get, err := f.Forward(t.Context(), hostsvc.CapabilityCall{Service: "firewall", Method: "GetRuleset", PluginID: "security.basic", Request: new(firewallv1.GetRulesetRequest)})
	if err != nil || get.Error != nil {
		t.Fatal("get through helper failed")
	}
	current := get.Response.(*firewallv1.GetRulesetResponse)
	request := &firewallv1.ApplyRulesetRequest{RulesetJson: []byte(testRuleset), ExpectedRevision: current.Revision, PreservedPorts: []uint32{22, 8443}}
	call := hostsvc.CapabilityCall{Service: "firewall", Method: "ApplyRuleset", PluginID: "security.basic", Request: request}
	result, err := f.Forward(t.Context(), call)
	if err != nil || result.Error == nil || result.Error.Code != "VALIDATION_FAILED" || n.writes != 0 {
		t.Fatal("plugin omitted the host's real port")
	}
	request.PreservedPorts = append(request.PreservedPorts, 9443)
	result, err = f.Forward(t.Context(), call)
	if err != nil || result.Error != nil || n.writes != 1 {
		t.Fatal("host-protected apply failed")
	}
	last := caller.calls[len(caller.calls)-1]
	if last.ID != "security.basic" || !strings.Contains(string(last.ParamsJSON), "host_preserved_ports") || strings.Contains(string(last.ParamsJSON), "instance_handle") {
		t.Fatal("helper identity or host fact envelope is invalid")
	}
}
