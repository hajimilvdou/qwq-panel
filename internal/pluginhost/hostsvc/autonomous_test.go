// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc_test

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	accountv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/account/v1"
	banv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/ban/v1"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

type fakeBgChecker struct {
	active bool
}

func (f fakeBgChecker) IsActiveBackgroundInstance(_, _ string) bool {
	return f.active
}

func TestAutonomousCapabilityWriteGate(t *testing.T) {
	// 1. Active background instance can execute allowlisted ban.apply via auton:ban_loop
	fwd := &capabilityForwarder{response: &banv1.ApplyBansResponse{}}
	srv := startServer(t, func(c *hostsvc.Config) {
		c.GrantedCapabilities = []*platformv1.Capability{
			capability("system.ban.manage", "self"),
			capability("system.sshd.configure", "self"),
			capability("system.account.password", "all"),
		}
		c.AutonomousChecker = fakeBgChecker{active: true}
		c.CapabilityForwarder = fwd
	})

	_, err := banv1.NewBanServiceClient(srv.Conn()).ApplyBans(testContext(t), &banv1.ApplyBansRequest{
		Context: &platformv1.HostCallContext{InstanceHandle: "h1", OperationId: "auton:ban_loop"},
	})
	if err != nil {
		t.Fatalf("allowlisted autonomous ban.apply failed: %v", err)
	}

	// 2. sshd.set-port via auton:* MUST reject PREPARE / COMMIT and ONLY allow ROLLBACK
	fwd.response = &sshdv1.SetPortResponse{}
	_, err = sshdv1.NewSshdServiceClient(srv.Conn()).SetPort(testContext(t), &sshdv1.SetPortRequest{
		Context: &platformv1.HostCallContext{InstanceHandle: "h1", OperationId: "auton:sshd_sneaky"},
		Stage:   sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ADD_NEW,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("autonomous sshd ADD_NEW = %v, want PermissionDenied", err)
	}
	_, err = sshdv1.NewSshdServiceClient(srv.Conn()).SetPort(testContext(t), &sshdv1.SetPortRequest{
		Context: &platformv1.HostCallContext{InstanceHandle: "h1", OperationId: "auton:sshd_saga_rollback"},
		Stage:   sshdv1.PortChangeStage_PORT_CHANGE_STAGE_ROLLBACK,
	})
	if err != nil {
		t.Fatalf("autonomous sshd ROLLBACK failed: %v", err)
	}

	// 3. Non-allowlisted dangerous verb (account.set-password) is denied on auton:*
	fwd.response = &accountv1.SetPasswordResponse{}
	_, err = accountv1.NewAccountServiceClient(srv.Conn()).SetPassword(testContext(t), &accountv1.SetPasswordRequest{
		Context: &platformv1.HostCallContext{InstanceHandle: "h1", OperationId: "auton:evil"},
		User:    "alice",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("autonomous account.set-password = %v, want PermissionDenied", err)
	}

	// 4. Non-background / inactive instance is rejected with FailedPrecondition
	srvInactive := startServer(t, func(c *hostsvc.Config) {
		c.GrantedCapabilities = []*platformv1.Capability{capability("system.ban.manage", "self")}
		c.AutonomousChecker = fakeBgChecker{active: false}
		c.CapabilityForwarder = &capabilityForwarder{response: &banv1.ApplyBansResponse{}}
	})
	_, err = banv1.NewBanServiceClient(srvInactive.Conn()).ApplyBans(testContext(t), &banv1.ApplyBansRequest{
		Context: &platformv1.HostCallContext{InstanceHandle: "h1", OperationId: "auton:ban_loop"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("inactive instance autonomous ban.apply = %v, want FailedPrecondition", err)
	}
}
