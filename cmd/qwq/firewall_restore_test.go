// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"io"
	"testing"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

type restoreCapabilityCaller struct{ called bool }

func (c *restoreCapabilityCaller) Call(_ context.Context, r sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	c.called = true
	if r.Op != "firewall.restore" || r.ID != "qwq.bootstrap" || len(r.ParamsJSON) != 0 || len(r.Secret) != 0 {
		return sandbox.CapabilityResponse{}, nil
	}
	return sandbox.CapabilityResponse{OK: true}, nil
}
func TestFirewallRestoreAcceptsOnlyExistingPolicy(t *testing.T) {
	c := new(restoreCapabilityCaller)
	if runFirewallRestore([]string{"--rules"}, io.Discard, c) != 2 || c.called {
		t.Fatal("restore accepted new parameters")
	}
	if runFirewallRestore(nil, io.Discard, c) != 0 || !c.called {
		t.Fatal("saved-policy restore failed")
	}
}
