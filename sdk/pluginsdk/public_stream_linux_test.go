// SPDX-License-Identifier: Apache-2.0

//go:build linux

package pluginsdk

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultPublicStreamPeerVerifierFailsClosedWhenHostSocketMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nonexistent-host.sock")
	verify := defaultPublicStreamPeerVerifier(missing)
	if verify == nil {
		t.Fatal("defaultPublicStreamPeerVerifier returned nil on missing host.sock; must fail closed")
	}
	err := verify(nil)
	if err == nil || !strings.Contains(err.Error(), "host socket peer UID unavailable") {
		t.Fatalf("expected fail-closed peer UID unavailable error, got %v", err)
	}
}
