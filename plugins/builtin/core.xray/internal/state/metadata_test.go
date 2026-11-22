// SPDX-License-Identifier: AGPL-3.0-only

package state

import (
	"strings"
	"testing"
)

func validMetadata() Metadata {
	return Metadata{SchemaVersion: "1", State: "RUNNING", ResetEpoch: "epoch-fixture",
		Current: &Generation{Digest: "sha256:" + strings.Repeat("a", 64), Revision: "7", Version: "26.11.9", Enabled: true}}
}

func TestMetadataRejectsUnsafeCommittedFields(t *testing.T) {
	if err := validMetadata().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Metadata){
		func(m *Metadata) { m.Current.Digest = "../../config.json" },
		func(m *Metadata) { m.Current.Digest = "sha256:" + strings.Repeat("A", 64) },
		func(m *Metadata) { m.Current.Revision = "01" },
		func(m *Metadata) { m.Current.Revision = "0" },
		func(m *Metadata) { m.Current.Enabled = false },
		func(m *Metadata) { m.Current.Version = "unknown" },
		func(m *Metadata) { m.ResetEpoch = "token/with/path" },
		func(m *Metadata) { m.LastError = "raw upstream diagnostics" },
		func(m *Metadata) { m.State = "UNKNOWN" },
	} {
		m := validMetadata()
		mutate(&m)
		if err := m.Validate(); err == nil {
			t.Fatal("unsafe metadata was accepted")
		}
	}
}
