// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

func TestMonitorManifestAndPackageFiles(t *testing.T) {
	parsed, err := manifest.Parse(Manifest())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != "monitor.basic" || len(parsed.Operations) != 8 || parsed.Resources.MemoryMaxMB != 24 || len(parsed.Capabilities) != 4 {
		t.Fatal("monitor manifest does not match approved capabilities")
	}
	wantCaps := map[string]string{
		"metrics.read":   "self",
		"state.kv.read":  "self",
		"state.kv.write": "self",
		"events.publish": "monitor.alert",
	}
	for _, cap := range parsed.Capabilities {
		if wantCaps[cap.Name] != cap.Scope {
			t.Fatalf("unexpected monitor capability: %s:%s", cap.Name, cap.Scope)
		}
	}
	for name := range parsed.Files {
		if name != parsed.Entrypoint {
			if _, err := os.Stat(name); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			if parsed.Files[name] != "sha256:"+hex.EncodeToString(digest[:]) {
				t.Fatalf("manifest digest drift: %s", name)
			}
		}
	}
}
