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
	if parsed.ID != "monitor.basic" || len(parsed.Operations) != 7 || parsed.Resources.MemoryMaxMB != 24 || len(parsed.Capabilities) != 1 || parsed.Capabilities[0].Name != "metrics.read" {
		t.Fatal("monitor manifest does not match approved capabilities")
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
