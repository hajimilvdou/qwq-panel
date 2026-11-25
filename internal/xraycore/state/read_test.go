// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func snapshotFixture(t *testing.T) (string, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "data")
	config := []byte(`{"fixture":"private native config"}`)
	digest := sha256.Sum256(config)
	name := filepath.Join(directory, "runtime", "generations", hex.EncodeToString(digest[:]), "config.json")
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, config, 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := validMetadata()
	metadata.Current.Digest = "sha256:" + hex.EncodeToString(digest[:])
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "runtime", "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return directory, name
}

// ======================== 真实文件边界，不启动核心 ========================
func TestLoadCommittedSnapshotIsBoundedAndPrivate(t *testing.T) {
	directory, config := snapshotFixture(t)
	metadata, err := Load(t.Context(), directory)
	if err != nil || metadata == nil || metadata.Current.Revision != "7" {
		t.Fatalf("committed snapshot was not read: %v", err)
	}
	if err := os.WriteFile(config, []byte(`{"fixture":"tampered"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(t.Context(), directory); !errors.Is(err, ErrCorrupt) {
		t.Fatal("digest mismatch did not fail closed")
	}
}

func TestLoadUnconfiguredHasNoFilesystemSideEffects(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "absent")
	metadata, err := Load(t.Context(), directory)
	if err != nil || metadata != nil {
		t.Fatalf("absent snapshot was not unconfigured: %v", err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read created a data directory")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Load(ctx, directory); !errors.Is(err, context.Canceled) {
		t.Fatal("read ignored cancellation")
	}
}

// 宿主须下发真实目录；状态读取不因适配 systemd 而放宽任意根链接。
func TestLoadRejectsSymlinkDataDir(t *testing.T) {
	directory, _ := snapshotFixture(t)
	alias := filepath.Join(t.TempDir(), "data-link")
	if err := os.Symlink(directory, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(t.Context(), alias); !errors.Is(err, ErrCorrupt) {
		t.Fatal("symlink data root was accepted")
	}
}

func TestLoadRejectsUnsafeFilesAndMetadata(t *testing.T) {
	for _, name := range []string{"oversized", "unknown-field", "duplicate-field", "public-config", "config-symlink", "missing-config", "runtime-symlink", "uncommitted-config"} {
		t.Run(name, func(t *testing.T) {
			directory, config := snapshotFixture(t)
			metadata := filepath.Join(directory, "runtime", "state.json")
			data, err := os.ReadFile(metadata)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "oversized":
				err = os.WriteFile(metadata, []byte(strings.Repeat(" ", MaxMetadataBytes+1)), 0o600)
			case "unknown-field":
				err = os.WriteFile(metadata, append([]byte(`{"unsafe":"hidden",`), data[1:]...), 0o600)
			case "duplicate-field":
				err = os.WriteFile(metadata, append([]byte(`{"schema_version":"1",`), data[1:]...), 0o600)
			case "public-config":
				err = os.Chmod(config, 0o640)
			case "config-symlink":
				outside := filepath.Join(t.TempDir(), "config.json")
				content, readErr := os.ReadFile(config)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err = os.WriteFile(outside, content, 0o600); err == nil {
					err = os.Remove(config)
				}
				if err == nil {
					err = os.Symlink(outside, config)
				}
			case "missing-config":
				err = os.Remove(config)
			case "runtime-symlink":
				old := filepath.Join(directory, "runtime-old")
				if err = os.Rename(filepath.Join(directory, "runtime"), old); err == nil {
					err = os.Symlink(old, filepath.Join(directory, "runtime"))
				}
			case "uncommitted-config":
				err = os.Remove(metadata)
			}
			if err != nil {
				t.Fatal(err)
			}
			if loaded, err := Load(t.Context(), directory); name == "uncommitted-config" {
				if err != nil || loaded != nil {
					t.Fatal("uncommitted generation was guessed as a recovery source")
				}
			} else if !errors.Is(err, ErrCorrupt) {
				t.Fatal("unsafe snapshot was accepted")
			}
		})
	}
}
