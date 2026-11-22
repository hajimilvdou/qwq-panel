// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

const (
	xrayID     = "core.xray"
	xraySHA256 = "e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d"
)

// TestXrayPackageArtifacts 只读取真实签名包，不需要 systemd 或 root。
// 后续生命周期测试仍须独立开关及干净测试主机。
func TestXrayPackageArtifacts(t *testing.T) {
	requireXrayEnabled(t)
	for _, name := range []string{"QWQ_E2E_TRUST_PUB", "QWQ_E2E_XRAY_PKG_V1", "QWQ_E2E_XRAY_PKG_V2", "QWQ_E2E_XRAY_PKG_BAD"} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is required", name)
		}
	}
	trust := xrayTrustStore(t)
	for _, item := range []struct{ environment, version string }{
		{"QWQ_E2E_XRAY_PKG_V1", "0.1.1"},
		{"QWQ_E2E_XRAY_PKG_V2", "0.1.2"},
		{"QWQ_E2E_XRAY_PKG_BAD", "0.1.3"},
	} {
		t.Run(item.version, func(t *testing.T) {
			path := os.Getenv(item.environment)
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			pack, err := pkgfile.Read(file, trust, pkgfile.ReadOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if pack.Manifest.ID != xrayID || pack.Manifest.Version != item.version || pack.Signature == nil {
				t.Fatal("签名包身份或版本不一致")
			}
			coreDigest := pack.Manifest.Files["bin/xray"]
			if (item.version == "0.1.3") == (coreDigest == "sha256:"+xraySHA256) {
				t.Fatal("固定核心摘要或故障包标记不一致")
			}
			xrayArchive(t, path, func(header *tar.Header, reader io.Reader) {
				if header.Typeflag == tar.TypeDir {
					if header.Mode != 0o755 {
						t.Fatal("包内目录权限不规范")
					}
					return
				}
				mode := int64(0o644)
				if header.Name == "bin/plugin" || header.Name == "bin/xray" {
					mode = 0o755
				}
				if header.Mode != mode {
					t.Fatalf("包内 %s 权限不规范", header.Name)
				}
				if strings.HasSuffix(header.Name, ".key") || strings.HasSuffix(header.Name, ".pem") {
					t.Fatal("发布包含敏感材料路径")
				}
				if header.Name == "attestations/build.json" {
					var build struct {
						Version   string `json:"plugin_version"`
						PluginSHA string `json:"plugin_sha256"`
						CoreSHA   string `json:"xray_sha256"`
						Fault     bool   `json:"fault_injection"`
					}
					if err := json.NewDecoder(reader).Decode(&build); err != nil {
						t.Fatal(err)
					}
					if build.Version != item.version || "sha256:"+build.PluginSHA != pack.Manifest.Files["bin/plugin"] || "sha256:"+build.CoreSHA != coreDigest || build.Fault != (item.version == "0.1.3") {
						t.Fatal("构建来源与包内二进制摘要不一致")
					}
				}
			})
			for _, name := range []string{"attestations/build.json", "attestations/sbom.spdx.json", "sources/stats-wire/stats.proto", "sources/stats-wire/stats.pb.go", "sources/stats-wire/stats_grpc.pb.go", "LICENSES/MPL-2.0.txt"} {
				if pack.Manifest.Files[name] == "" {
					t.Fatalf("发布包缺少 %s", name)
				}
			}
		})
	}
	// 重写合法的 tar/gzip 容器，只改目标字节，保证验证的是签名/内容摘要。
	for _, name := range []string{"manifest.json", "bin/plugin", "bin/xray"} {
		t.Run("tamper_"+strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			path := mutateXrayPackage(t, os.Getenv("QWQ_E2E_XRAY_PKG_V1"), name)
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := pkgfile.Read(file, trust, pkgfile.ReadOptions{}); err == nil {
				t.Fatal("篡改后的真实包通过了校验")
			}
		})
	}
}

func requireXrayEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("QWQ_XRAY_E2E") != "1" {
		t.Skip("显式启用 QWQ_XRAY_E2E=1 才执行 Xray 验收")
	}
}

func xrayTrustStore(t *testing.T) manifest.TrustStore {
	t.Helper()
	public, err := pkgfile.ParsePublicKeyPEM(readFile(t, os.Getenv("QWQ_E2E_TRUST_PUB")))
	if err != nil {
		t.Fatal(err)
	}
	store, err := manifest.NewStaticTrustStore(manifest.TrustedKey{PublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func xrayArchive(t *testing.T, path string, visit func(*tar.Header, io.Reader)) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zipped, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer zipped.Close()
	archive := tar.NewReader(zipped)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		visit(header, archive)
	}
}

func mutateXrayPackage(t *testing.T, source, entry string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tampered.qwq")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zipped := gzip.NewWriter(file)
	archive := tar.NewWriter(zipped)
	changed := false
	xrayArchive(t, source, func(header *tar.Header, reader io.Reader) {
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Name == entry {
			var first [1]byte
			if _, err := io.ReadFull(reader, first[:]); err != nil {
				t.Fatal(err)
			}
			first[0] ^= 1
			if _, err := archive.Write(first[:]); err != nil {
				t.Fatal(err)
			}
			changed = true
		}
		if _, err := io.Copy(archive, reader); err != nil {
			t.Fatal(err)
		}
	})
	if !changed {
		t.Fatal("篡改目标不在包中")
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zipped.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
