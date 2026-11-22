// SPDX-License-Identifier: AGPL-3.0-only

package packageinfo

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func catalogFixture(t *testing.T) (document, fstest.MapFS) {
	t.Helper()
	raw := []byte("test-only retained license")
	digest := sha256.Sum256(raw)
	sha := hex.EncodeToString(digest[:])
	notice := Notice{Path: "LICENSES/dependencies/" + sha + ".txt", SourcePath: "LICENSE", SHA256: sha}
	module := Module{Path: "example.com/library", Version: "v1.0.0", Sum: "h1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		License: "MIT", SourceURL: "https://proxy.golang.org/example.com/library/@v/v1.0.0.zip", Notices: []Notice{notice}}
	doc := document{SchemaVersion: "1", CoreSHA256: strings.Repeat("a", 64), SourceSBOMSHA256: strings.Repeat("b", 64),
		SourceNoticesArchiveSHA256: strings.Repeat("c", 64), Modules: []Module{module}, StandardLibraries: []StandardLibrary{
			{Version: "go1.27.3", License: "BSD-3-Clause", Path: notice.Path, SHA256: sha, SourceURL: "https://go.dev/src/LICENSE"},
		}}
	files := fstest.MapFS{notice.Path: &fstest.MapFile{Data: raw}}
	writeFixtureLock(t, doc, files)
	return doc, files
}

func writeFixtureLock(t *testing.T, doc document, files fstest.MapFS) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	files[LockPath] = &fstest.MapFile{Data: raw}
}

func TestCatalogRequiresExactVersionAndChecksum(t *testing.T) {
	doc, files := catalogFixture(t)
	catalog, err := Load(files)
	if err != nil {
		t.Fatal(err)
	}
	want := doc.Modules[0]
	got, err := catalog.Module(want.Path, want.Version, want.Sum)
	if err != nil || got.License != "MIT" {
		t.Fatal("reviewed dependency did not match")
	}
	got.Notices[0].Path = "changed"
	again, err := catalog.Module(want.Path, want.Version, want.Sum)
	if err != nil || again.Notices[0].Path != want.Notices[0].Path {
		t.Fatal("caller changed the catalog")
	}
	for _, input := range []struct{ path, version, sum string }{
		{"example.com/foreign", want.Version, want.Sum}, {want.Path, "v1.0.1", want.Sum}, {want.Path, want.Version, "h1:changed"},
	} {
		if _, err := catalog.Module(input.path, input.version, input.sum); !errors.Is(err, ErrUnreviewed) {
			t.Fatal("unreviewed identity inherited a license")
		}
	}
	if _, err := catalog.StandardLibrary("go1.27.4"); !errors.Is(err, ErrUnreviewed) {
		t.Fatal("unknown core toolchain inherited a license")
	}
}

func TestCatalogRejectsInvalidReviewInputs(t *testing.T) {
	for name, mutate := range map[string]func(*document, fstest.MapFS){
		"unknown license":  func(doc *document, _ fstest.MapFS) { doc.Modules[0].License = "NOASSERTION" },
		"wrong h1":         func(doc *document, _ fstest.MapFS) { doc.Modules[0].Sum = "h1:bad" },
		"duplicate module": func(doc *document, _ fstest.MapFS) { doc.Modules = append(doc.Modules, doc.Modules[0]) },
		"foreign source":   func(doc *document, _ fstest.MapFS) { doc.Modules[0].SourceURL = "https://foreign.invalid/source" },
		"unsafe notice":    func(doc *document, _ fstest.MapFS) { doc.Modules[0].Notices[0].Path = "../outside" },
		"missing notice":   func(doc *document, files fstest.MapFS) { delete(files, doc.Modules[0].Notices[0].Path) },
		"changed bytes": func(doc *document, files fstest.MapFS) {
			files[doc.Modules[0].Notices[0].Path].Data = []byte("changed")
		},
		"directory":     func(doc *document, files fstest.MapFS) { files[doc.Modules[0].Notices[0].Path].Mode = fs.ModeDir },
		"checksum case": func(doc *document, _ fstest.MapFS) { doc.SourceSBOMSHA256 = strings.ToUpper(doc.SourceSBOMSHA256) },
	} {
		t.Run(name, func(t *testing.T) {
			doc, files := catalogFixture(t)
			mutate(&doc, files)
			writeFixtureLock(t, doc, files)
			if _, err := Load(files); !errors.Is(err, ErrIntegrity) {
				t.Fatal("invalid review input was accepted")
			}
		})
	}
}

func TestCatalogRejectsInvalidJSONBoundary(t *testing.T) {
	for _, suffix := range []string{" {}", " true"} {
		_, files := catalogFixture(t)
		files[LockPath].Data = append(files[LockPath].Data, suffix...)
		if _, err := Load(files); !errors.Is(err, ErrIntegrity) {
			t.Fatal("trailing JSON was accepted")
		}
	}
	_, files := catalogFixture(t)
	files[LockPath].Data = []byte(`{"schema_version":"1","unknown":true}`)
	if _, err := Load(files); !errors.Is(err, ErrIntegrity) {
		t.Fatal("unknown lock field was accepted")
	}
}

// TestRepositoryLicenseCatalog 验证实际已审版本、原文摘要和上游Go版本，不能用fixture代替。
func TestRepositoryLicenseCatalog(t *testing.T) {
	catalog, err := Load(os.DirFS("../.."))
	if err != nil {
		t.Fatal(err)
	}
	if catalog.ModuleCount() != 47 || catalog.CoreDigest() != "e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d" {
		t.Fatal("actual reviewed catalog does not cover the fixed core")
	}
	library, err := catalog.StandardLibrary("go1.27.3")
	if err != nil || library.License != "BSD-3-Clause" {
		t.Fatal("fixed core Go license is missing")
	}
	// 发布模式与工作区可选择不同版本，必须匹配真实版本及源码校验和。
	module, err := catalog.Module("golang.org/x/net", "v0.60.0", "h1:79p50tfZlm0J9YfoDsSi639qSXNGVwEzOPLCxM2FsYU=")
	if err != nil || module.License != "BSD-3-Clause" || len(module.Notices) != 2 {
		t.Fatal("production dependency license is missing")
	}
}
