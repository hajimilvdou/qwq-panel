// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestExchangeManagerLifecycleAndSecurity(t *testing.T) {
	mgr := NewExchangeManager(t.TempDir())

	// Create task subfolder with Unicode/Chinese name.
	dirEnt, err := mgr.Mkdir("审查报告/原始资料")
	if err != nil || !dirEnt.IsDir || dirEnt.Path != "审查报告/原始资料" {
		t.Fatalf("Mkdir = (%+v, %v)", dirEnt, err)
	}

	// Upload / write files into subfolder.
	f1, err := mgr.SaveStream("审查报告/原始资料/config.json", strings.NewReader(`{"port":443}`), 1<<20)
	if err != nil || f1.Size != 12 {
		t.Fatalf("SaveStream = (%+v, %v)", f1, err)
	}
	if _, err := mgr.WriteText("审查报告/输出报告.md", "# 审查结论\n一切正常。\n"); err != nil {
		t.Fatalf("WriteText: %v", err)
	}

	// List root and subfolder.
	rootList, err := mgr.List("")
	if err != nil || rootList.TotalDirs != 1 || rootList.Entries[0].Name != "审查报告" {
		t.Fatalf("List root = (%+v, %v)", rootList, err)
	}
	subList, err := mgr.List("审查报告")
	if err != nil || subList.TotalDirs != 1 || subList.TotalFiles != 1 {
		t.Fatalf("List sub = (%+v, %v)", subList, err)
	}

	// Preview text.
	prev, err := mgr.Preview("审查报告/输出报告.md")
	if err != nil || !prev.IsText || !strings.Contains(prev.Content, "审查结论") {
		t.Fatalf("Preview = (%+v, %v)", prev, err)
	}

	// Zip archive of folder.
	full, info, _, err := mgr.ResolveDownload("审查报告")
	if err != nil || !info.IsDir() {
		t.Fatalf("ResolveDownload dir = (%v, %v)", info, err)
	}
	var zbuf bytes.Buffer
	if err := mgr.WriteZipArchive(&zbuf, full); err != nil {
		t.Fatalf("WriteZipArchive: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zbuf.Bytes()), int64(zbuf.Len()))
	if err != nil || len(zr.File) < 2 {
		t.Fatalf("zip reader = (%d files, %v)", len(zr.File), err)
	}

	// Rename file and refuse moving folder into itself.
	if _, err := mgr.Rename("审查报告/输出报告.md", "审查报告/最终报告.md"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := mgr.Rename("审查报告", "审查报告/sub"); err == nil {
		t.Fatal("expected error moving folder into itself")
	}

	// Path traversal attempts must fail.
	for _, bad := range []string{"../etc/passwd", "a/../../b", "C:/Windows/win.ini", "bad\x00name"} {
		if _, err := mgr.List(bad); err == nil {
			t.Errorf("expected List(%q) to fail", bad)
		}
		if _, err := mgr.WriteText(bad, "x"); err == nil {
			t.Errorf("expected WriteText(%q) to fail", bad)
		}
	}

	// Delete subfolder recursively.
	if err := mgr.Delete("审查报告"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	after, err := mgr.List("")
	if err != nil || len(after.Entries) != 0 {
		t.Fatalf("after delete = (%+v, %v)", after, err)
	}
}
