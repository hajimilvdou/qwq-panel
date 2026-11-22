// SPDX-License-Identifier: AGPL-3.0-only

package buildinfo

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	i := Info{Version: "v1.2.3", Revision: "0123456789abcdef", Modified: true,
		GoVersion: "go1.27.3", Platform: "linux/amd64", ABI: "qwq.platform.v1 1.0"}
	got := i.String()
	want := "v1.2.3 (0123456789ab+dirty, go1.27.3, linux/amd64, ABI qwq.platform.v1 1.0)"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if s := (Info{Version: "dev"}).String(); !strings.Contains(s, "unknown") {
		t.Fatalf("missing revision not reported: %q", s)
	}
}

func TestReadFillsRuntime(t *testing.T) {
	i := Read()
	if i.GoVersion == "" || i.Platform == "" || !strings.HasPrefix(i.ABI, "qwq.platform.v1 ") {
		t.Fatalf("Read() = %+v", i)
	}
}
