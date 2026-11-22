// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	cases := []struct {
		args     []string
		code     int
		inStdout string
		inStderr string
	}{
		{[]string{"version"}, 0, "qwq ", ""},
		{[]string{"help"}, 0, "usage: qwq", ""},
		{nil, 2, "", "usage: qwq"},
		{[]string{"bogus"}, 2, "", `unknown command "bogus"`},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if code := run(c.args, &out, &errb); code != c.code {
			t.Errorf("run(%q) = %d, want %d", c.args, code, c.code)
		}
		if !strings.Contains(out.String(), c.inStdout) || !strings.Contains(errb.String(), c.inStderr) {
			t.Errorf("run(%q): stdout %q stderr %q", c.args, out.String(), errb.String())
		}
	}
}
