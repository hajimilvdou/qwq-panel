// SPDX-License-Identifier: Apache-2.0

package abi

import "testing"

func TestCompatible(t *testing.T) {
	cases := []struct {
		hostMajor, hostMinor, pluginMajor, pluginMinMinor uint32
		want                                              bool
	}{
		{1, 0, 1, 0, true},
		{1, 3, 1, 2, true},
		{1, 2, 1, 3, false},
		{2, 0, 1, 0, false},
		{1, 0, 2, 0, false},
	}
	for _, c := range cases {
		if got := Compatible(c.hostMajor, c.hostMinor, c.pluginMajor, c.pluginMinMinor); got != c.want {
			t.Errorf("Compatible(%d.%d, plugin %d >= .%d) = %v, want %v",
				c.hostMajor, c.hostMinor, c.pluginMajor, c.pluginMinMinor, got, c.want)
		}
	}
}
