// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package apply

func probeSocketMarkPermitted() bool {
	return false
}
