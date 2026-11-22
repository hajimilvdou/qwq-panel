// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

// Package diskfree reports the free space of the filesystem that holds a
// directory. It backs the upload staging preflight (GW-07) and the
// pre-install disk capacity check (GAPS gap 4).
package diskfree

import "errors"

// Bytes is unavailable off unix; callers skip the space check rather than
// blocking work on a development host.
func Bytes(string) (uint64, error) {
	return 0, errors.New("diskfree: free disk space is not available on this platform")
}
