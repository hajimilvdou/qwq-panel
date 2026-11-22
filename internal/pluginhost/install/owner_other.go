// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package install

// verifyTreeOwner is a no-op where root ownership is not expressible. The
// production installer only runs on Linux, where owner_unix.go asserts it.
func verifyTreeOwner(string) error { return nil }
