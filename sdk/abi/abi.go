// SPDX-License-Identifier: Apache-2.0

// Package abi holds the Platform ABI version implemented by this SDK.
//
// The ABI version is independent of the go-plugin protocol version, plugin API
// versions and state schema versions (ARCH §5.2). A host accepts a plugin when
// the majors are equal and the host minor is at least the plugin's
// manifest abi.minimum_minor.
package abi

const (
	// Major must equal the host's ABI major. Matches manifest abi.major.
	Major = 1
	// Minor is the highest ABI minor this SDK knows. Minors only add fields,
	// RPCs and enum values.
	Minor = 0
	// Package is the protobuf package of the Platform ABI.
	Package = "qwq.platform.v1"
)

// Compatible reports whether a host speaking hostMajor.hostMinor can load a
// plugin that declares pluginMajor and requires at least pluginMinimumMinor.
func Compatible(hostMajor, hostMinor, pluginMajor, pluginMinimumMinor uint32) bool {
	return hostMajor == pluginMajor && hostMinor >= pluginMinimumMinor
}
