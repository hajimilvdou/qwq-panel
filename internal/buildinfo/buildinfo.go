// SPDX-License-Identifier: AGPL-3.0-only

// Package buildinfo reports the version of the running binary.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/qwq-panel/qwq/sdk/abi"
)

// Version is the release version, set at link time:
//
//	-ldflags "-X github.com/qwq-panel/qwq/internal/buildinfo.Version=v0.1.0"
var Version = "dev"

// Info describes a build.
type Info struct {
	Version   string `json:"version"`
	Revision  string `json:"revision,omitempty"`
	Modified  bool   `json:"modified,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
	ABI       string `json:"abi"`
}

// Read collects build information from the linker flag and the VCS stamp that
// the Go toolchain embeds.
func Read() Info {
	info := Info{
		Version:   Version,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		ABI:       fmt.Sprintf("%s %d.%d", abi.Package, abi.Major, abi.Minor),
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				info.Revision = s.Value
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}
	return info
}

// String formats the info on one line.
func (i Info) String() string {
	rev := i.Revision
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev == "" {
		rev = "unknown"
	}
	if i.Modified {
		rev += "+dirty"
	}
	return fmt.Sprintf("%s (%s, %s, %s, ABI %s)", i.Version, rev, i.GoVersion, i.Platform, i.ABI)
}
