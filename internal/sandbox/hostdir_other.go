// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package sandbox

import (
	"errors"
	"os"
)

// ensureHostDir 只在 Linux 上实现：root helper 与插件沙箱都只跑在 Linux。
func ensureHostDir(*os.Root, string, int, int) error {
	return errors.New("sandbox: the plugin host channel directory is only supported on Linux")
}
