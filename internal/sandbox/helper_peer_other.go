// SPDX-License-Identifier: AGPL-3.0-only
//go:build !linux

package sandbox

import (
	"errors"
	"net"
)

func HelperPeerUID(net.Conn) (int, error) {
	return 0, errors.New("sandbox: helper peer verification requires Linux")
}
