// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package pluginsdk

import "net"

func defaultPublicStreamPeerVerifier(string) func(net.Conn) error {
	return nil
}
