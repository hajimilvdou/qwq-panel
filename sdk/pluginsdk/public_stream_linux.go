// SPDX-License-Identifier: Apache-2.0

//go:build linux

package pluginsdk

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

const requirePublicStreamPeerVerification = true

// defaultPublicStreamPeerVerifier checks SO_PEERCRED on Linux so only the host
// agent (owner of host.sock), root, or the same process UID can dial the stream
// bridge socket. If host.sock metadata cannot be inspected, it fails closed and
// rejects all incoming connections rather than disabling peer verification.
func defaultPublicStreamPeerVerifier(hostSocketEnv string) func(net.Conn) error {
	st, err := os.Stat(hostSocketEnv)
	if err != nil {
		return func(net.Conn) error {
			return fmt.Errorf("public stream: host socket peer UID unavailable: %w", err)
		}
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return func(net.Conn) error {
			return errors.New("public stream: host socket stat_t unavailable")
		}
	}
	hostUID := sys.Uid
	selfUID := uint32(os.Geteuid())
	return func(conn net.Conn) error {
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			return errors.New("public stream peer is not a unix connection")
		}
		raw, err := uc.SyscallConn()
		if err != nil {
			return err
		}
		var ucred *syscall.Ucred
		var ctlErr error
		if err := raw.Control(func(fd uintptr) {
			ucred, ctlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		}); err != nil {
			return err
		}
		if ctlErr != nil {
			return ctlErr
		}
		if ucred == nil {
			return errors.New("missing peer credentials")
		}
		if ucred.Uid != 0 && ucred.Uid != hostUID && ucred.Uid != selfUID {
			return errors.New("unauthorized public stream peer uid")
		}
		return nil
	}
}
