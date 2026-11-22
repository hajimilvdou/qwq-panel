// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package apply

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	coreapiv2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

// ======================== 当前网络命名空间 + 原 PID 的精确 inode ========================

type listeningSocket struct {
	endpoint netip.AddrPort
	inode    uint64
}

func verifyOwnedPortConflict(ctx context.Context, target, previous netip.AddrPort, pid int) error {
	inodes := make(map[uint64]bool)
	for _, path := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		sockets, err := conflictingSockets(ctx, path, target)
		if errors.Is(err, os.ErrNotExist) && strings.HasSuffix(path, "/tcp6") {
			continue // 内核未启用 IPv6 时没有 tcp6 表，不虚构另一族监听。
		}
		if err != nil {
			return err
		}
		for _, socket := range sockets {
			// 同一通配配置在内核可能呈现为另一族通配地址，仍须逐 inode 核原 PID。
			wildcard := socket.endpoint.Port() == previous.Port() && socket.endpoint.Addr().IsUnspecified() && previous.Addr().IsUnspecified()
			if socket.endpoint != previous && !wildcard {
				return errPortIdentity
			}
			inodes[socket.inode] = true
		}
	}
	if len(inodes) == 0 {
		return errPortIdentity
	}
	return verifySocketOwner(ctx, pid, inodes)
}

func conflictingSockets(ctx context.Context, path string, target netip.AddrPort) (sockets []listeningSocket, err error) {
	table, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, table.Close()) }()
	scanner := bufio.NewScanner(table)
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "local_address") {
		return nil, errPortIdentity
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		if len(fields) < 10 {
			return nil, errPortIdentity
		}
		endpoint, err := procSocketEndpoint(fields[1])
		if err != nil {
			return nil, err
		}
		if endpoint.Port() != target.Port() {
			continue
		}
		// 复用 v2 的地址族重叠规则；:: 仍按可能双栈保守判断。
		if coreapiv2.CheckListenerConflicts([]coreapiv2.Listener{
			{ProfileID: "candidate", Network: "tcp", Listen: target.Addr().String(), Port: int(target.Port())},
			{ProfileID: "existing", Network: "tcp", Listen: endpoint.Addr().String(), Port: int(endpoint.Port())},
		}) == nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			return nil, errPortIdentity
		}
		sockets = append(sockets, listeningSocket{endpoint: endpoint, inode: inode})
	}
	return sockets, scanner.Err()
}

// procSocketEndpoint 按内核的本机字节序读取 IPv4 / IPv6 的 32 位字，端口为网络序十六进制。
func procSocketEndpoint(text string) (netip.AddrPort, error) {
	address, portText, ok := strings.Cut(text, ":")
	if !ok || len(address) != 8 && len(address) != 32 || len(portText) != 4 {
		return netip.AddrPort{}, errPortIdentity
	}
	port, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return netip.AddrPort{}, errPortIdentity
	}
	var bytes [16]byte
	for offset := 0; offset < len(address); offset += 8 {
		word, err := strconv.ParseUint(address[offset:offset+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, errPortIdentity
		}
		binary.NativeEndian.PutUint32(bytes[offset/2:offset/2+4], uint32(word))
	}
	addr, ok := netip.AddrFromSlice(bytes[:len(address)/2])
	if !ok {
		return netip.AddrPort{}, errPortIdentity
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

// verifySocketOwner 只保留少量相关监听 inode；按批扫描 fd，不缓存连接或整个 fd 表。
func verifySocketOwner(ctx context.Context, pid int, inodes map[uint64]bool) (err error) {
	directory := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fds, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, fds.Close()) }()
	for len(inodes) != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, readErr := fds.ReadDir(64)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		for _, entry := range entries {
			link, err := os.Readlink(filepath.Join(directory, entry.Name()))
			if errors.Is(err, os.ErrNotExist) {
				continue // 连接 fd 可在读取时正常关闭，不把消失当作监听归属。
			}
			if err != nil {
				return err
			}
			text, socket := strings.CutPrefix(link, "socket:[")
			if !socket || !strings.HasSuffix(text, "]") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(text, "]"), 10, 64)
			if err != nil {
				return errPortIdentity
			}
			delete(inodes, inode)
		}
		if errors.Is(readErr, io.EOF) && len(inodes) != 0 {
			return errPortIdentity
		}
	}
	return nil
}
