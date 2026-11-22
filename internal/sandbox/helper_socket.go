// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
)

// ======================== 两个 helper 共用的激活/监听 ========================

// ActivatedFDCount 只允许一条 systemd listener；身份不匹配时不能回退到手工监听。
func ActivatedFDCount(getenv func(string) string, pid int) (int, error) {
	if getenv == nil {
		return 0, nil
	}
	raw := getenv("LISTEN_FDS")
	if raw == "" {
		return 0, nil
	}
	count, err := strconv.Atoi(raw)
	if err != nil || count < 0 {
		return 0, errors.New("sandbox: invalid LISTEN_FDS")
	}
	if count == 0 {
		return 0, nil
	}
	if count != 1 {
		return 0, errors.New("sandbox: helper requires exactly one listener")
	}
	if rawPID := getenv("LISTEN_PID"); rawPID != "" {
		owner, err := strconv.Atoi(rawPID)
		if err != nil || owner != pid {
			return 0, errors.New("sandbox: LISTEN_PID does not match the helper")
		}
	}
	return 1, nil
}

// ListenHelperSocket 复用 socket 激活；手工模式仅创建 root:<group> 0660 的 Unix socket。
func ListenHelperSocket(path, group string, getenv func(string) string) (net.Listener, bool, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 107 {
		return nil, false, errors.New("sandbox: helper socket requires a clean absolute path within the Unix length limit")
	}
	count, err := ActivatedFDCount(getenv, os.Getpid())
	if err != nil {
		return nil, false, err
	}
	if count == 1 {
		file := os.NewFile(3, "qwq-helper.socket")
		if file == nil {
			return nil, false, errors.New("sandbox: activated listener is missing")
		}
		listener, err := net.FileListener(file)
		_ = file.Close()
		if err != nil {
			return nil, false, fmt.Errorf("sandbox: adopting helper listener: %w", err)
		}
		unix, ok := listener.(*net.UnixListener)
		if !ok {
			listener.Close()
			return nil, false, errors.New("sandbox: activated listener is not Unix")
		}
		unix.SetUnlinkOnClose(false)
		return unix, true, nil
	}
	if err := removeStaleHelperSocket(path); err != nil {
		return nil, false, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, false, err
	}
	if err := setHelperSocketAccess(path, group); err != nil {
		listener.Close()
		_ = os.Remove(path)
		return nil, false, err
	}
	return listener, false, nil
}

func removeStaleHelperSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("sandbox: refusing to replace a non-socket helper path")
	}
	return os.Remove(path)
}

func setHelperSocketAccess(path, group string) error {
	entry, err := user.LookupGroup(group)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(entry.Gid)
	if err != nil {
		return errors.New("sandbox: invalid helper socket group")
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	return os.Chown(path, 0, gid)
}

// ServeHelperConnections 一请求一连接；激活模式处理一个连接后退出。手工模式
// 最多运行 maxConcurrent 个 handler，取消关闭 listener 与活动连接，并等待排空。
func ServeHelperConnections(ctx context.Context, listener net.Listener, oneShot bool, maxConcurrent int, handle func(context.Context, net.Conn)) error {
	if ctx == nil || listener == nil || handle == nil || maxConcurrent < 1 {
		return errors.New("sandbox: invalid helper server configuration")
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	limiter := make(chan struct{}, maxConcurrent)
	serve := func(connection net.Conn) {
		defer connection.Close()
		stopConnection := context.AfterFunc(ctx, func() { _ = connection.Close() })
		defer stopConnection()
		handle(ctx, connection)
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if oneShot {
			serve(connection)
			return nil
		}
		select {
		case limiter <- struct{}{}:
		case <-ctx.Done():
			connection.Close()
			return nil
		}
		workers.Add(1)
		go func() { defer workers.Done(); defer func() { <-limiter }(); serve(connection) }()
	}
}
