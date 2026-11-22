// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bufio"
	"context"
	"io"
	"net"
	"path/filepath"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// WatchHelperDisconnect 在完整请求读取后监听对端断开，使取消能传到执行器。
// 每个在途请求仅一个监听协程；finish 主动中断读取并等待它退出。
// 对端须保持双向连接直到响应，CapabilityClient 已遵循该协议。
func WatchHelperDisconnect(ctx context.Context, connection net.Conn) (context.Context, func()) {
	return watchHelperDisconnect(ctx, connection, connection)
}

// WatchHelperReaderDisconnect 复用原监听，也消费同一 reader 中已预读的额外帧。
func WatchHelperReaderDisconnect(ctx context.Context, connection net.Conn, reader *bufio.Reader) (context.Context, func()) {
	return watchHelperDisconnect(ctx, connection, reader)
}

func watchHelperDisconnect(ctx context.Context, connection net.Conn, reader io.Reader) (context.Context, func()) {
	execution, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	stop := context.AfterFunc(execution, func() {
		if err := connection.SetReadDeadline(time.Now()); err != nil {
			_ = connection.Close()
		}
	})
	go func() {
		defer close(done)
		var extra [1]byte
		_, _ = reader.Read(extra[:])
		cancel()
	}()
	return execution, func() { cancel(); <-done; stop() }
}

// exchange 是两个 helper 客户端唯一的传输路径；没有业务动作重试。
func (c *HelperClient) exchange(ctx context.Context, request, response any) error {
	return c.exchangeChecked(ctx, request, response, nil)
}

// exchangeChecked 与旧调用共用完整传输；peer 门禁在写任何正文之前执行。
func (c *HelperClient) exchangeChecked(ctx context.Context, request, response any, checkPeer func(net.Conn) error) error {
	if c == nil {
		return problem.New(problem.Unavailable, "No privileged helper client is configured.")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.Socket == "" {
		return problem.New(problem.Unavailable, "No privileged helper socket is configured.")
	}
	if !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket {
		return problem.New(problem.Unavailable, "The privileged helper socket path is not a clean absolute path.")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultHelperTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := c.connect(ctx)
	if err != nil {
		return helperTransportFailure("reach", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return helperTransportFailure("configure", err)
		}
	}
	// deadline 控制最长等待；取消必须提前中断已连接的读写。
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if checkPeer != nil {
		if err := checkPeer(conn); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return helperTransportFailure("send the request to", err)
	}
	if err := WriteHelperJSON(conn, request); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return helperTransportFailure("send the request to", err)
	}
	if err := ReadHelperJSON(conn, response); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return helperTransportFailure("read the answer from", err)
	}
	return nil
}
