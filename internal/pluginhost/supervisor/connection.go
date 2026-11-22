// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ======================== 原生 Unix gRPC；进程身份和启停仍由 systemd 管理 ========================

// PluginDialOptions 统一本机插件连接的传输凭据与 ABI 消息上限。
// Unix socket 的 peer/路径权限由独立入口核验，不启动另一套 PID 监视器。
func PluginDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxPluginMessageBytes),
			grpc.MaxCallSendMsgSize(MaxPluginMessageBytes),
		),
	}
}

// OpenPluginConnection 只在真实 HTTP/2 就绪后交出连接；失败和取消均关闭已创建句柄。
// 调用方仍须重新核验真实进程代次/版本，并在不再使用时关闭连接。
func OpenPluginConnection(ctx context.Context, socket string, timeout time.Duration) (*grpc.ClientConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connection, err := grpc.NewClient("unix://"+socket, PluginDialOptions()...)
	if err != nil {
		return nil, err
	}
	if err := waitReady(ctx, connection, timeout); err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}
