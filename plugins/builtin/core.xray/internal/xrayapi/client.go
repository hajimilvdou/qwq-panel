// SPDX-License-Identifier: AGPL-3.0-only

// Package xrayapi 仅通过私有文件系统 UDS 读取锁定核心的统计，不提供 reset。
package xrayapi

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/xrayapi/wire"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/xrayconfig"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	MaxResponse = 128 << 10
	MaxCounters = 2 * (coreapi.MaxUsers + 8)
	RPCTimeout  = 2 * time.Second
)

var (
	ErrSocket      = errors.New("xrayapi: private socket is unavailable")
	ErrUnavailable = errors.New("xrayapi: statistics API is unavailable")
	ErrCounter     = errors.New("xrayapi: counter name is invalid")
	ErrMissing     = errors.New("xrayapi: counter is not present")
	ErrResponse    = errors.New("xrayapi: statistics response is invalid")
)

// Client 的 dialer 忽略地址与环境代理，连接目标始终是已校验的私有 socket。
type Client struct {
	connection *grpc.ClientConn
	service    wire.StatsServiceClient
}

// New 验证 socket 的属主、目录和权限；连接建立时再次检查，拒绝 symlink。
func New(socket string) (*Client, error) {
	if !privateSocket(socket) {
		return nil, ErrSocket
	}
	connection, err := grpc.NewClient("passthrough:///qwq-xray-stats",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithNoProxy(),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			if !privateSocket(socket) {
				return nil, ErrSocket
			}
			return (&net.Dialer{Timeout: RPCTimeout}).DialContext(ctx, "unix", socket)
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxResponse), grpc.MaxCallSendMsgSize(16<<10)),
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Client{connection: connection, service: wire.NewStatsServiceClient(connection)}, nil
}

// Close 释放连接及其后台资源；调用方负责实例/核心换代时关闭旧客户端。
func (c *Client) Close() error {
	if c == nil || c.connection == nil {
		return nil
	}
	return c.connection.Close()
}

// Get 区分真实零值和不存在；名称只能由稳定面板 ID 构成。
func (c *Client) Get(parent context.Context, name string) (int64, error) {
	if !validCounter(name) {
		return 0, ErrCounter
	}
	if c == nil || c.service == nil {
		return 0, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, RPCTimeout)
	defer cancel()
	response, err := c.service.QueryStats(ctx, &wire.QueryStatsRequest{Pattern: name, Reset_: false})
	if err != nil {
		return 0, ErrUnavailable
	}
	if response == nil {
		return 0, ErrResponse
	}
	if len(response.GetStat()) == 0 {
		return 0, ErrMissing
	}
	if len(response.GetStat()) != 1 {
		return 0, ErrResponse
	}
	stat := response.GetStat()[0]
	if stat == nil || stat.GetName() != name || stat.GetValue() < 0 {
		return 0, ErrResponse
	}
	return stat.GetValue(), nil
}

// Counters 使用固定前缀读取业务统计；缺失系列不补零，不接受任意 pattern。
func (c *Client) Counters(parent context.Context) (map[string]int64, error) {
	if c == nil || c.service == nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, RPCTimeout)
	defer cancel()
	result := make(map[string]int64)
	for _, prefix := range []string{"inbound>>>qwq-in-", "user>>>qwq-user-"} {
		response, err := c.service.QueryStats(ctx, &wire.QueryStatsRequest{Pattern: prefix, Reset_: false})
		if err != nil {
			return nil, ErrUnavailable
		}
		if response == nil || len(response.GetStat()) > MaxCounters-len(result) {
			return nil, ErrResponse
		}
		for _, stat := range response.GetStat() {
			if stat == nil || !strings.HasPrefix(stat.GetName(), prefix) || !validCounter(stat.GetName()) || stat.GetValue() < 0 {
				return nil, ErrResponse
			}
			if _, duplicate := result[stat.GetName()]; duplicate {
				return nil, ErrResponse
			}
			result[stat.GetName()] = stat.GetValue()
		}
	}
	return result, nil
}

// ---- 私有端点与固定统计身份 ------------------------------------------------

func privateSocket(socket string) bool {
	if !xrayconfig.ValidSocket(socket) {
		return false
	}
	directory, err := os.Lstat(filepath.Dir(socket))
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0o700 || directory.Mode()&os.ModeSymlink != 0 {
		return false
	}
	owner, ok := sandbox.FileOwner(directory)
	if !ok || owner != os.Geteuid() {
		return false
	}
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return false
	}
	owner, ok = sandbox.FileOwner(info)
	return ok && owner == os.Geteuid()
}

func validCounter(name string) bool {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || parts[2] != "traffic" || parts[3] != "uplink" && parts[3] != "downlink" {
		return false
	}
	var id string
	var expected string
	var err error
	switch parts[0] {
	case "inbound":
		id = strings.TrimPrefix(parts[1], "qwq-in-")
		expected, err = coreapi.InboundTag(id)
	case "user":
		id = strings.TrimPrefix(parts[1], "qwq-user-")
		expected, err = coreapi.UserEmail(id)
	default:
		return false
	}
	return err == nil && expected == parts[1]
}
