// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"net/rpc"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/qwq-panel/qwq/spikes/p2t1/internal/echopb"
)

// echoPlugin adapts the spike's gRPC client to go-plugin. Only GRPCClient is
// used: the plugin process is started by systemd and connected to through
// ReattachConfig, so go-plugin never starts or stops it.
type echoPlugin struct{}

// Server implements plugin.Plugin (net/rpc); unused.
func (echoPlugin) Server(*plugin.MuxBroker) (any, error) {
	return nil, errNotSupported
}

// Client implements plugin.Plugin (net/rpc); unused.
func (echoPlugin) Client(*plugin.MuxBroker, *rpc.Client) (any, error) {
	return nil, errNotSupported
}

// GRPCServer implements plugin.GRPCPlugin; the agent is not a plugin server.
func (echoPlugin) GRPCServer(*plugin.GRPCBroker, *grpc.Server) error {
	return errNotSupported
}

// GRPCClient implements plugin.GRPCPlugin and returns the typed client on the
// connection go-plugin dialled.
func (echoPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	return echopb.NewEchoClient(conn), nil
}

var errNotSupported = errors.New("net/rpc and server modes are not used by the spike")
