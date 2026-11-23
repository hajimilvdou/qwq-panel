#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Print the go-plugin source fragments relevant to the P2-T1 spike:
# ReattachConfig handling, Serve/ServeConfig listener creation, and the gRPC
# client/service plumbing. Read-only inspection of the module cache.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off
D=${GOMODCACHE:-$(go env GOMODCACHE)}/github.com/hashicorp/go-plugin@v1.8.0
echo "=== go-plugin dir: $D ==="
echo
echo '=== client.go: ReattachConfig + Start/reattach ==='
awk '/^type ReattachConfig/,/^}/' "$D/client.go"
echo
sed -n '/func (c \*Client) Start()/,/^}/p' "$D/client.go"
echo
echo '=== client.go: dial / dialer / unix ==='
grep -n 'Reattach\|Address\|dial\|Dial\|UnixSocket' "$D/client.go" | sed -n '1,120p'
echo
echo '=== server.go: Serve + ServeConfig + listener ==='
awk '/^type ServeConfig/,/^}/' "$D/server.go"
echo
sed -n '/^func Serve(/,/^}/p' "$D/server.go"
echo
echo '=== server.go: serverListener ==='
sed -n '/func serverListener(/,/^}/p' "$D/server.go"
sed -n '/func serverListener_unix(/,/^}/p' "$D/server.go"
echo
echo '=== grpc_client.go ==='
sed -n '/func newGRPCClient(/,/^}/p' "$D/grpc_client.go"
sed -n '/func (c \*GRPCClient) Dispense(/,/^}/p' "$D/grpc_client.go"
sed -n '/func (c \*GRPCClient) Start(/,/^}/p' "$D/grpc_client.go"
echo
echo '=== grpc_stdio.go: client start ==='
sed -n '/func newGRPCStdioClient(/,/^}/p' "$D/grpc_stdio.go"
sed -n '/func (c \*GRPCStdioClient) Run(/,/^}/p' "$D/grpc_stdio.go"
echo
echo '=== grpc_server.go: service registration ==='
sed -n '/func (s \*GRPCServer) Init(/,/^}/p' "$D/grpc_server.go"
sed -n '/func (s \*GRPCServer) Serve(/,/^}/p' "$D/grpc_server.go"
echo
echo '=== internal/plugin service names ==='
grep -rn 'ServiceName:\|FullMethodName' "$D/internal/plugin/"*.pb.go | head -40
