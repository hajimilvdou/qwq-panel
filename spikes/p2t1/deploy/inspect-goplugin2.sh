#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Print the go-plugin Reattach() implementation and the cmdrunner reattach
# helper, so the spike can document Pid semantics for socket-activated units.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off
D=${GOMODCACHE:-$(go env GOMODCACHE)}/github.com/hashicorp/go-plugin@v1.8.0
echo '=== client.go reattach() ==='
sed -n '/^func (c \*Client) reattach()/,/^}/p' "$D/client.go"
echo
echo '=== client.go Client()/Kill()/Protocol() ==='
sed -n '/^func (c \*Client) Client()/,/^}/p' "$D/client.go"
sed -n '/^func (c \*Client) Kill()/,/^}/p' "$D/client.go"
sed -n '/^func (c \*Client) Protocol()/,/^}/p' "$D/client.go"
echo
echo '=== client.go Ping / GRPCClient.Ping ==='
sed -n '/^func (c \*GRPCClient) Ping()/,/^}/p' "$D/grpc_client.go"
echo
echo '=== cmdrunner reattach ==='
sed -n '/func ReattachFunc(/,/^}/p' "$D/internal/cmdrunner/runner.go"
echo
echo '=== runner.go reattach state ==='
grep -n 'reattach\|Reattach\|attached' "$D/internal/cmdrunner/runner.go" | head -40
echo
echo '=== grpc_broker_client StartStream ==='
sed -n '/func (c \*GRPCBrokerClient) StartStream/,/^}/p' "$D/grpc_broker.go"
echo
echo '=== plugin.go interface ==='
sed -n '/^type Plugin interface/,/^}/p' "$D/plugin.go"
sed -n '/^type GRPCPlugin interface/,/^}/p' "$D/plugin.go"
