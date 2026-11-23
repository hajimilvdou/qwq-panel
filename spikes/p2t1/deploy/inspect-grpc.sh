#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Inspect the gRPC TransportCredentials interface and how the server transport
# exposes AuthInfo to handlers, for the P2-T1 spike.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
M=${GOMODCACHE:-$(go env GOMODCACHE)}
G=$M/google.golang.org/grpc@v1.85.0
echo '=== credentials.TransportCredentials ==='
sed -n '/^type TransportCredentials interface/,/^}/p' "$G/credentials/credentials.go"
echo
echo '=== AuthInfo ==='
sed -n '/^type AuthInfo interface/,/^}/p' "$G/credentials/credentials.go"
echo
echo '=== server transport authInfo use ==='
grep -rn 'AuthInfo' "$G/internal/transport/http2_server.go" | head -20
echo
echo '=== peer.NewContext usage in server ==='
grep -rn 'peer.NewContext' "$G/internal/transport/"*.go | head -20
echo
echo '=== handleRawConn authInfo ==='
grep -rn 'authInfo' "$G/internal/transport/http2_server.go" | head -20
