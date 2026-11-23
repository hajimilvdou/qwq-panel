#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Print the go-plugin cmdrunner reattach implementation and the protobuf service
# names relevant to a minimal gRPC plugin server.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off
D=${GOMODCACHE:-$(go env GOMODCACHE)}/github.com/hashicorp/go-plugin@v1.8.0
echo '=== cmdrunner files ==='
ls "$D/internal/cmdrunner/" 2>/dev/null || find "$D" -name '*runner*' -maxdepth 3
echo
echo '=== ReattachFunc / attached runner ==='
grep -rn 'func ReattachFunc' "$D" || true
for f in $(grep -rl 'func ReattachFunc' "$D" 2>/dev/null); do
  echo "--- $f ---"
  sed -n '/func ReattachFunc/,/^}/p' "$f"
  echo '--- struct + Wait ---'
  sed -n '/^type attachedRunner/,/^}/p' "$f"
  sed -n '/func (r \*attachedRunner) Wait/,/^}/p' "$f"
  sed -n '/func (r \*attachedRunner) Kill/,/^}/p' "$f"
  sed -n '/func (r \*attachedRunner) Name/,/^}/p' "$f"
done
echo
echo '=== GRPCServiceName + consts ==='
grep -rn 'GRPCServiceName\s*=' "$D"/*.go
grep -rn 'EnvUnixSocketDir\|EnvUnixSocketGroup\|envMultiplexGRPC' "$D"/*.go | head
echo
echo '=== health check usage in client ==='
grep -rn 'Ping()\|GRPCServiceName' "$D"/*.go | head -20
