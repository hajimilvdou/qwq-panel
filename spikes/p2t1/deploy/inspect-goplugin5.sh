#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Print go-plugin's pidWait helper and the runner package interfaces.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off
D=${GOMODCACHE:-$(go env GOMODCACHE)}/github.com/hashicorp/go-plugin@v1.8.0
echo "=== pidWait ==="
grep -rn 'func pidWait' "$D" || true
for f in $(grep -rl 'func pidWait' "$D" 2>/dev/null); do
  sed -n '/func pidWait/,/^}/p' "$f"
done
echo
echo '=== runner package ==='
ls "$D/runner"
sed -n '1,80p' "$D/runner/runner.go"
