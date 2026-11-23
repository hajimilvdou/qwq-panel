#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Print go-plugin's attached-runner process handling (cmd_reattach.go,
# process_posix.go) used when a Client is configured with ReattachConfig.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off
D=${GOMODCACHE:-$(go env GOMODCACHE)}/github.com/hashicorp/go-plugin@v1.8.0
for f in internal/cmdrunner/cmd_reattach.go internal/cmdrunner/process_posix.go internal/runner/runner.go; do
  echo "=== $f ==="
  cat "$D/$f"
  echo
done
