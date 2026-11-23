#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Format the spike sources on the build machine and compile-check them. The
# formatted files are pulled back to Windows with `remote.sh pull`.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64
gofmt -w .
echo '--- tidy ---'
go mod tidy
echo '--- build ---'
go build ./... && echo 'build ok'
echo '--- vet ---'
go vet ./... && echo 'vet ok'
