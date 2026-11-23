#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Fetch the Go dependencies of the P2-T1 spike on the build machine and print the
# module cache location so the caller can inspect the go-plugin sources.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off
export GOFLAGS=-mod=mod
go get github.com/hashicorp/go-plugin@latest
go get google.golang.org/grpc@latest
go get golang.org/x/sys@latest
echo '--- go.mod ---'
cat go.mod
echo '--- go.sum lines ---'
wc -l <go.sum
echo '--- module cache ---'
go env GOMODCACHE
echo '--- versions ---'
go list -m github.com/hashicorp/go-plugin google.golang.org/grpc golang.org/x/sys github.com/hashicorp/go-hclog
