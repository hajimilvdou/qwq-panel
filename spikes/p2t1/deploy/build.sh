#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Build the P2-T1 spike binaries on the build machine and place them in
# .cache/p2t1/bin so `remote.sh pull .cache/p2t1/bin` can fetch them.
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT/spikes/p2t1"
export GOWORK=off
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

go mod tidy
echo '--- gofmt ---'
unformatted=$(gofmt -l .)
if [[ -n $unformatted ]]; then
  echo "gofmt needed:" >&2
  echo "$unformatted" >&2
  exit 1
fi
echo 'clean'
echo '--- go vet ---'
go vet ./...
echo 'vet ok'

OUT="$ROOT/.cache/p2t1/bin"
rm -rf "$OUT"
mkdir -p "$OUT"
go build -trimpath -ldflags='-s -w' -o "$OUT/spike-agent" ./cmd/agent
go build -trimpath -ldflags='-s -w' -o "$OUT/spike-plugin" ./cmd/plugin
echo '--- binaries ---'
ls -l "$OUT"
file "$OUT"/* 2>/dev/null || true

echo '--- module list ---'
go list -m all | sed -n '1,40p'
echo '--- licenses ---'
M=${GOMODCACHE:-$(go env GOMODCACHE)}
for mod in github.com/hashicorp/go-plugin@v1.8.0 google.golang.org/grpc@v1.85.0 \
  golang.org/x/sys@v0.49.0 github.com/hashicorp/go-hclog@v1.6.3 \
  google.golang.org/protobuf@v1.36.12; do
  if [[ -d $M/$mod ]]; then
    printf '%s: ' "$mod"
    head -3 "$M/$mod/LICENSE" 2>/dev/null | tr '\n' ' ' | cut -c1-120
    echo
  fi
done
