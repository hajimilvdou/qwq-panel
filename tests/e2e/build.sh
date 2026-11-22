#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Build the Linux fixtures of tests/e2e on a build machine, so the disposable
# test host needs no Go toolchain. The output directory contains:
#
#   bin/qwq, bin/qwq-privileged   host binaries for the target arch
#   e2e.test                      the cross-compiled end-to-end test binary
#   release/qwq-e2e-linux-<arch>.tar.gz  release-layout tarball (scripts/package.sh);
#                                 every test installs the host with its install.sh
#   packages/noop-0.1.1.qwq       signed plugin packages
#   packages/noop-0.1.2.qwq
#   packages/noop-0.1.3.qwq       built to fail Initialize (failed-update test)
#   key.key, key.pub              the throwaway publisher key pair
#   SHA256SUMS                    digests of the transferable files
#
# Usage: [GOARCH=arm64] bash tests/e2e/build.sh <out-dir>   (default: the build host's arch)
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT=${1:?usage: tests/e2e/build.sh <out-dir>}
rm -rf "$OUT"
mkdir -p "$OUT/bin" "$OUT/packages" "$OUT/tools"
cd "$ROOT"

# Host binaries get the same link flags as a release (scripts/lib/ldflags.sh),
# with the version "e2e"; the plugin and the test binary only strip symbols.
source scripts/lib/ldflags.sh
HOST_LDFLAGS=$(qwq_ldflags e2e)
LDFLAGS=$QWQ_BASE_LDFLAGS
# qwqctl packs the fixtures on this machine, so it is built for the host.
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="$HOST_LDFLAGS" -o "$OUT/tools/qwqctl" ./cmd/qwqctl

export GOOS=linux GOARCH=${GOARCH:-$(go env GOARCH)} CGO_ENABLED=0
go build -trimpath -buildvcs=false -ldflags="$HOST_LDFLAGS" -o "$OUT/bin/qwq" ./cmd/qwq
go build -trimpath -buildvcs=false -ldflags="$HOST_LDFLAGS" -o "$OUT/bin/qwq-privileged" ./cmd/qwq-privileged
go build -trimpath -buildvcs=false -ldflags="$HOST_LDFLAGS" -o "$OUT/bin/qwq-capability" ./cmd/qwq-capability
go test -c -tags e2e -ldflags="$LDFLAGS" -o "$OUT/e2e.test" ./tests/e2e

RELEASE_TAR=release/qwq-e2e-linux-$GOARCH.tar.gz
bash scripts/package.sh "$OUT/bin" e2e "$OUT/$RELEASE_TAR"

"$OUT/tools/qwqctl" keygen -out "$OUT/key" >"$OUT/keygen.txt"
KEY_ID=$(sed -n 's/^key_id: *//p' "$OUT/keygen.txt")
test -n "$KEY_ID"

for version in 0.1.1 0.1.2 0.1.3; do
  extra=""
  if [[ $version == 0.1.3 ]]; then extra="-X main.failInitialize=1"; fi
  go build -trimpath -buildvcs=false \
    -ldflags="$LDFLAGS -X main.buildVersion=$version $extra" \
    -o "$OUT/noop-plugin-$version" ./plugins/builtin/noop
  rm -rf "$OUT/pkgroot"
  mkdir -p "$OUT/pkgroot/bin"
  cp "$OUT/noop-plugin-$version" "$OUT/pkgroot/bin/plugin"
  chmod 0755 "$OUT/pkgroot/bin/plugin"
  cp -R plugins/builtin/noop/schemas plugins/builtin/noop/attestations "$OUT/pkgroot/"
  # The manifest is a checked-in file with placeholder identity values; the
  # package needs its real version and the throwaway publisher key. sed keeps
  # every other field (including the non-ASCII name and descriptions) intact.
  sed -e 's/"version": "0.1.0"/"version": "'"$version"'"/' \
    -e 's|"key_id": "ed25519:0*"|"key_id": "'"$KEY_ID"'"|' \
    plugins/builtin/noop/manifest.json >"$OUT/pkgroot/manifest.json"
  grep -q "\"version\": \"$version\"" "$OUT/pkgroot/manifest.json"
  grep -q "$KEY_ID" "$OUT/pkgroot/manifest.json"
  "$OUT/tools/qwqctl" pack -src "$OUT/pkgroot" -out "$OUT/packages/noop-$version.qwq" -key "$OUT/key.key"
  "$OUT/tools/qwqctl" verify -trust "$OUT/key.pub" "$OUT/packages/noop-$version.qwq" >/dev/null
done
rm -rf "$OUT/pkgroot"

# 监控复用相同发布者与打包脚本，实际安装测试不需要额外信任根。
QWQ_MONITOR_OUT="$OUT/monitor" QWQ_MONITOR_PUBLISHER_PREFIX="$OUT/key" \
  QWQ_MONITOR_KEY_ID="$KEY_ID" QWQ_MONITOR_QWQCTL="$OUT/tools/qwqctl" \
  bash tests/monitor/build.sh

(
  cd "$OUT"
  sha256sum bin/qwq bin/qwq-privileged bin/qwq-capability e2e.test key.pub "$RELEASE_TAR" packages/noop-0.1.{1,2,3}.qwq monitor/monitor.basic-0.1.0.qwq
) >"$OUT/SHA256SUMS"

echo "e2e fixtures ready in $OUT"
