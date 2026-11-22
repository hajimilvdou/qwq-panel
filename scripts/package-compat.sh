#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
#  package-compat.sh —— 打包旧版 polkit 兼容补丁（qwq-compat-polkit）
#  用法：bash scripts/package-compat.sh <bin-path> <version> <out.tar.gz>
# =============================================================================
set -euo pipefail
umask 022

BIN=${1:?usage: package-compat.sh <qwq-compat-unitctl-bin> <version> <out.tar.gz>}
VERSION=${2:?usage: package-compat.sh <qwq-compat-unitctl-bin> <version> <out.tar.gz>}
OUT=${3:?usage: package-compat.sh <qwq-compat-unitctl-bin> <version> <out.tar.gz>}
[[ -f $BIN ]] || { echo "找不到二进制 $BIN" >&2; exit 2; }
[[ $VERSION =~ ^[0-9A-Za-z._+-]+$ ]] || { echo "非法版本号 $VERSION" >&2; exit 2; }
EPOCH=${SOURCE_DATE_EPOCH:-0}
[[ $EPOCH =~ ^[0-9]+$ ]] || { echo "非法 SOURCE_DATE_EPOCH $EPOCH" >&2; exit 2; }

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
chmod 0755 "$D"

install -d "$D/bin" "$D/share/systemd"
printf '%s\n' "$VERSION" >"$D/VERSION"
install -m0755 "$BIN" "$D/bin/qwq-compat-unitctl"
install -m0644 \
  "$ROOT/deployments/compat/polkit/qwq-compat-unitctl.socket" \
  "$ROOT/deployments/compat/polkit/qwq-compat-unitctl.service" \
  "$D/share/systemd/"
install -m0755 \
  "$ROOT/deployments/compat/polkit/install-compat.sh" \
  "$ROOT/deployments/compat/polkit/uninstall-compat.sh" \
  "$D/"
install -m0644 "$ROOT/LICENSE" "$ROOT/NOTICE" "$D/"

mkdir -p "$(dirname "$OUT")"
tar -C "$D" --format=gnu --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" --sort=name -cf - . | gzip -n -9 >"$OUT"
echo "packaged $OUT"
