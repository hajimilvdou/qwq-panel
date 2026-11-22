#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# 把已通过 postbuild 的前端产物放入 Go 嵌入目录；只在 Linux 构建机执行。
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo '请在 Linux 构建机执行 embed-web.sh' >&2; exit 2; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE=${1:-$ROOT/web/dist}
DEST=$ROOT/internal/webui/dist
for name in index.html manifest.json .csp THIRD_PARTY_LICENSES.txt; do
  [[ -f $SOURCE/$name ]] || { echo "前端构建产物不完整：$name" >&2; exit 2; }
done
[[ ! -L $DEST && $DEST == "$ROOT/internal/webui/dist" ]] || exit 2
mkdir -p "$DEST"
find "$DEST" -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf -- {} +
cp -R "$SOURCE"/. "$DEST"/
echo 'Web Shell 已接入宿主嵌入目录'
