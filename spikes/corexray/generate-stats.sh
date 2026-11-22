#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
# 最小 wire 定义独立生成，不进入冻结的 Platform ABI 工作区。
# =============================================================================
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WIRE="$ROOT/plugins/builtin/core.xray/internal/xrayapi/wire"
CHECK=0
if [[ ${1:-} == --check ]]; then CHECK=1; fi
cd "$WIRE"
DEST="$WIRE"
TEMP=''
trap 'if [[ -n $TEMP ]]; then rm -rf "$TEMP"; fi' EXIT
if ((CHECK)); then
  TEMP=$(mktemp -d)
  DEST="$TEMP"
else
  buf format -w stats.proto
fi
buf generate --template "$ROOT/spikes/corexray/buf.gen.yaml" -o "$DEST"
python3 - "$DEST" <<'PY'
import pathlib,sys
root=pathlib.Path(sys.argv[1])
for name in ('stats.pb.go','stats_grpc.pb.go'):
    path=root/name
    text=path.read_text()
    path.write_text('// SPDX-License-Identifier: MPL-2.0\n\n'+text)
PY
gofmt -w "$DEST/stats.pb.go" "$DEST/stats_grpc.pb.go"
if ((CHECK)); then
  for name in stats.pb.go stats_grpc.pb.go; do
    cmp -s "$DEST/$name" "$WIRE/$name" || { printf 'StatsService 生成代码发生漂移。\n' >&2; exit 1; }
  done
fi
