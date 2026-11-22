#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# 只在构建机项目目录构建签名监控包；不安装系统服务、不改测试机。
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
source scripts/lib/ldflags.sh
OUT=${QWQ_MONITOR_OUT:-.cache/monitor-acceptance}
PUBLISHER=${QWQ_MONITOR_PUBLISHER_PREFIX:-$OUT/publisher}
PACKER=${QWQ_MONITOR_QWQCTL:-$OUT/bin/qwqctl}
mkdir -p "$OUT/bin" "$OUT/package/bin"
if [[ -z ${QWQ_MONITOR_QWQCTL:-} ]]; then CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$PACKER" ./cmd/qwqctl; fi
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="$QWQ_BASE_LDFLAGS" -o "$OUT/package/bin/plugin" ./plugins/builtin/monitor
cp -R plugins/builtin/monitor/schemas plugins/builtin/monitor/ui plugins/builtin/monitor/attestations "$OUT/package/"
if [[ ! -f $PUBLISHER.key ]]; then "$PACKER" keygen -out "$PUBLISHER" >"$OUT/publisher-info.txt"; fi
KEY_ID=${QWQ_MONITOR_KEY_ID:-$(sed -n 's/^key_id: *//p' "$OUT/publisher-info.txt")}
[[ -n $KEY_ID ]]
python3 - "$OUT/package" "$KEY_ID" <<'PY'
import pathlib,json,sys
source=pathlib.Path('plugins/builtin/monitor/manifest.json')
manifest=json.loads(source.read_text())
manifest['publisher']['key_id']=sys.argv[2]
(pathlib.Path(sys.argv[1])/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
PY
"$PACKER" pack -src "$OUT/package" -out "$OUT/monitor.basic-0.1.0.qwq" -key "$PUBLISHER.key"
"$PACKER" verify -trust "$PUBLISHER.pub" "$OUT/monitor.basic-0.1.0.qwq"
sha256sum "$OUT/monitor.basic-0.1.0.qwq" >"$OUT/SHA256SUMS"
printf '监控插件已构建并验签；系统安装与真机采样尚未执行。\n'
