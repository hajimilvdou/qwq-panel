#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
# 构建带显式 tag 的原生 spike；只编译，不在构建机启动 Xray 监听。
# =============================================================================
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
source scripts/lib/ldflags.sh
OUT=.cache/core-xray/spike/bundle
XRAY=.cache/core-xray/v26.11.9/unpacked/xray
EXPECTED=e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d
[[ -f $XRAY && ! -L $XRAY ]]
[[ $(sha256sum "$XRAY" | cut -d ' ' -f1) == "$EXPECTED" ]]
[[ ! -L $OUT && ! -L $OUT/bin ]]
mkdir -p "$OUT/bin"
chmod u+w "$OUT" "$OUT/bin"
CGO_ENABLED=0 go test -c -trimpath -buildvcs=false -tags x6spike -ldflags="$QWQ_BASE_LDFLAGS" \
  -o "$OUT/bin/plugin" ./internal/xraycore/xraybin
cp "$XRAY" "$OUT/bin/xray"
python3 - "$OUT" <<'PY'
import hashlib,json,pathlib,sys
out=pathlib.Path(sys.argv[1])
source=pathlib.Path('plugins/builtin/core.xray/manifest.json')
manifest=json.loads(source.read_text())
for name in ('bin/plugin','bin/xray'):
    manifest['files'][name]='sha256:'+hashlib.sha256((out/name).read_bytes()).hexdigest()
(out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
PY
chmod 0444 "$OUT/manifest.json"
chmod 0555 "$OUT/bin/plugin" "$OUT/bin/xray" "$OUT/bin" "$OUT"
tar -czf .cache/core-xray/spike/x6-spike.tar.gz -C .cache/core-xray/spike bundle
sha256sum .cache/core-xray/spike/x6-spike.tar.gz
