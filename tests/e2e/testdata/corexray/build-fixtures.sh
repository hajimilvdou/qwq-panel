#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
# 仅构建真实 Xray 安装夹具；签名材料必须显式给定，发布传输包只含公钥。
# =============================================================================
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$ROOT"
: "${QWQ_XRAY_SIGNING_KEY:?必须显式提供既有签名私钥}"
: "${QWQ_XRAY_TRUST_PUB:?必须显式提供匹配公开信任根}"
[[ $(uname -s) == Linux ]]
for asset in index.html manifest.json .csp THIRD_PARTY_LICENSES.txt; do
  [[ -f internal/webui/dist/$asset ]] || { printf '宿主嵌入 Web 产物缺少 %s；先运行 embed-web.sh。\n' "$asset" >&2; exit 2; }
done
OUT="$ROOT/.cache/core-xray/out"
mkdir -p "$OUT/bin" "$OUT/release"
source scripts/lib/ldflags.sh
HOST_LDFLAGS=$(qwq_ldflags e2e-xray)
export GOOS=linux GOARCH=amd64 CGO_ENABLED=0
for command in qwq qwq-privileged qwq-capability; do
  go build -trimpath -buildvcs=false -ldflags="$HOST_LDFLAGS" -o "$OUT/bin/$command" "./cmd/$command"
done
go test -c -trimpath -buildvcs=false -tags e2e -ldflags="$QWQ_BASE_LDFLAGS" -o "$OUT/e2e.test" ./tests/e2e
bash scripts/package.sh "$OUT/bin" e2e-xray "$OUT/release/qwq-e2e-xray-linux-amd64.tar.gz"
for version in 0.1.1 0.1.2; do
  go run plugins/builtin/core.xray/build.go -version "$version"
done
go run plugins/builtin/core.xray/build.go -version 0.1.3 -e2e-reject-core
(
  cd "$OUT"
  cp "$ROOT/tests/e2e/testdata/corexray/resources.py" resources.py
  sha256sum e2e.test key.pub release/qwq-e2e-xray-linux-amd64.tar.gz core.xray-0.1.{1,2,3}.qwq >SHA256SUMS
  sha256sum resources.py >>SHA256SUMS
  tar -czf xray-e2e-transfer.tar.gz e2e.test key.pub SHA256SUMS release resources.py core.xray-0.1.{1,2,3}.qwq
  sha256sum xray-e2e-transfer.tar.gz >xray-e2e-transfer.tar.gz.sha256
)
printf 'Xray 夹具已构建；传输包仅含测试二进制、宿主 release、公钥和三份签名包。\n'
