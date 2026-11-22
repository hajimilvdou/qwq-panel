#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
#  release.sh —— 构建可复现的分层发布产物（DEP-03 + Track 10 按需选装架构）
# -----------------------------------------------------------------------------
#  用法：source scripts/dev-env.sh && bash scripts/release.sh vX.Y.Z <out-dir>
#
#  产出（<out-dir> 须不存在或为空，全部扁平输出以直接兼容 GitHub Releases）：
#    qwq-vX.Y.Z-linux-{amd64,arm64}.tar.gz        极简必装主包（原面板底座 + 必装 security.basic.qwqpkg）
#    install.sh                                   内嵌发布公钥与镜像地址的在线安装脚本
#    <id>-vX.Y.Z-linux-{amd64,arm64}.qwqpkg       10 款独立可选官方插件包（按需下载安装）
#    plugins-index.json                           官方可选插件元数据与依赖索引
#    sbom.cdx.json                                CycloneDX SBOM（cmd/qwq，linux/amd64）
#    SHA256SUMS                                   覆盖主包 + install.sh + *.qwqpkg + plugins-index.json + sbom
# =============================================================================
set -euo pipefail

V=${1:?usage: release.sh vX.Y.Z <out-dir>}
OUT=${2:?usage: release.sh vX.Y.Z <out-dir>}
[[ $V =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "版本号格式应为 vX.Y.Z[-pre]" >&2; exit 2; }
CLEAN_VER=${V#v}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
# shellcheck source=scripts/lib/ldflags.sh
source scripts/lib/ldflags.sh

for t in go git gzip tar sha256sum python3 cyclonedx-gomod go-licenses; do
  command -v "$t" >/dev/null || { echo "缺少 $t（运行 bash scripts/bootstrap-tools.sh）" >&2; exit 1; }
done
[[ -z $(git status --porcelain) ]] || { echo "工作区不干净，拒绝发布" >&2; git status --short >&2; exit 1; }
if [[ -e $OUT && -n $(ls -A "$OUT") ]]; then echo "$OUT 非空" >&2; exit 1; fi
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

# 确保发布二进制内嵌了 Web Shell 产物（internal/webui/dist 被 .gitignore 忽略，不会污染工作区）
if [[ ${QWQ_SKIP_WEBUI:-0} != 1 && ! -f "$ROOT/internal/webui/dist/index.html" ]]; then
  if [[ ! -f "$ROOT/web/dist/index.html" ]]; then
    command -v npm >/dev/null || { echo "缺少 Web Shell 产物 internal/webui/dist 且未找到 npm（先构建 web/ 或安装 Node.js）" >&2; exit 1; }
    (cd "$ROOT/web" && npm ci && npm run build)
  fi
  bash "$ROOT/scripts/embed-web.sh"
fi

SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH GOFLAGS="${GOFLAGS:-} -mod=readonly" GOWORK=off CGO_ENABLED=0 GOOS=linux
LDF=$(qwq_ldflags "$V")
PUBKEY=${QWQ_RELEASE_PUBKEY:-$ROOT/deployments/release.pub}
if [[ -f $PUBKEY ]]; then
  export QWQ_RELEASE_PUBKEY=$PUBKEY
else
  unset QWQ_RELEASE_PUBKEY
  echo "警告：没有发布公钥 $PUBKEY；包内 install.sh 只支持 --offline" >&2
fi

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

# 构建打包签名工具 qwqctl（本机 Linux 架构执行）
HOST_GOARCH=$(go env GOHOSTARCH)
GOARCH=$HOST_GOARCH go build -trimpath -ldflags "$LDF" -o "$W/qwqctl" ./cmd/qwqctl

# 插件签名密钥：优先使用注入的 QWQ_PLUGIN_SIGNING_KEY + QWQ_PLUGIN_TRUST_PUB（默认 deployments/plugin-trust.pub），
# 缺省时仅限本地试构建生成临时密钥对（跨次构建不可复现）。
PLUGIN_TRUST_PUB=${QWQ_PLUGIN_TRUST_PUB:-$ROOT/deployments/plugin-trust.pub}
if [[ -n ${QWQ_PLUGIN_SIGNING_KEY:-} && -f $PLUGIN_TRUST_PUB ]]; then
  PLUGIN_PRIV=$QWQ_PLUGIN_SIGNING_KEY
  PLUGIN_PUB=$PLUGIN_TRUST_PUB
  PLUGIN_KEY_ID=$(python3 - "$PLUGIN_PUB" <<'PY'
import base64, hashlib, pathlib, sys
lines = [ln.strip() for ln in pathlib.Path(sys.argv[1]).read_text().splitlines() if ln and not ln.startswith("-----")]
der = base64.b64decode("".join(lines))
raw32 = der[-32:]
print("ed25519:" + hashlib.sha256(raw32).hexdigest())
PY
)
else
  echo "警告：未提供 QWQ_PLUGIN_SIGNING_KEY / $PLUGIN_TRUST_PUB，将生成临时插件签名密钥（仅适用于本地试构建）" >&2
  "$W/qwqctl" keygen -out "$W/qwq-builtin" >"$W/keygen.txt"
  PLUGIN_PRIV="$W/qwq-builtin.key"
  PLUGIN_PUB="$W/qwq-builtin.pub"
  PLUGIN_KEY_ID=$(sed -n 's/^key_id: *//p' "$W/keygen.txt")
fi
export QWQ_TRUST_PUBKEYS="$PLUGIN_PUB"

# ── 第三方许可证 ─────────────────────────────────────────────────────────────
GOARCH=amd64 go-licenses save ./cmd/qwq ./cmd/qwq-privileged ./cmd/qwq-capability ./cmd/qwqctl \
  --ignore github.com/qwq-panel/qwq --save_path "$W/THIRD_PARTY_LICENSES"
export QWQ_THIRD_PARTY_DIR=$W/THIRD_PARTY_LICENSES

# 打包单个官方插件：pack_official_plugin <src_dir> <arch> <out_qwqpkg>
pack_official_plugin() {
  local src_dir=$1 arch=$2 out_pkg=$3
  local stage="$W/pkgstage-$arch-$(basename "$src_dir")"
  rm -rf "$stage"
  mkdir -p "$stage/bin"
  GOARCH=$arch go build -trimpath -ldflags "$QWQ_BASE_LDFLAGS" -o "$stage/bin/plugin" "./$src_dir"
  chmod 0755 "$stage/bin/plugin"
  for sub in schemas ui attestations LICENSES; do
    if [[ -d "$src_dir/$sub" ]]; then
      cp -R "$src_dir/$sub" "$stage/"
    fi
  done
  python3 - "$src_dir/manifest.json" "$stage/manifest.json" "$CLEAN_VER" "$arch" "$PLUGIN_KEY_ID" <<'PY'
import json, pathlib, sys
src, dst, ver, arch, key_id = sys.argv[1:6]
m = json.loads(pathlib.Path(src).read_text(encoding="utf-8"))
m["version"] = ver
m["target"] = f"linux/{arch}"
m["publisher"]["key_id"] = key_id
pathlib.Path(dst).write_text(json.dumps(m, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
  "$W/qwqctl" pack -src "$stage" -out "$out_pkg" -key "$PLUGIN_PRIV" >/dev/null
  "$W/qwqctl" verify -trust "$PLUGIN_PUB" "$out_pkg" >/dev/null
}

# 10 款独立可选插件（源码目录 -> 插件 ID）
OPTIONAL_SPECS=(
  "plugins/builtin/monitor:monitor.basic"
  "plugins/builtin/server.probe:server.probe"
  "plugins/builtin/domain.dns:domain.dns"
  "plugins/builtin/tls.certificates:tls.certificates"
  "plugins/builtin/core.xray:core.xray"
  "plugins/builtin/proxy.advanced:proxy.advanced"
  "plugins/builtin/ai.relay:ai.relay"
  "plugins/builtin/web.ingress:web.ingress"
  "plugins/builtin/containers.docker:containers.docker"
  "plugins/builtin/notify.hub:notify.hub"
)

# ── 交叉编译并分层打包 ───────────────────────────────────────────────────────
for arch in amd64 arm64; do
  bin=$W/$arch
  mkdir -p "$bin"
  for c in qwq qwqctl qwq-privileged qwq-capability; do
    GOARCH=$arch go build -trimpath -ldflags "$LDF" -o "$bin/$c" "./cmd/$c"
  done

  # 1. 构建默认必装的基础安全插件 security.basic，内嵌进极简主发布包
  sec_pkg="$W/security.basic-$V-linux-$arch.qwqpkg"
  pack_official_plugin "plugins/builtin/security.basic" "$arch" "$sec_pkg"
  QWQ_BOOTSTRAP_PLUGIN="$sec_pkg" bash scripts/package.sh "$bin" "$V" "$OUT/qwq-$V-linux-$arch.tar.gz" >/dev/null

  # 2. 构建其余 10 款可选插件为包外独立 .qwqpkg 产物（扁平输出，直接作为 GitHub Release 附件）
  for spec in "${OPTIONAL_SPECS[@]}"; do
    src_dir=${spec%%:*}
    pid=${spec##*:}
    if [[ -d $src_dir ]]; then
      pack_official_plugin "$src_dir" "$arch" "$OUT/${pid}-${V}-linux-${arch}.qwqpkg"
    fi
  done
done

# 导出与主包完全一致的独立在线安装脚本 install.sh（已内嵌发布公钥与默认镜像地址）
tar -xOzf "$OUT/qwq-$V-linux-amd64.tar.gz" ./install.sh >"$OUT/install.sh"
chmod 0755 "$OUT/install.sh"

# ── 生成官方可选插件目录索引 plugins-index.json ──────────────────────────────
python3 - "$OUT" "$V" "$CLEAN_VER" <<'PY'
import hashlib, json, pathlib, sys
out_dir = pathlib.Path(sys.argv[1])
tag_ver, clean_ver = sys.argv[2], sys.argv[3]
specs = [
    ("plugins/builtin/monitor", "monitor.basic"),
    ("plugins/builtin/server.probe", "server.probe"),
    ("plugins/builtin/domain.dns", "domain.dns"),
    ("plugins/builtin/tls.certificates", "tls.certificates"),
    ("plugins/builtin/core.xray", "core.xray"),
    ("plugins/builtin/proxy.advanced", "proxy.advanced"),
    ("plugins/builtin/ai.relay", "ai.relay"),
    ("plugins/builtin/web.ingress", "web.ingress"),
    ("plugins/builtin/containers.docker", "containers.docker"),
    ("plugins/builtin/notify.hub", "notify.hub"),
]
entries = []
for src_dir, pid in specs:
    mpath = pathlib.Path(src_dir) / "manifest.json"
    if not mpath.exists():
        continue
    m = json.loads(mpath.read_text(encoding="utf-8"))
    packages = {}
    for arch in ("amd64", "arm64"):
        pkg = out_dir / f"{pid}-{tag_ver}-linux-{arch}.qwqpkg"
        if pkg.exists():
            digest = hashlib.sha256(pkg.read_bytes()).hexdigest()
            packages[f"linux/{arch}"] = {
                "file": pkg.name,
                "size": pkg.stat().st_size,
                "sha256": f"sha256:{digest}",
            }
    entries.append({
        "id": pid,
        "version": clean_ver,
        "name": m.get("name", pid),
        "summary": m.get("summary", ""),
        "dependencies": [d["id"] if isinstance(d, dict) else d for d in m.get("dependencies", [])],
        "memory_max_mb": m.get("resources", {}).get("memory_max_mb", 0),
        "packages": packages,
    })
index_doc = {
    "schema_version": "1.0",
    "release": tag_ver,
    "mandatory_base": ["security.basic"],
    "optional_plugins": entries,
}
(out_dir / "plugins-index.json").write_text(json.dumps(index_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

# ── SBOM ─────────────────────────────────────────────────────────────────────
GOARCH=amd64 cyclonedx-gomod app -json -noserial -notimestamp -std -licenses -main cmd/qwq -output "$OUT/sbom.cdx.json" .

(
  cd "$OUT"
  LC_ALL=C
  files=(qwq-"$V"-linux-*.tar.gz install.sh sbom.cdx.json plugins-index.json)
  shopt -s nullglob
  for p in *.qwqpkg; do files+=("$p"); done
  sha256sum -- "${files[@]}" >SHA256SUMS
)
cat "$OUT/SHA256SUMS"
