#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
#  package.sh —— 把已编译的宿主二进制按发布包布局打成 tar.gz
# -----------------------------------------------------------------------------
#  用法：bash scripts/package.sh <bin-dir> <version> <out.tar.gz>
#    <bin-dir> 内须有 qwq、qwq-privileged 与 qwq-capability，qwqctl 可选。
#  可选环境变量（release.sh 设置）：
#    QWQ_RELEASE_PUBKEY   发布公钥 PEM，写入包内 install.sh 的 RELEASE_PUBKEY_PEM
#    QWQ_RELEASE_MIRROR   发布下载镜像基址，写入包内 install.sh 的 DEFAULT_MIRROR
#    QWQ_THIRD_PARTY_DIR  go-licenses 产出的目录，放进包内 THIRD_PARTY_LICENSES/
#    SOURCE_DATE_EPOCH    归档内文件的 mtime（缺省 0）
#  布局即 scripts/install.sh 头部注释描述的契约；release.sh（DEP-03）与
#  tests/e2e/build.sh 都调用本脚本，避免两份布局各自漂移。
# =============================================================================
set -euo pipefail
umask 022 # 归档内权限不随调用者的 umask 变化

BIN=${1:?usage: package.sh <bin-dir> <version> <out.tar.gz>}
VERSION=${2:?usage: package.sh <bin-dir> <version> <out.tar.gz>}
OUT=${3:?usage: package.sh <bin-dir> <version> <out.tar.gz>}
[[ $VERSION =~ ^[0-9A-Za-z._+-]+$ ]] || { echo "非法版本号 $VERSION" >&2; exit 2; }
EPOCH=${SOURCE_DATE_EPOCH:-0}
[[ $EPOCH =~ ^[0-9]+$ ]] || { echo "非法 SOURCE_DATE_EPOCH $EPOCH" >&2; exit 2; }

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
chmod 0755 "$D"

install -d "$D/bin" "$D/share/systemd" "$D/share/tmpfiles" "$D/share/sysusers" \
  "$D/share/polkit" "$D/share/config" "$D/share/trust"
printf '%s\n' "$VERSION" >"$D/VERSION"
install -m0755 "$BIN/qwq" "$BIN/qwq-privileged" "$BIN/qwq-capability" "$D/bin/"
if [[ -f $BIN/qwqctl ]]; then install -m0755 "$BIN/qwqctl" "$D/bin/"; fi
install -m0644 "$ROOT"/deployments/systemd/* "$D/share/systemd/"
install -m0644 "$ROOT/deployments/tmpfiles/qwq.conf" "$D/share/tmpfiles/"
install -m0644 "$ROOT/deployments/sysusers/qwq.conf" "$D/share/sysusers/"
install -m0644 "$ROOT/deployments/polkit/qwq-plugin.rules" "$D/share/polkit/"
install -m0644 "$ROOT"/deployments/config/qwq.json.example* "$D/share/config/"
install -m0755 "$ROOT/scripts/install.sh" "$ROOT/scripts/uninstall.sh" "$D/"
# 宿主是 AGPL-3.0-only；二进制里链接的 sdk/ 是 Apache-2.0，须随附其许可证。
install -m0644 "$ROOT/LICENSE" "$ROOT/NOTICE" "$D/"
install -m0644 "$ROOT/sdk/LICENSE" "$D/LICENSE.Apache-2.0"

if [[ -n ${QWQ_RELEASE_PUBKEY:-} ]]; then
  pem=$(cat "$QWQ_RELEASE_PUBKEY")
  # 嵌入单引号字符串：PEM 只含 base64 字符、横线与空格，先确认再写。
  [[ $pem == "-----BEGIN PUBLIC KEY-----"*"-----END PUBLIC KEY-----" ]] &&
    ! printf '%s\n' "$pem" | grep -qv '^[A-Za-z0-9+/= -]*$' ||
    { echo "$QWQ_RELEASE_PUBKEY 不是 PEM 公钥" >&2; exit 2; }
  PEM=$pem awk -v q="'" '
    $0 == "RELEASE_PUBKEY_PEM=" q q { print "RELEASE_PUBKEY_PEM=" q ENVIRON["PEM"] q; n++; next }
    { print }
    END { exit n != 1 }' "$D/install.sh" >"$D/install.sh.tmp" ||
    { echo "install.sh 中找不到 RELEASE_PUBKEY_PEM=''" >&2; exit 1; }
  mv "$D/install.sh.tmp" "$D/install.sh"
  chmod 0755 "$D/install.sh"
fi
if [[ -n ${QWQ_RELEASE_MIRROR:-} ]]; then
  mirror=${QWQ_RELEASE_MIRROR%/}
  mirror_re='^https://[A-Za-z0-9._~:/?#@!+,;=-]+$'
  [[ $mirror =~ $mirror_re ]] ||
    { echo "QWQ_RELEASE_MIRROR 非法：$QWQ_RELEASE_MIRROR" >&2; exit 2; }
  MIRROR=$mirror awk '
    /^DEFAULT_MIRROR=/ { print "DEFAULT_MIRROR=" ENVIRON["MIRROR"]; n++; next }
    { print }
    END { exit n != 1 }' "$D/install.sh" >"$D/install.sh.tmp" ||
    { echo "install.sh 中找不到 DEFAULT_MIRROR=" >&2; exit 1; }
  mv "$D/install.sh.tmp" "$D/install.sh"
  chmod 0755 "$D/install.sh"
fi
if [[ -n ${QWQ_THIRD_PARTY_DIR:-} ]]; then
  cp -R "$QWQ_THIRD_PARTY_DIR" "$D/THIRD_PARTY_LICENSES"
  chmod -R u=rwX,go=rX "$D/THIRD_PARTY_LICENSES" # 模块缓存里的文件是只读的
fi
if [[ -n ${QWQ_TRUST_PUBKEYS:-} ]]; then
  for pub in $QWQ_TRUST_PUBKEYS; do
    [[ -f $pub ]] || { echo "找不到信任公钥 $pub" >&2; exit 1; }
    base=$(basename "$pub")
    [[ $base == *.pem ]] || base="${base%.pub}.pem"
    install -m0644 "$pub" "$D/share/trust/$base"
  done
fi
if [[ -n ${QWQ_BOOTSTRAP_PLUGIN:-} ]]; then
  [[ -f $QWQ_BOOTSTRAP_PLUGIN ]] || { echo "找不到必装安全插件包 $QWQ_BOOTSTRAP_PLUGIN" >&2; exit 1; }
  install -d "$D/share/bootstrap-plugins"
  install -m0644 "$QWQ_BOOTSTRAP_PLUGIN" "$D/share/bootstrap-plugins/security.basic.qwqpkg"
fi

# 归档内容可复现：固定格式、属主、时间与顺序；gzip -n 不写文件名与时间戳。
mkdir -p "$(dirname "$OUT")"
tar -C "$D" --format=gnu --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" --sort=name -cf - . | gzip -n -9 >"$OUT"
echo "packaged $OUT"
