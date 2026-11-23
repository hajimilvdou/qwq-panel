#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
#  install.sh —— 安装或升级 qwq（随发布包分发，可重复幂等执行）
# -----------------------------------------------------------------------------
#  用法：
#    sudo bash install.sh --offline qwq-vX.Y.Z-linux-amd64.tar.gz [--minimal | --plugins <csv|all> --plugin-dir <dir>] [--port N] [--entry-path PATH]
#    sudo bash install.sh --version vX.Y.Z [--mirror URL] [--minimal | --plugins <csv|all>] [--port N] [--entry-path PATH]
#
#  默认必装范围（Track 10 架构）：
#    初始强制必装且仅必装：原面板底座（qwq / qwq-privileged / qwq-capability）+ 基础安全插件（security.basic）。
#    其余 10 款官方插件（monitor.basic / server.probe / domain.dns / tls.certificates / core.xray /
#    proxy.advanced / ai.relay / web.ingress / containers.docker / notify.hub）全部为独立可选 .qwqpkg 包：
#    交互终端下可勾选安装（直接回车仅装必装底座），非交互可用 --plugins 按需选装。
#
#  与宿主共存（宝塔等）：不碰 nginx、ufw、firewalld；默认配置只监听 127.0.0.1。
#  第二次执行同一版本不会改变任何东西，也不会重启服务。
#  退出码：0 成功 / 1 失败 / 2 用法错误
# =============================================================================
set -euo pipefail

# 发布公钥（PEM，Ed25519）由 release.sh 在打包时写入；为空时只允许 --offline。
RELEASE_PUBKEY_PEM=''
DEFAULT_MIRROR=https://github.com/qwq-panel/qwq/releases/download

PREFIX=/opt/qwq
UNIT_DIR=/etc/systemd/system
ETC=/etc/qwq

readonly OPTIONAL_PLUGIN_IDS=(
  "monitor.basic"
  "server.probe"
  "domain.dns"
  "tls.certificates"
  "core.xray"
  "proxy.advanced"
  "ai.relay"
  "web.ingress"
  "containers.docker"
  "notify.hub"
)

declare -A PLUGIN_SUMMARY=(
  ["monitor.basic"]="基础监控（CPU / 内存 / 磁盘 / 网络实时趋势微件，~18 MiB）"
  ["server.probe"]="服务器探针中心（多机单向安全探针 / 90天SLA / 三网拨测 / 前后台切换，~32 MiB）"
  ["domain.dns"]="域名与 DNS 管理（Cloudflare / 阿里云解析管理，按需唤醒）"
  ["tls.certificates"]="TLS 证书与 ACME DNS-01 自动签发续期（按需唤醒）"
  ["core.xray"]="Xray 三协议核心驱动（VLESS+REALITY / Hysteria2 / SS2022）"
  ["proxy.advanced"]="高级代理多用户配额、HTB 限速与订阅中心（自动连带安装 core.xray）"
  ["ai.relay"]="AI API 聚合中转、四协议互转与团体自服务分发门户"
  ["web.ingress"]="轻量反向代理与站点托管（零依赖内置 Go 反代 / Caddy & Nginx 渲染 / 快照回滚，按需唤醒）"
  ["containers.docker"]="轻量容器与 Compose 管理（直连 Unix Socket / 动态限额 / 有界日志 / 安全扫描，按需唤醒）"
  ["notify.hub"]="统一告警与通知中枢（Telegram / 飞书 / 钉钉 / 企微 / Discord / SMTP / 签名 Webhook，按需唤醒）"
)

die() { echo "install.sh: $*" >&2; exit 1; }
log() { echo "==> $*"; }
usage() { sed -n '5,8p' "$0" | sed 's/^#  //' >&2; exit 2; }

# ── 参数 ─────────────────────────────────────────────────────────────────────
offline='' version='' mirror=$DEFAULT_MIRROR
mode_minimal=0 csv_plugins='' offline_plugin_dir=''
compat_patch_file='' no_compat_patch=0
custom_port='' custom_entry_path='' has_custom_entry_path=0
while (($#)); do
  case $1 in
    --offline)         offline=${2:?}; shift 2 ;;
    --version)         version=${2:?}; shift 2 ;;
    --mirror)          mirror=${2:?}; shift 2 ;;
    --minimal)         mode_minimal=1; shift ;;
    --plugins)         csv_plugins=${2:?}; shift 2 ;;
    --plugin-dir)      offline_plugin_dir=${2:?}; shift 2 ;;
    --compat-patch)    compat_patch_file=${2:?}; shift 2 ;;
    --no-compat-patch) no_compat_patch=1; shift ;;
    --port)            custom_port=${2:?}; shift 2 ;;
    --entry-path)      custom_entry_path=${2:?}; has_custom_entry_path=1; shift 2 ;;
    -h|--help)         usage ;;
    *) echo "未知参数：$1" >&2; usage ;;
  esac
done
[[ -n $offline || -n $version ]] || usage
[[ -n $offline && -n $version ]] && { echo "--offline 与 --version 只能二选一" >&2; usage; }
((mode_minimal)) && [[ -n $csv_plugins ]] && { echo "--minimal 与 --plugins 不能同时指定" >&2; usage; }
if [[ -n $custom_port ]]; then
  [[ $custom_port =~ ^[0-9]+$ ]] && ((custom_port >= 1 && custom_port <= 65535)) || die "--port 必须是 1~65535 之间的整数"
fi
if ((has_custom_entry_path)); then
  custom_entry_path=${custom_entry_path#/}
  custom_entry_path=${custom_entry_path%/}
  if [[ $custom_entry_path == "none" ]]; then
    custom_entry_path=""
  elif [[ -n $custom_entry_path && ! $custom_entry_path =~ ^[A-Za-z0-9_-]{4,48}$ ]]; then
    die "--entry-path 必须为 4~48 位字母、数字、下划线或连字符（或传 none 关闭）"
  fi
fi

# ── 平台 ─────────────────────────────────────────────────────────────────────
[[ $EUID == 0 ]] || die "需要 root（sudo bash install.sh …）"
case $(uname -m) in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "不支持的架构 $(uname -m)" ;;
esac
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || die "需要以 systemd 启动的系统"
for c in tar sha256sum systemd-sysusers systemd-tmpfiles install; do
  command -v "$c" >/dev/null || die "缺少命令 $c"
done

if [[ -e /var/lib/qwq/plugin-data || -L /var/lib/qwq/plugin-data ]]; then
  die "发现旧插件数据树 /var/lib/qwq/plugin-data；请先按 docs/operations/plugin-data-layout.md 停服迁移，旧数据未修改"
fi

# ── 解析可选插件选择与拓扑依赖排序 ───────────────────────────────────────────
SELECTED_PLUGINS=()
select_optional_plugins() {
  if ((mode_minimal)); then
    return 0
  fi
  if [[ -n $csv_plugins ]]; then
    if [[ $csv_plugins == "none" ]]; then
      return 0
    elif [[ $csv_plugins == "all" ]]; then
      SELECTED_PLUGINS=("${OPTIONAL_PLUGIN_IDS[@]}")
    else
      IFS=',' read -r -a raw_items <<<"$csv_plugins"
      local item
      for item in "${raw_items[@]}"; do
        item=${item//[[:space:]]/}
        [[ -z $item || $item == "security.basic" ]] && continue
        [[ -n ${PLUGIN_SUMMARY[$item]+x} ]] || die "未知的官方可选插件 ID：$item"
        SELECTED_PLUGINS+=("$item")
      done
    fi
  elif [[ -t 0 && -t 1 && ( -n $version || -n $offline_plugin_dir ) ]]; then
    echo ""
    echo "==> 默认必装组件（已锁定）："
    echo "    [*] qwq 原面板底座 + security.basic（基础安全防护：防火墙 / 防失联改 SSH / 公钥 / 防爆破）"
    echo ""
    echo "==> 可选安装的官方插件（按需选择，安装后也可随时在面板内一键补装或卸载）："
    local idx pid
    for idx in "${!OPTIONAL_PLUGIN_IDS[@]}"; do
      pid=${OPTIONAL_PLUGIN_IDS[$idx]}
      printf "    [%d] %-18s %s\n" "$((idx + 1))" "$pid" "${PLUGIN_SUMMARY[$pid]}"
    done
    echo ""
    local reply=""
    read -r -p "请输入要额外安装的编号（多个用空格或逗号分隔，直接回车仅安装面板+安全插件）: " reply || reply=""
    reply=${reply//,/ }
    local tok
    for tok in $reply; do
      if [[ $tok == "all" ]]; then
        SELECTED_PLUGINS=("${OPTIONAL_PLUGIN_IDS[@]}")
        break
      elif [[ $tok =~ ^[0-9]+$ ]] && ((tok >= 1 && tok <= ${#OPTIONAL_PLUGIN_IDS[@]})); then
        SELECTED_PLUGINS+=("${OPTIONAL_PLUGIN_IDS[$((tok - 1))]}")
      else
        die "无效的选项编号：$tok（请输入 1~${#OPTIONAL_PLUGIN_IDS[@]}、all 或直接回车跳过）"
      fi
    done
  fi

  local need_xray=0 has_certs=0 has_dns=0 p
  for p in "${SELECTED_PLUGINS[@]}"; do
    [[ $p == "proxy.advanced" ]] && need_xray=1
    [[ $p == "tls.certificates" ]] && has_certs=1
    [[ $p == "domain.dns" ]] && has_dns=1
  done
  if ((need_xray)); then
    log "已自动补齐 proxy.advanced 的前置依赖插件：core.xray"
  fi
  if ((has_certs && !has_dns)); then
    echo "提示：已选择 tls.certificates 但未选 domain.dns；如需使用 DNS-01 自动签发证书，建议后续在面板内补装 domain.dns。" >&2
  fi

  local ordered=() candidate
  for candidate in "${OPTIONAL_PLUGIN_IDS[@]}"; do
    if [[ $candidate == "core.xray" && $need_xray == 1 ]]; then
      ordered+=("core.xray")
      continue
    fi
    for p in "${SELECTED_PLUGINS[@]}"; do
      if [[ $p == "$candidate" ]]; then
        ordered+=("$candidate")
        break
      fi
    done
  done
  SELECTED_PLUGINS=("${ordered[@]}")
}

select_optional_plugins
if ((${#SELECTED_PLUGINS[@]} > 0)) && [[ -n $offline && -z $offline_plugin_dir ]]; then
  die "离线模式下通过 --plugins 选择可选插件时，请同时指定 --plugin-dir <目录>"
fi

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

# ── 获取发布包 ───────────────────────────────────────────────────────────────
if [[ -n $version ]]; then
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "版本号格式应为 vX.Y.Z"
  [[ -n $RELEASE_PUBKEY_PEM ]] || die "此脚本未内嵌发布公钥，只能使用 --offline"
  command -v curl >/dev/null || die "在线安装需要 curl"
  command -v openssl >/dev/null || die "在线安装需要 openssl（验签）"
  name=qwq-$version-linux-$ARCH.tar.gz
  for f in "$name" SHA256SUMS SHA256SUMS.sig; do
    curl -fsSL --proto '=https' --connect-timeout 10 --speed-limit 10240 --speed-time 15 --retry 3 -o "$T/$f" "$mirror/$version/$f" || die "下载 $f 失败"
  done
  printf '%s\n' "$RELEASE_PUBKEY_PEM" >"$T/release.pub"
  openssl pkeyutl -verify -pubin -inkey "$T/release.pub" -rawin \
    -in "$T/SHA256SUMS" -sigfile "$T/SHA256SUMS.sig" >/dev/null || die "SHA256SUMS 签名无效"
  (cd "$T" && sha256sum --ignore-missing --strict -c SHA256SUMS >/dev/null) || die "发布包校验和不符"
  TAR=$T/$name
else
  [[ -f $offline ]] || die "找不到发布包 $offline"
  TAR=$offline
fi

mkdir "$T/pkg"
tar -C "$T/pkg" --no-same-owner -xzf "$TAR" || die "解包失败"
P=$T/pkg
[[ -f $P/VERSION && -x $P/bin/qwq && -x $P/bin/qwq-privileged && -x $P/bin/qwq-capability && -d $P/share/systemd ]] || die "发布包布局不完整"
[[ -f $P/share/polkit/qwq-plugin.rules ]] || die "发布包缺少插件管理所需的 polkit 规则"
V=$(tr -d '[:space:]' <"$P/VERSION")
[[ $V =~ ^[0-9A-Za-z._+-]+$ ]] || die "发布包 VERSION 非法"
[[ -z $version || $version == "$V" || $version == "v$V" ]] || die "发布包版本 $V 与 --version $version 不一致"

# ── 随机高位端口与安全密道生成（仅首次安装使用；已有配置保持不变）──────────
port_in_use() {
  local hex
  printf -v hex '%04X' "$1"
  awk -v h="$hex" 'NR>1 && $4=="0A" { split($2, a, ":"); if (toupper(a[2]) == h) { found=1; exit } } END { exit !found }' \
    /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

pick_random_high_port() {
  local attempt=0 raw p
  while ((attempt < 64)); do
    attempt=$((attempt + 1))
    raw=$(od -An -tu2 -N2 /dev/urandom 2>/dev/null | tr -d '[:space:]' || true)
    if [[ $raw =~ ^[0-9]+$ ]]; then
      p=$((20000 + raw % 40000))
    else
      p=$((20000 + (RANDOM * 32768 + RANDOM) % 40000))
    fi
    if ! port_in_use "$p"; then
      echo "$p"
      return 0
    fi
  done
  echo 28443
}

generate_random_entry_path() {
  local out="" chunk
  while ((${#out} < 10)); do
    chunk=$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | LC_ALL=C tr -dc 'a-hjkmnp-z2-9' || true)
    out+=$chunk
  done
  echo "${out:0:10}"
}

fresh_install=0
init_port=""
init_entry_path=""
if [[ ! -f $ETC/qwq.json ]]; then
  fresh_install=1
  if [[ -n $custom_port ]]; then
    init_port=$custom_port
  else
    init_port=$(pick_random_high_port)
  fi
  if ((has_custom_entry_path)); then
    init_entry_path=$custom_entry_path
  else
    init_entry_path=$(generate_random_entry_path)
  fi
fi

# ── 安装前检查（DEP-05：0 通过 / 1 警告 / 3 失败）──────────────────────────
preinstall_args=(doctor --preinstall)
if ((fresh_install)); then
  preinstall_args+=(--listen "127.0.0.1:$init_port")
fi
rc=0; "$P/bin/qwq" "${preinstall_args[@]}" || rc=$?
case $rc in
  0|1) ;;
  3) die "安装前检查失败，按上面的提示修复后重试" ;;
  *) die "qwq doctor --preinstall 异常退出（$rc）" ;;
esac

# ── 发布树（不可变；同版本重复安装须内容一致）────────────────────────────────
R=$PREFIX/releases/$V
if [[ -d $R ]]; then
  diff -rq "$P" "$R" >/dev/null || die "$R 已存在且内容不同；发布树不可变，请换版本号"
  log "发布树 $R 已存在且一致"
else
  install -d -m0755 "$PREFIX" "$PREFIX/releases"
  cp -a "$P" "$R.tmp"
  chown -R root:root "$R.tmp"
  chmod -R go-w "$R.tmp"
  chmod 0755 "$R.tmp"
  mv -T "$R.tmp" "$R"
  log "已安装发布树 $R"
fi

# changed 记录本次是否改动了需要重启/重载的东西。
changed=0
put() { # put <mode> <src> <dst>：内容或权限不同才写入
  local mode=$1 src=$2 dst=$3
  if [[ -f $dst ]] && cmp -s "$src" "$dst" && [[ $(stat -c %a "$dst") == "${mode#0}" ]]; then
    return 0
  fi
  install -D -m"$mode" "$src" "$dst"
  changed=1
}

# ── 用户、目录骨架 ───────────────────────────────────────────────────────────
put 0644 "$R/share/sysusers/qwq.conf" /usr/lib/sysusers.d/qwq.conf
systemd-sysusers /usr/lib/sysusers.d/qwq.conf
put 0644 "$R/share/tmpfiles/qwq.conf" /usr/lib/tmpfiles.d/qwq.conf

if [[ -d /var/lib/qwq/plugins && ! -L /var/lib/qwq/plugins ]]; then
  log "迁移旧布局 /var/lib/qwq/plugins → /var/lib/qwq-plugins"
  systemctl stop qwq-controller.service 'qwq-plugin@*.service' 'qwq-plugin@*.socket' 2>/dev/null || true
  install -d -m0755 -o root -g root /var/lib/qwq-plugins
  for d in /var/lib/qwq/plugins/*; do
    [[ -e $d ]] || continue
    [[ ! -e /var/lib/qwq-plugins/${d##*/} ]] || die "迁移冲突：/var/lib/qwq-plugins/${d##*/} 已存在"
    mv -T "$d" "/var/lib/qwq-plugins/${d##*/}"
  done
  chown -R root:root /var/lib/qwq-plugins
  rmdir /var/lib/qwq/plugins
  install -d -m0700 -o root -g root /var/lib/qwq-privileged /var/lib/qwq-privileged/creds
  for c in /run/qwq/creds/*.token; do
    if [[ -f $c ]]; then install -m0600 -o root -g root "$c" /var/lib/qwq-privileged/creds/; fi
  done
  for f in "$UNIT_DIR"/qwq-plugin@*.service "$UNIT_DIR"/qwq-plugin@*.service.d/*.conf /etc/tmpfiles.d/qwq-plugin-*.conf; do
    [[ -f $f ]] || continue
    sed -i -e 's|/var/lib/qwq/plugins/|/var/lib/qwq-plugins/|g' \
      -e 's|/run/qwq/creds/|/var/lib/qwq-privileged/creds/|g' "$f"
  done
  changed=1
fi
systemd-tmpfiles --create /usr/lib/tmpfiles.d/qwq.conf

# ── unit、polkit、配置、信任根 ───────────────────────────────────────────────
for u in "$R"/share/systemd/*; do
  put 0644 "$u" "$UNIT_DIR/${u##*/}"
done
if [[ -f $R/share/polkit/qwq-plugin.rules ]]; then
  [[ -d "/etc/polkit-1/rules.d" ]] || install -d -m0755 "/etc/polkit-1/rules.d"
  put 0644 "$R/share/polkit/qwq-plugin.rules" "/etc/polkit-1/rules.d/60-qwq-plugin.rules"
fi
install -d -m0750 -o root -g qwq "$ETC"
install -d -m0755 -o root -g root "$ETC/trust"
for k in "$R"/share/trust/*.pem "$R"/share/trust/*.policy.json; do
  if [[ -f $k && ! -e $ETC/trust/${k##*/} ]]; then
    install -m0644 "$k" "$ETC/trust/"
    changed=1
  fi
done
if [[ ! -f $ETC/qwq.json ]]; then
  cat >"$T/qwq.json" <<EOF
{
  "role": "standalone",
  "data_dir": "/var/lib/qwq",
  "run_dir": "/run/qwq",
  "http": {
    "listen": "127.0.0.1:${init_port}",
    "entry_path": "${init_entry_path}",
    "disguise": "drop",
    "auto_disable_on_domain": true,
    "tls": { "mode": "self_signed" }
  },
  "log": { "level": "info", "format": "json" },
  "retention": { "operations": "90d", "audit": "365d", "sessions": "30d" }
}
EOF
  install -m0640 -o root -g qwq "$T/qwq.json" "$ETC/qwq.json"
  changed=1
  if [[ -n $init_entry_path ]]; then
    log "已生成随机高位端口 ${init_port} 与随机安全密道 /${init_entry_path}（伪装模式：drop 静默断开）"
  else
    log "已生成随机高位端口 ${init_port}（已关闭安全密道）"
  fi
fi

if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
  chcon -R -t bin_t "$PREFIX" 2>/dev/null || true
  [[ -d /var/lib/qwq-plugins ]] && chcon -R -t bin_t /var/lib/qwq-plugins 2>/dev/null || true
fi
if command -v getenforce >/dev/null && [[ $(getenforce) == Enforcing ]]; then
  echo "注意：SELinux 为 Enforcing，已尝试为 $PREFIX 与 /var/lib/qwq-plugins 恢复 bin_t 标签；若仍遇 203/EXEC 请排查：qwq doctor、journalctl -u qwq-controller、ausearch -m avc -ts recent" >&2
fi

# ── 切换版本 ─────────────────────────────────────────────────────────────────
if [[ $(readlink "$PREFIX/current" 2>/dev/null) != "$R" ]]; then
  ln -sfn "$R" "$PREFIX/current.new"
  mv -T "$PREFIX/current.new" "$PREFIX/current"
  changed=1
  log "当前版本 → $V"
fi
if [[ $(readlink /usr/local/bin/qwq 2>/dev/null) != "$PREFIX/current/bin/qwq" ]]; then
  ln -sfn "$PREFIX/current/bin/qwq" /usr/local/bin/qwq
fi

# ── 旧版 polkit 自动兼容补丁检测（仅缺 polkit >= 0.106 的系统启用）──────────
needs_polkit_compat() {
  local load_state
  load_state=$(systemctl show -p LoadState --value polkit.service 2>/dev/null || true)
  if [[ $load_state != loaded ]]; then
    return 0
  fi
  if command -v pkaction >/dev/null 2>&1; then
    local ver major minor
    ver=$(pkaction --version 2>/dev/null | sed -nE 's/.*version[[:space:]]+([0-9]+)(\.([0-9]+))?.*/\1 \3/p' | head -n 1)
    if [[ -n $ver ]]; then
      read -r major minor <<<"$ver"
      minor=${minor:-0}
      if (( major == 0 && minor < 106 )); then
        return 0
      fi
    fi
  fi
  return 1
}

apply_polkit_compat_if_needed() {
  ((no_compat_patch)) && return 0
  if ! needs_polkit_compat; then
    return 0
  fi
  local rel_tag=$V
  [[ $rel_tag == v* ]] || rel_tag="v$rel_tag"
  local cfname="qwq-compat-polkit-${rel_tag}-linux-${ARCH}.tar.gz"
  local alt_cfname="qwq-compat-polkit-${V}-linux-${ARCH}.tar.gz"
  local ctar=""

  if [[ -n $compat_patch_file ]]; then
    [[ -f $compat_patch_file ]] || die "找不到指定的兼容补丁包 $compat_patch_file"
    ctar=$compat_patch_file
  elif [[ -n $version ]]; then
    log "检测到当前系统缺少 polkit >= 0.106（不支持原生 JS 规则），自动下载兼容补丁 $cfname …"
    ctar="$T/$cfname"
    curl -fsSL --proto '=https' --connect-timeout 10 --speed-limit 10240 --speed-time 15 --retry 3 -o "$ctar" "$mirror/$rel_tag/$cfname" ||
      die "下载兼容补丁 $cfname 失败"
    if ! (cd "$T" && awk -v f="$cfname" '$2 == f { found = 1; print } END { exit !found }' SHA256SUMS | sha256sum --strict -c - >/dev/null); then
      die "兼容补丁 $cfname SHA-256 校验失败"
    fi
  else
    local off_dir
    off_dir=$(dirname "$offline")
    if [[ -f "$off_dir/$cfname" ]]; then
      ctar="$off_dir/$cfname"
    elif [[ -f "$off_dir/$alt_cfname" ]]; then
      ctar="$off_dir/$alt_cfname"
    else
      echo "提示：当前系统缺少 polkit >= 0.106，但离线目录未找到 $cfname；插件沙箱需安装该兼容补丁或升级至 Debian 12+ / Ubuntu 24.04+" >&2
      return 0
    fi
    log "检测到当前系统缺少 polkit >= 0.106，自动应用离线兼容补丁 $(basename "$ctar") …"
  fi

  local cdir="$T/compat-polkit"
  mkdir -p "$cdir"
  tar -C "$cdir" --no-same-owner -xzf "$ctar" || die "解压兼容补丁失败"
  [[ -x "$cdir/install-compat.sh" ]] || die "兼容补丁缺少 install-compat.sh"
  local out
  out=$(bash "$cdir/install-compat.sh")
  printf '%s\n' "$out"
  if [[ $out != *"已是最新"* ]]; then
    changed=1
  fi
}

# ── 启动 ─────────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now qwq-privileged.socket            # 先 socket，controller 依赖它
systemctl enable --now qwq-capability.socket            # 空闲没有 root 能力进程
apply_polkit_compat_if_needed
systemctl enable qwq-controller.service
systemctl enable --now qwq-backup.timer                 # 每日备份到 /var/lib/qwq/backups（DEP-04）
if ((changed)); then
  systemctl restart qwq-controller.service
else
  systemctl start qwq-controller.service
fi

for _ in $(seq 30); do
  systemctl is-active --quiet qwq-controller.service && break
  sleep 1
done
systemctl is-active --quiet qwq-controller.service ||
  die "qwq-controller 未能启动；查看 journalctl -u qwq-controller -n 50 与 qwq doctor"
# 从运行时数据库或 /etc/qwq/qwq.json 解析当前监听端口、安全密道与 TLS 模式，用于健康探测与接入指引
cfg_listen=$(sed -nE 's/.*"listen"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$ETC/qwq.json" | head -n 1 || true)
cfg_entry_path=$(sed -nE 's/.*"entry_path"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$ETC/qwq.json" | head -n 1 || true)
cfg_panel_domain=$(sed -nE 's/.*"panel_domain"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$ETC/qwq.json" | head -n 1 || true)
cfg_tls_mode=$(sed -nE 's/.*"mode"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$ETC/qwq.json" | head -n 1 || true)
if [[ -f /var/lib/qwq/qwq.db ]] && command -v sqlite3 >/dev/null 2>&1; then
  db_row=$(sqlite3 -readonly -separator '|' /var/lib/qwq/qwq.db "SELECT listen_port, entry_path, panel_domain FROM panel_access_settings WHERE id = 1;" 2>/dev/null || true)
  if [[ -n $db_row ]]; then
    IFS='|' read -r db_port db_entry db_domain <<<"$db_row"
    if [[ $db_port =~ ^[0-9]+$ ]] && ((db_port >= 1 && db_port <= 65535)); then
      cfg_host=${cfg_listen%:*}
      cfg_listen="${cfg_host:-127.0.0.1}:${db_port}"
    fi
    cfg_entry_path=$db_entry
    cfg_panel_domain=$db_domain
  fi
fi
cfg_listen=${cfg_listen:-127.0.0.1:8443}
cfg_port=${cfg_listen##*:}
[[ $cfg_port =~ ^[0-9]+$ ]] || cfg_port=8443
cfg_scheme=https
[[ $cfg_tls_mode == "proxy" ]] && cfg_scheme=http
cfg_entry_path=${cfg_entry_path#/}
cfg_entry_path=${cfg_entry_path%/}
probe_host="127.0.0.1"
if [[ $cfg_listen == \[*\]* ]]; then
  probe_host="[::1]"
fi
if [[ -n $cfg_entry_path && $cfg_tls_mode != "proxy" && -z $cfg_panel_domain ]]; then
  LISTEN_CHECK="${cfg_scheme}://${probe_host}:${cfg_port}/${cfg_entry_path}/readyz"
else
  LISTEN_CHECK="${cfg_scheme}://${probe_host}:${cfg_port}/readyz"
fi

if command -v curl >/dev/null; then
  for _ in $(seq 30); do
    curl -skf --connect-timeout 2 --max-time 3 "$LISTEN_CHECK" >/dev/null && break
    sleep 1
  done || true
  curl -skf --connect-timeout 2 --max-time 3 "$LISTEN_CHECK" >/dev/null || echo "提示：$LISTEN_CHECK 暂无响应（若已在面板内修改过端口或密道可忽略）" >&2
fi

# ── 激活默认必装安全插件（security.basic）与用户按需选装的官方插件 ──────────
bootstrap_pkgs=()
if [[ -f $R/share/bootstrap-plugins/security.basic.qwqpkg ]]; then
  bootstrap_pkgs+=("$R/share/bootstrap-plugins/security.basic.qwqpkg")
fi
if ((${#SELECTED_PLUGINS[@]} > 0)); then
  rel_tag=$V
  [[ $rel_tag == v* ]] || rel_tag="v$rel_tag"
  for pid in "${SELECTED_PLUGINS[@]}"; do
    fname="${pid}-${rel_tag}-linux-${ARCH}.qwqpkg"
    alt_fname="${pid}-${V}-linux-${ARCH}.qwqpkg"
    if [[ -n $offline_plugin_dir ]]; then
      if [[ -f "$offline_plugin_dir/$fname" ]]; then
        bootstrap_pkgs+=("$offline_plugin_dir/$fname")
      elif [[ -f "$offline_plugin_dir/$alt_fname" ]]; then
        bootstrap_pkgs+=("$offline_plugin_dir/$alt_fname")
      elif [[ -f "$offline_plugin_dir/plugins/$fname" ]]; then
        bootstrap_pkgs+=("$offline_plugin_dir/plugins/$fname")
      elif [[ -f "$offline_plugin_dir/plugins/$alt_fname" ]]; then
        bootstrap_pkgs+=("$offline_plugin_dir/plugins/$alt_fname")
      else
        die "离线插件目录 $offline_plugin_dir 中未找到 $fname"
      fi
    else
      target_pkg="$T/$fname"
      log "下载可选插件 $pid ($fname) …"
      curl -fsSL --proto '=https' --connect-timeout 10 --speed-limit 10240 --speed-time 15 --retry 3 -o "$target_pkg" "$mirror/$rel_tag/$fname" ||
        die "下载可选插件 $fname 失败"
      if ! (cd "$T" && awk -v f="$fname" '$2 == f { found = 1; print } END { exit !found }' SHA256SUMS | sha256sum --strict -c - >/dev/null); then
        die "可选插件 $fname SHA-256 校验失败"
      fi
      bootstrap_pkgs+=("$target_pkg")
    fi
  done
fi
if ((${#bootstrap_pkgs[@]} > 0)); then
  log "正在验签并部署官方插件（共 ${#bootstrap_pkgs[@]} 个）…"
  "$PREFIX/current/bin/qwq" plugin bootstrap --config "$ETC/qwq.json" "${bootstrap_pkgs[@]}"
fi

rc=0; "$PREFIX/current/bin/qwq" setup-token --config "$ETC/qwq.json" || rc=$?
case $rc in
  0) ;;
  3) log "已初始化；忘记密码请用 sudo qwq recover" ;;
  *) echo "获取初始化链接失败，可稍后执行 sudo qwq setup-token" >&2 ;;
esac
cat <<EOF

====================================================================
  qwq 面板接入信息（已启用随机高位端口 + 随机安全密道防扫描保护）
====================================================================
  监听地址：${cfg_listen}
  安全密道：${cfg_entry_path:+/${cfg_entry_path}}${cfg_entry_path:-（未启用）}
  安全伪装：端口正确但密道错误时自动触发无服务伪装（默认 drop 静默断开）
  本地 SSH 隧道访问：
    ssh -L ${cfg_port}:127.0.0.1:${cfg_port} root@<服务器>
    建立隧道后，在浏览器打开上方打印的初始化链接即可。

  提示：
  1. 登录面板后可在「设置 → 系统 → 面板入口与安全伪装」随时修改端口、
     安全密道与伪装页模式（修改端口支持热切换，无需重装）。
  2. 若为面板配置反向代理域名，系统会自动关闭安全密道与伪装，
     直接访问域名即可进入面板。
  3. 如改为 0.0.0.0 直连（见 /opt/qwq/current/share/config/qwq.json.example.md），
     请自行在宝塔「安全」页 / ufw / firewalld 放行 TCP ${cfg_port} 端口，并核对证书指纹。
====================================================================
EOF
