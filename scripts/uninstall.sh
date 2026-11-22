#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
#  uninstall.sh —— 卸载 qwq
# -----------------------------------------------------------------------------
#  用法：
#    sudo bash uninstall.sh            卸载程序、unit、插件；保留 /var/lib/qwq 与 /etc/qwq
#    sudo bash uninstall.sh --purge    另删除数据、配置与 qwq 用户（需输入确认词）
#
#  只删除 qwq 自己安装或创建的东西：qwq* unit、qwq-p-* 组、qwq 的目录与文件。
#  不碰 nginx、防火墙、宝塔或其他服务。可重复执行。
#  顺序与 tests/e2e 的 cleanup 一致：先停 controller，再停插件，最后停 helper。
# =============================================================================
set -euo pipefail

UNIT_DIR=/etc/systemd/system
CONFIRM_WORD=purge-qwq

die() { echo "uninstall.sh: $*" >&2; exit 1; }
log() { echo "==> $*"; }

purge=0
case ${1:-} in
  '') ;;
  --purge) purge=1 ;;
  -h|--help) sed -n '5,8p' "$0" | sed 's/^#  //' >&2; exit 0 ;;
  *) sed -n '5,8p' "$0" | sed 's/^#  //' >&2; exit 2 ;;
esac
[[ $EUID == 0 ]] || die "需要 root（sudo bash uninstall.sh …）"

if ((purge)); then
  echo "将永久删除 /var/lib/qwq（数据库、密钥、证书、备份）、/etc/qwq 与 qwq 用户。"
  read -r -p "输入 $CONFIRM_WORD 确认：" answer
  [[ $answer == "$CONFIRM_WORD" ]] || die "确认词不符，未做任何更改"
fi

# ── 停止并禁用（单元不存在时忽略错误）────────────────────────────────────────
log "停止服务"
systemctl disable --now qwq-backup.timer 2>/dev/null || true
systemctl stop qwq-backup.service 2>/dev/null || true
systemctl disable --now qwq-controller.service 2>/dev/null || true
# disable 不展开模板实例通配符。先读取实际已加载的单位，停止 socket 后再停止服务；
# 停止失败必须中止卸载，不能删除文件后留下仍运行的插件及其子进程。
loaded_units=$(systemctl list-units --all --plain --no-legend --no-pager) || die "无法枚举运行单位，未删除程序"
mapfile -t plugin_units < <(printf '%s\n' "$loaded_units" | awk '$1 ~ /^qwq-plugin@.+\.(socket|service)$/ {print $1}')
for suffix in socket service; do
  for unit in "${plugin_units[@]}"; do
    [[ $unit == *.$suffix ]] || continue
    systemctl stop "$unit" || die "停止 $unit 失败，未删除程序"
    systemctl disable "$unit" 2>/dev/null || true
  done
done
systemctl disable --now qwq-privileged.socket 2>/dev/null || true
systemctl stop qwq-privileged.service 2>/dev/null || true
systemctl disable --now qwq-capability.socket 2>/dev/null || true
systemctl stop qwq-capability.service 2>/dev/null || true
systemctl stop qwq-firewall-restore.service 2>/dev/null || true

# ── unit、tmpfiles、polkit、程序 ─────────────────────────────────────────────
log "删除 unit 与程序"
shopt -s nullglob
rm -rf -- \
  "$UNIT_DIR"/qwq-controller.service "$UNIT_DIR"/qwq-backup.service "$UNIT_DIR"/qwq-backup.timer \
  "$UNIT_DIR"/qwq-privileged.service "$UNIT_DIR"/qwq-privileged.socket \
  "$UNIT_DIR"/qwq-capability.service "$UNIT_DIR"/qwq-capability.socket \
  "$UNIT_DIR"/qwq-firewall-restore.service \
  "$UNIT_DIR"/qwq-plugin@* "$UNIT_DIR"/*.wants/qwq-* \
  /etc/tmpfiles.d/qwq-plugin-*.conf \
  /etc/polkit-1/rules.d/60-qwq-plugin.rules \
  /usr/lib/tmpfiles.d/qwq.conf /usr/lib/sysusers.d/qwq.conf \
  /usr/local/bin/qwq /opt/qwq \
  /var/lib/qwq-plugins /var/lib/qwq-privileged /run/qwq
shopt -u nullglob
systemctl daemon-reload
systemctl reset-failed 'qwq*' 2>/dev/null || true

# 插件私有组 qwq-p-<id>（由 helper 创建，插件目录已删除）。
while IFS=: read -r name _; do
  if [[ $name == qwq-p-* ]]; then
    groupdel "$name" && log "删除组 $name" || echo "删除组 $name 失败" >&2
  fi
done < <(getent group)

if ((purge)); then
  log "删除数据、配置与 qwq 用户"
  rm -rf -- /var/lib/qwq /var/lib/qwq-plugin-data /var/lib/private/qwq-plugin-data /var/lib/qwq-capability /etc/qwq
  if getent passwd qwq >/dev/null; then userdel qwq; fi
  if getent group qwq >/dev/null; then groupdel qwq; fi
  log "已彻底卸载"
else
  log "已卸载；保留 /var/lib/qwq、/var/lib/qwq-plugin-data、/etc/qwq 和 qwq 用户（重新安装即可继续使用；彻底删除用 --purge）"
fi
