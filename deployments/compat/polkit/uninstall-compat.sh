#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
#  uninstall-compat.sh —— 卸载旧版 polkit 兼容补丁（qwq-compat-polkit）
# =============================================================================
set -euo pipefail

[[ $EUID == 0 ]] || { echo "uninstall-compat.sh: 需要 root 权限" >&2; exit 1; }

systemctl disable --now qwq-compat-unitctl.socket 2>/dev/null || true
systemctl stop qwq-compat-unitctl.service 2>/dev/null || true
rm -rf -- \
  /etc/systemd/system/qwq-compat-unitctl.socket \
  /etc/systemd/system/qwq-compat-unitctl.service \
  /etc/systemd/system/qwq-controller.service.d/10-compat-seccomp.conf \
  /etc/systemd/system/qwq-privileged.service.d/10-compat-seccomp.conf \
  /etc/systemd/system/qwq-capability.service.d/10-compat-seccomp.conf \
  /etc/systemd/system/qwq-plugin@.service.d/10-compat-seccomp.conf \
  /etc/tmpfiles.d/qwq-compat-polkit.conf \
  /etc/qwq/compat/polkit-compat.json \
  /opt/qwq/compat/polkit \
  /run/qwq/compat-unitctl.sock \
  /run/qwq/compat-creds
for d in \
  /etc/systemd/system/qwq-controller.service.d \
  /etc/systemd/system/qwq-privileged.service.d \
  /etc/systemd/system/qwq-capability.service.d \
  /etc/systemd/system/qwq-plugin@.service.d \
  /etc/qwq/compat /opt/qwq/compat; do
  rmdir "$d" 2>/dev/null || true
done
systemctl daemon-reload
systemctl reset-failed 'qwq-compat-unitctl*' 2>/dev/null || true
echo "==> 已卸载旧版 polkit 兼容补丁 qwq-compat-polkit"
