#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
#  install-compat.sh —— 安装旧版 polkit 兼容补丁（qwq-compat-polkit）
#  仅用于缺少 polkit >= 0.106 JS 规则的系统（如 Ubuntu 22.04 / Debian 11）。
#  原生支持系统（Debian 12+ / Ubuntu 24.04+）无需也绝不应安装此补丁。
# =============================================================================
set -euo pipefail

[[ $EUID == 0 ]] || { echo "install-compat.sh: 需要 root 权限" >&2; exit 1; }

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEST=/opt/qwq/compat/polkit
UNIT_DIR=/etc/systemd/system
MARKER_DIR=/etc/qwq/compat
MARKER=$MARKER_DIR/polkit-compat.json

[[ -x "$SELF_DIR/bin/qwq-compat-unitctl" ]] || { echo "install-compat.sh: 缺少 bin/qwq-compat-unitctl" >&2; exit 1; }
[[ -f "$SELF_DIR/share/systemd/qwq-compat-unitctl.socket" && -f "$SELF_DIR/share/systemd/qwq-compat-unitctl.service" ]] || {
  echo "install-compat.sh: 缺少 systemd unit 文件" >&2
  exit 1
}
VER=$(tr -d '[:space:]' <"$SELF_DIR/VERSION" 2>/dev/null || echo "unknown")

changed=0
put_file() {
  local mode=$1 src=$2 dst=$3
  if [[ -f $dst ]] && cmp -s "$src" "$dst" && [[ $(stat -c %a "$dst") == "${mode#0}" ]]; then
    return 0
  fi
  install -D -m"$mode" -o root -g root "$src" "$dst"
  changed=1
}

install -d -m0755 -o root -g root "$DEST/bin" "$MARKER_DIR"
put_file 0755 "$SELF_DIR/bin/qwq-compat-unitctl" "$DEST/bin/qwq-compat-unitctl"
put_file 0644 "$SELF_DIR/VERSION" "$DEST/VERSION"
put_file 0755 "$SELF_DIR/uninstall-compat.sh" "$DEST/uninstall-compat.sh"
put_file 0644 "$SELF_DIR/share/systemd/qwq-compat-unitctl.socket" "$UNIT_DIR/qwq-compat-unitctl.socket"
put_file 0644 "$SELF_DIR/share/systemd/qwq-compat-unitctl.service" "$UNIT_DIR/qwq-compat-unitctl.service"

# Linux 5.x + 旧版 systemd/libseccomp（Ubuntu 22.04 / Debian 11）上的 @system-service
# 不包含较新的 Linux 6.x 系统调用（如 Go 1.27 os.Root.Chmod 调用的 fchmodat2）。
# 保持完全相同的 seccomp 白名单不变，仅将拒绝码改为 ENOSYS 让 Go 运行时自动优雅回退到 fchmodat。
TMP_SECCOMP=$(mktemp)
TMP_TMPFILES=$(mktemp)
TMP_MARKER=$(mktemp)
trap 'rm -f "$TMP_SECCOMP" "$TMP_TMPFILES" "$TMP_MARKER"' EXIT
cat >"$TMP_SECCOMP" <<'EOF'
# SPDX-License-Identifier: AGPL-3.0-only
[Service]
SystemCallErrorNumber=ENOSYS
EOF
for unit_svc in qwq-controller.service qwq-privileged.service qwq-capability.service qwq-plugin@.service; do
  put_file 0644 "$TMP_SECCOMP" "$UNIT_DIR/${unit_svc}.d/10-compat-seccomp.conf"
done

# 为 systemd 247 (Debian 11) 准备绑定挂载点 /run/qwq/compat-creds -> /run/credentials
cat >"$TMP_TMPFILES" <<'EOF'
# SPDX-License-Identifier: AGPL-3.0-only
d /run/qwq/compat-creds 0700 root root -
EOF
put_file 0644 "$TMP_TMPFILES" /etc/tmpfiles.d/qwq-compat-polkit.conf
systemd-tmpfiles --create /etc/tmpfiles.d/qwq-compat-polkit.conf 2>/dev/null || install -d -m0700 -o root -g root /run/qwq/compat-creds

cat >"$TMP_MARKER" <<EOF
{
  "patch": "qwq-compat-polkit",
  "version": "$VER",
  "socket": "/run/qwq/compat-unitctl.sock"
}
EOF
put_file 0644 "$TMP_MARKER" "$MARKER"

systemctl daemon-reload
systemctl enable --now qwq-compat-unitctl.socket

if ((changed)); then
  echo "==> 已安装并启用旧版 polkit 兼容补丁 qwq-compat-polkit ($VER)"
else
  echo "==> 旧版 polkit 兼容补丁 qwq-compat-polkit ($VER) 已是最新"
fi
