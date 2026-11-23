#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Install the P2-T1 spike objects on the test machine. Everything it creates is
# named qwq-spike-* so uninstall.sh can remove it again. It never touches
# sshd, the firewall, fail2ban, /www (BT panel) or journald.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
BIN_SRC=${BIN_SRC:-$ROOT/bin}
UNIT_SRC=$ROOT/systemd
BIN_DST=/opt/qwq-spike
RUN=/run/qwq-spike
PLUGINS=(alpha beta)

[[ $EUID -eq 0 ]] || { echo "install.sh must run as root" >&2; exit 1; }
[[ -f $BIN_SRC/spike-agent && -f $BIN_SRC/spike-plugin ]] || {
  echo "missing binaries in $BIN_SRC" >&2
  exit 1
}

echo '== users and groups =='
for id in "${PLUGINS[@]}"; do
  getent group "qwq-spike-p-$id" >/dev/null || groupadd --system "qwq-spike-p-$id"
done
getent passwd qwq-spike-agent >/dev/null ||
  useradd --system --user-group --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin qwq-spike-agent
echo "agent user: $(id -nG qwq-spike-agent)"

echo '== binaries =='
install -d -o root -g root -m 0755 "$BIN_DST"
install -o root -g root -m 0755 "$BIN_SRC/spike-agent" "$BIN_DST/spike-agent"
install -o root -g root -m 0755 "$BIN_SRC/spike-plugin" "$BIN_DST/spike-plugin"

echo '== runtime tree =='
install -d -o root -g root -m 0755 "$RUN"
install -d -o root -g root -m 0700 "$RUN/creds"
install -d -o qwq-spike-agent -g qwq-spike-agent -m 0755 "$RUN/state"
install -d -o qwq-spike-agent -g qwq-spike-agent -m 0700 "$RUN/host"
for id in "${PLUGINS[@]}"; do
  install -d -o root -g root -m 0711 "$RUN/plugin/$id"
  install -d -o qwq-spike-agent -g "qwq-spike-p-$id" -m 2750 "$RUN/host/$id"
  if [[ ! -s $RUN/creds/$id.token ]]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$RUN/creds/$id.token"
    chmod 0600 "$RUN/creds/$id.token"
    chown root:root "$RUN/creds/$id.token"
  fi
done
ls -la "$RUN" "$RUN/plugin/alpha" "$RUN/creds"

echo '== systemd units =='
install -o root -g root -m 0644 "$UNIT_SRC/qwq-spike-agent.service" /etc/systemd/system/qwq-spike-agent.service
install -o root -g root -m 0644 "$UNIT_SRC/qwq-spike-plugin@.service" /etc/systemd/system/qwq-spike-plugin@.service
install -o root -g root -m 0644 "$UNIT_SRC/qwq-spike-plugin@.socket" /etc/systemd/system/qwq-spike-plugin@.socket
systemctl daemon-reload
systemctl reset-failed qwq-spike-plugin@alpha.service qwq-spike-plugin@beta.service 2>/dev/null || true

echo '== polkit rule =='
install -d -o root -g root -m 0755 /etc/polkit-1/rules.d
install -o root -g root -m 0644 "$UNIT_SRC/qwq-spike.rules" /etc/polkit-1/rules.d/qwq-spike.rules
# polkit re-reads rules on restart; a restart of polkitd is the documented way
# to apply a new rule immediately.
systemctl try-restart polkit.service
echo "polkit: $(systemctl is-active polkit.service)"

echo '== installed =='
systemctl list-unit-files 'qwq-spike*' --no-legend
