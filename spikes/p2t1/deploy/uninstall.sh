#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Remove every object the P2-T1 spike created and verify nothing is left.
set -uo pipefail

echo '== stop and remove units =='
systemctl stop qwq-spike-plugin@alpha.service qwq-spike-plugin@beta.service 2>/dev/null
systemctl stop qwq-spike-plugin@alpha.socket qwq-spike-plugin@beta.socket 2>/dev/null
systemctl stop qwq-spike-agent.service 2>/dev/null
systemctl disable qwq-spike-plugin@alpha.socket qwq-spike-plugin@beta.socket 2>/dev/null
rm -f /etc/systemd/system/qwq-spike-agent.service \
  /etc/systemd/system/qwq-spike-plugin@.service \
  /etc/systemd/system/qwq-spike-plugin@.socket
rm -rf /etc/systemd/system/qwq-spike-agent.service.d /etc/systemd/system/qwq-spike-plugin@.service.d
systemctl daemon-reload
systemctl reset-failed 'qwq-spike-plugin@*' 'qwq-spike-agent*' 2>/dev/null

echo '== remove polkit rule =='
rm -f /etc/polkit-1/rules.d/qwq-spike.rules
systemctl try-restart polkit.service 2>/dev/null

echo '== remove files, runtime tree and users =='
rm -rf /opt/qwq-spike /run/qwq-spike
rm -rf /run/credentials/qwq-spike-plugin@alpha.service /run/credentials/qwq-spike-plugin@beta.service
pkill -KILL -f '/opt/qwq-spike/spike-' 2>/dev/null
sleep 1
if getent passwd qwq-spike-agent >/dev/null; then
  userdel qwq-spike-agent 2>/dev/null
fi
if getent group qwq-spike-agent >/dev/null; then
  groupdel qwq-spike-agent 2>/dev/null
fi
for id in alpha beta; do
  if getent group "qwq-spike-p-$id" >/dev/null; then
    groupdel "qwq-spike-p-$id" 2>/dev/null
  fi
done
# Leftover from the first design iteration; harmless but must not survive.
if getent group qwq-spike-link >/dev/null; then
  groupdel qwq-spike-link 2>/dev/null
fi

echo '== verification: remaining qwq-spike objects =='
# Every check prints exactly one line: PRESENT means the object survived (bad),
# absent means it is gone (good).
check_absent() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "PRESENT: $label"
  else
    echo "absent:  $label"
  fi
}

check_absent 'unit file qwq-spike-agent.service' test -e /etc/systemd/system/qwq-spike-agent.service
check_absent 'unit file qwq-spike-plugin@.service' test -e /etc/systemd/system/qwq-spike-plugin@.service
check_absent 'unit file qwq-spike-plugin@.socket' test -e /etc/systemd/system/qwq-spike-plugin@.socket
check_absent 'unit registered qwq-spike-agent.service' systemctl cat qwq-spike-agent.service
check_absent 'unit registered qwq-spike-plugin@alpha.service' systemctl cat qwq-spike-plugin@alpha.service
check_absent 'unit registered qwq-spike-plugin@alpha.socket' systemctl cat qwq-spike-plugin@alpha.socket
check_absent 'user qwq-spike-agent' getent passwd qwq-spike-agent
check_absent 'group qwq-spike-agent' getent group qwq-spike-agent
check_absent 'group qwq-spike-p-alpha' getent group qwq-spike-p-alpha
check_absent 'group qwq-spike-p-beta' getent group qwq-spike-p-beta
check_absent 'group qwq-spike-link' getent group qwq-spike-link
check_absent 'polkit rule' test -e /etc/polkit-1/rules.d/qwq-spike.rules
check_absent 'binaries dir /opt/qwq-spike' test -e /opt/qwq-spike
check_absent 'runtime dir /run/qwq-spike' test -e /run/qwq-spike
check_absent 'credentials dir alpha' test -e /run/credentials/qwq-spike-plugin@alpha.service
check_absent 'credentials dir beta' test -e /run/credentials/qwq-spike-plugin@beta.service
check_absent 'processes' pgrep -f '/opt/qwq-spike/spike-'
check_absent 'cgroup alpha' test -d /sys/fs/cgroup/system.slice/system-qwq\x2dspike\x2dplugin.slice/qwq-spike-plugin@alpha.service
check_absent 'cgroup slice' test -d /sys/fs/cgroup/system.slice/system-qwq\x2dspike\x2dplugin.slice

echo '--- loaded units matching qwq-spike* ---'
systemctl list-units 'qwq-spike*' --all --no-legend --no-pager || true
echo '--- systemd failed units matching qwq-spike* ---'
systemctl list-units --failed 'qwq-spike*' --no-legend --no-pager || true
echo '--- end ---'