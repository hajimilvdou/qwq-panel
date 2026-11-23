#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Check what happens when the agent stops and starts a plugin socket unit, and
# capture the journal reason if the start fails. Temporary diagnostic.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

bash "$HERE/install.sh" >/dev/null || exit 1
systemctl stop 'qwq-spike-plugin@alpha.service' 'qwq-spike-plugin@beta.service' \
  'qwq-spike-plugin@alpha.socket' 'qwq-spike-plugin@beta.socket' 2>/dev/null
systemctl restart qwq-spike-agent.service
for _ in $(seq 1 150); do
  [[ -s /run/qwq-spike/state/beta.json ]] && break
  sleep 0.2
done
sleep 1
unit=qwq-spike-plugin@beta.socket
echo "before: $(systemctl show -p ActiveState -p SubState --value "$unit" | tr '\n' ' ')"
ls -l /run/qwq-spike/plugin/beta/ 2>&1

echo '--- agent stops the socket unit ---'
runuser -u qwq-spike-agent -- systemctl stop "$unit"
echo "rc=$?  after stop: $(systemctl show -p ActiveState -p SubState --value "$unit" | tr '\n' ' ')"
ls -l /run/qwq-spike/plugin/beta/ 2>&1
journalctl -u "$unit" -n 6 --no-pager

echo '--- agent starts it again ---'
runuser -u qwq-spike-agent -- systemctl start "$unit"
echo "rc=$?"
sleep 1
echo "after start: $(systemctl show -p ActiveState -p SubState --value "$unit" | tr '\n' ' ')"
ls -l /run/qwq-spike/plugin/beta/ 2>&1
journalctl -u "$unit" -n 12 --no-pager
echo '--- agent journal ---'
journalctl -u qwq-spike-agent -n 6 --no-pager

bash "$HERE/uninstall.sh" >/dev/null 2>&1
echo done
