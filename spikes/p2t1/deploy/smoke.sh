#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Fast smoke test for the P2-T1 spike: install, start the agent, dump the first
# state, and leave everything running for inspection.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

bash "$HERE/install.sh" || exit 1
systemctl restart qwq-spike-agent.service
sleep 2
echo '=== agent unit ==='
systemctl --no-pager --full status qwq-spike-agent.service | head -20
echo '=== agent journal ==='
journalctl -u qwq-spike-agent -n 60 --no-pager
echo '=== plugin unit ==='
systemctl show -p MainPID -p ActiveState -p SubState -p DynamicUser -p SupplementaryGroups qwq-spike-plugin@alpha.service
echo '=== plugin journal ==='
journalctl -u 'qwq-spike-plugin@alpha' -n 40 --no-pager
echo '=== runtime tree ==='
ls -la /run/qwq-spike /run/qwq-spike/state /run/qwq-spike/plugin/alpha /run/qwq-spike/host/alpha
echo '=== state files ==='
for f in /run/qwq-spike/state/*.json; do
  echo "--- $f ---"
  cat "$f"
done
