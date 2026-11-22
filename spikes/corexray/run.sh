#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
# 测试机专用：动态 UID、私有网络/运行目录、只读已核验包，有界执行与回收。
# =============================================================================
set -euo pipefail
[[ $(id -u) == 0 ]]
PACKAGE=${1:?需要已核验 bundle 的绝对路径}
[[ $PACKAGE == /* && -d $PACKAGE && ! -L $PACKAGE ]]
RUN="qwq-x6-$(date +%s)-${RANDOM}"
UNIT="$RUN.service"
RUNTIME="/run/$RUN"
RUN_PID=''
cleanup() {
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
  if [[ -n $RUN_PID ]]; then wait "$RUN_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT
systemd-run --quiet --unit="$RUN" --collect --wait --pipe --service-type=exec \
  --property=DynamicUser=yes --property=RuntimeDirectory="$RUN" --property=RuntimeDirectoryMode=0700 \
  --property=PrivateNetwork=yes --property=PrivateTmp=yes --property=ProtectHome=yes \
  --property=ProtectSystem=strict --property=TemporaryFileSystem=/opt:ro \
  --property="BindReadOnlyPaths=$PACKAGE:/opt/qwq-x6-spike" \
  --property=NoNewPrivileges=yes --property=RestrictSUIDSGID=yes --property=CapabilityBoundingSet= \
  --property=MemoryHigh=160M --property=MemoryMax=192M --property=TasksMax=64 --property=LimitNOFILE=256 \
  --property=CPUQuota=50% --property=RuntimeMaxSec=120 --property=TimeoutStopSec=5 \
  --property="Environment=QWQ_X6_RUNTIME=$RUNTIME" --property=Environment=GOMEMLIMIT=80MiB \
  /usr/bin/env -i LANG=C LC_ALL=C "QWQ_X6_RUNTIME=$RUNTIME" GOMEMLIMIT=80MiB \
  /opt/qwq-x6-spike/bin/plugin -test.v -test.run '^TestNativePreflightAndPrivateStats$' -test.timeout=110s &
RUN_PID=$!
ready=0
for _ in $(seq 150); do
  if [[ -f $RUNTIME/other.ready ]]; then ready=1; break; fi
  if ! kill -0 "$RUN_PID" 2>/dev/null; then break; fi
  sleep 0.2
done
if ((ready)); then
  if setpriv --reuid=65534 --regid=65534 --clear-groups python3 - "$RUNTIME/api.sock" <<'PY'
import socket,sys
client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
client.settimeout(3)
try:
    client.connect(sys.argv[1])
except PermissionError:
    sys.exit(0)
except OSError:
    sys.exit(2)
else:
    sys.exit(1)
finally:
    client.close()
PY
  then
    printf 'denied\n' >"$RUNTIME/other.done"
  else
    printf 'failed\n' >"$RUNTIME/other.done"
  fi
  chmod 0644 "$RUNTIME/other.done"
fi
rc=0
wait "$RUN_PID" || rc=$?
RUN_PID=''
systemctl stop "$UNIT" >/dev/null 2>&1 || true
if [[ -e $RUNTIME ]]; then
  printf '隔离运行目录未回收。\n' >&2
  exit 1
fi
printf '动态单元及私有运行目录已回收；测试退出码=%s。\n' "$rc"
exit "$rc"
