#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# qwq-probe-agent 极简安全单向探针受控端一键安装/卸载脚本（支持 Debian/Ubuntu/Rocky systemd 与 Alpine OpenRC）
# 零入站端口 · 零远程命令执行 · 动态非特权用户运行 · 凭据 0600 隔离不入进程命令行 ps

set -euo pipefail

ENDPOINT=""
NODE_ID=""
TOKEN=""
ACTION="install"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --node)     NODE_ID="$2"; shift 2 ;;
    --token)    TOKEN="$2"; shift 2 ;;
    --uninstall) ACTION="uninstall"; shift 1 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$ACTION" == "uninstall" ]]; then
  systemctl disable --now qwq-probe-agent.service 2>/dev/null || rc-service qwq-probe-agent stop 2>/dev/null || true
  rm -f /etc/systemd/system/qwq-probe-agent.service /etc/init.d/qwq-probe-agent /usr/local/bin/qwq-probe-agent
  rm -rf /etc/qwq-probe-agent
  systemctl daemon-reload 2>/dev/null || true
  echo "[qwq-probe-agent] 已彻底卸载并清理全部文件。"
  exit 0
fi

if [[ -z "$ENDPOINT" || -z "$NODE_ID" || -z "$TOKEN" ]]; then
  echo "用法: install-probe-agent.sh --endpoint <URL> --node <ID> --token <prb_agt_...>" >&2
  exit 2
fi

if [[ ! "$NODE_ID" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,47}$ ]] || [[ ! "$TOKEN" =~ ^prb_agt_[A-Za-z0-9_-]{16,96}$ ]] || [[ "$ENDPOINT" =~ [[:space:]\'\"\`\$] ]]; then
  echo "参数格式校验未通过：拒绝含空白或特殊控制字符的 endpoint / node / token" >&2
  exit 2
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) BIN_ARCH="amd64" ;;
  aarch64|arm64) BIN_ARCH="arm64" ;;
  *) echo "Unsupported arch: $ARCH" >&2; exit 2 ;;
esac

install -d -m 0700 /etc/qwq-probe-agent
umask 0077
printf 'QWQ_PROBE_ENDPOINT=%s\nQWQ_PROBE_NODE=%s\nQWQ_PROBE_TOKEN=%s\n' "$ENDPOINT" "$NODE_ID" "$TOKEN" > /etc/qwq-probe-agent/agent.env

echo "[qwq-probe-agent] 正在拉取单文件只读探针二进制 (linux/${BIN_ARCH})..."
BASE_URL="${ENDPOINT%/api/probe/v1/report}"
BASE_URL="${BASE_URL%/v1/report}"
TMP_BIN="$(mktemp /tmp/qwq-probe-agent.XXXXXX)"
trap 'rm -f "$TMP_BIN"' EXIT
curl -fsSL "${BASE_URL}/static/qwq-probe-agent-linux-${BIN_ARCH}" -o "$TMP_BIN"
install -m 0755 "$TMP_BIN" /usr/local/bin/qwq-probe-agent
rm -f "$TMP_BIN"
chmod 0755 /usr/local/bin/qwq-probe-agent

if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/qwq-probe-agent.service <<'EOF'
[Unit]
Description=qwq One-Way Read-Only Server Probe Agent (Zero Inbound / Zero Exec)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
EnvironmentFile=/etc/qwq-probe-agent/agent.env
ExecStart=/usr/local/bin/qwq-probe-agent
Restart=always
RestartSec=5s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax=16M
CPUQuota=5%

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now qwq-probe-agent.service
  echo "[qwq-probe-agent] systemd 沙箱服务已启动 (DynamicUser=yes, MemoryMax=16M, 零入站监听)。"
elif command -v rc-service >/dev/null 2>&1 || command -v openrc-run >/dev/null 2>&1; then
  cat > /etc/init.d/qwq-probe-agent <<'EOF'
#!/sbin/openrc-run
name="qwq-probe-agent"
description="qwq One-Way Read-Only Server Probe Agent"
command="/usr/local/bin/qwq-probe-agent"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"

depend() {
  need net
  after firewall
}

start_pre() {
  if [ -f /etc/qwq-probe-agent/agent.env ]; then
    set -a
    . /etc/qwq-probe-agent/agent.env
    set +a
  fi
}
EOF
  chmod 0755 /etc/init.d/qwq-probe-agent
  rc-update add qwq-probe-agent default 2>/dev/null || true
  rc-service qwq-probe-agent restart
  echo "[qwq-probe-agent] Alpine OpenRC 服务已启动。"
else
  echo "[qwq-probe-agent] 未检测到 systemd 或 OpenRC，二进制已安装至 /usr/local/bin/qwq-probe-agent，请手动配置守护进程。"
fi
