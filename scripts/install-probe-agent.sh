#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# qwq-probe-agent 极简安全单向探针受控端一键安装/卸载脚本（支持 Debian/Ubuntu/Rocky systemd 与 Alpine OpenRC）
# 零入站端口 · 零远程命令执行 · 动态非特权用户运行 · 凭据 0600 隔离 · 可选 --ca-sha256 密码学证书指纹固定

set -euo pipefail

ENDPOINT=""
NODE_ID=""
TOKEN=""
CA_SHA256=""
ALLOW_INSECURE="0"
ALLOW_UNVERIFIED="0"
ACTION="install"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint)
      [[ $# -ge 2 ]] || { echo "缺少参数值: $1" >&2; exit 2; }
      ENDPOINT="$2"; shift 2 ;;
    --node)
      [[ $# -ge 2 ]] || { echo "缺少参数值: $1" >&2; exit 2; }
      NODE_ID="$2"; shift 2 ;;
    --token)
      [[ $# -ge 2 ]] || { echo "缺少参数值: $1" >&2; exit 2; }
      TOKEN="$2"; shift 2 ;;
    --ca-sha256)
      [[ $# -ge 2 ]] || { echo "缺少参数值: $1" >&2; exit 2; }
      CA_SHA256="$2"; shift 2 ;;
    --insecure)         ALLOW_INSECURE="1"; shift 1 ;;
    --allow-unverified) ALLOW_UNVERIFIED="1"; shift 1 ;;
    --uninstall)        ACTION="uninstall"; shift 1 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "错误：请使用 root 或 sudo 运行此安装/卸载脚本。" >&2
  exit 1
fi

if [[ "$ACTION" == "uninstall" ]]; then
  systemctl disable --now qwq-probe-agent.service 2>/dev/null || true
  rc-service qwq-probe-agent stop 2>/dev/null || true
  rc-update del qwq-probe-agent default 2>/dev/null || true
  rm -f /etc/systemd/system/qwq-probe-agent.service /etc/init.d/qwq-probe-agent /usr/local/bin/qwq-probe-agent
  rm -rf /etc/qwq-probe-agent
  systemctl daemon-reload 2>/dev/null || true
  echo "[qwq-probe-agent] 已彻底卸载并清理全部文件。"
  exit 0
fi

if [[ -z "$ENDPOINT" || -z "$NODE_ID" || -z "$TOKEN" ]]; then
  echo "用法: install-probe-agent.sh --endpoint <URL> --node <ID> --token <prb_agt_...> [--ca-sha256 <64位hex>]" >&2
  exit 2
fi

if [[ ! "$NODE_ID" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,47}$ ]] || \
   [[ ! "$TOKEN" =~ ^prb_agt_[A-Za-z0-9_-]{16,96}$ ]] || \
   [[ ! "$ENDPOINT" =~ ^https?://[A-Za-z0-9._:/\[\]-]+$ ]]; then
  echo "参数格式校验未通过：拒绝含非法字符的 endpoint / node / token" >&2
  exit 2
fi

NORM_PIN=""
if [[ -n "$CA_SHA256" ]]; then
  NORM_PIN="$(printf '%s' "$CA_SHA256" | tr '[:upper:]' '[:lower:]' | tr -d ':' | sed 's/^sha256//')"
  if [[ ! "$NORM_PIN" =~ ^[0-9a-f]{64}$ ]]; then
    echo "错误：--ca-sha256 必须是 64 位十六进制 SHA-256 指纹（支持带冒号格式）。" >&2
    exit 2
  fi
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  BIN_ARCH="amd64" ;;
  aarch64|arm64) BIN_ARCH="arm64" ;;
  *) echo "Unsupported arch: $ARCH" >&2; exit 2 ;;
esac

# 从上报地址派生探针门户基址（同时兼容 /p/server.probe/agent/v1/report 与独立域名 /api/probe/v1/report）
PORTAL_BASE="$ENDPOINT"
if [[ "$PORTAL_BASE" == */p/server.probe/agent/v1/report ]]; then
  PORTAL_BASE="${PORTAL_BASE%/agent/v1/report}/portal"
elif [[ "$PORTAL_BASE" == */api/probe/v1/report ]]; then
  PORTAL_BASE="${PORTAL_BASE%/api/probe/v1/report}"
else
  PORTAL_BASE="${PORTAL_BASE%/v1/report}"
fi

TMP_DIR="$(mktemp -d /tmp/qwq-probe-agent.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT
TMP_BIN="$TMP_DIR/qwq-probe-agent"
TMP_SHA="$TMP_DIR/qwq-probe-agent.sha256"
PEER_CERT="$TMP_DIR/peer.crt"

CURL_TLS_OPTS=()
if [[ -n "$NORM_PIN" ]]; then
  if [[ "$PORTAL_BASE" != https://* ]]; then
    echo "安全拦截：指定 --ca-sha256 时必须使用 https:// 上报地址。" >&2
    exit 3
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "安全拦截：校验 --ca-sha256 需要 openssl，请先安装 openssl 后重试。" >&2
    exit 3
  fi
  HOSTPORT="${PORTAL_BASE#https://}"
  HOSTPORT="${HOSTPORT%%/*}"
  TLS_HOST="$HOSTPORT"
  TLS_PORT="443"
  CONNECT_TARGET=""
  if [[ "$HOSTPORT" == \[*\]:* ]]; then
    TLS_HOST="${HOSTPORT#\[}"
    TLS_HOST="${TLS_HOST%%\]:*}"
    TLS_PORT="${HOSTPORT##*\]:}"
    CONNECT_TARGET="[${TLS_HOST}]:${TLS_PORT}"
  elif [[ "$HOSTPORT" == \[*\] ]]; then
    TLS_HOST="${HOSTPORT#\[}"
    TLS_HOST="${TLS_HOST%\]}"
    CONNECT_TARGET="[${TLS_HOST}]:${TLS_PORT}"
  elif [[ "$HOSTPORT" == *:* ]]; then
    TLS_HOST="${HOSTPORT%:*}"
    TLS_PORT="${HOSTPORT##*:}"
    CONNECT_TARGET="${TLS_HOST}:${TLS_PORT}"
  else
    CONNECT_TARGET="${TLS_HOST}:${TLS_PORT}"
  fi
  if ! openssl s_client -connect "${CONNECT_TARGET}" -servername "${TLS_HOST}" </dev/null 2>/dev/null \
    | openssl x509 -outform PEM > "$PEER_CERT" 2>/dev/null; then
    echo "安全拦截：无法获取主控端 TLS 证书用于 --ca-sha256 核验，已中止下载！" >&2
    exit 3
  fi
  GOT_PIN="$(openssl x509 -in "$PEER_CERT" -outform DER 2>/dev/null | sha256sum | awk '{print tolower($1)}' || true)"
  if [[ -z "$GOT_PIN" || "$GOT_PIN" != "$NORM_PIN" ]]; then
    echo "安全拦截：服务端证书 SHA-256 (${GOT_PIN:-empty}) 与 --ca-sha256 (${NORM_PIN}) 不匹配，已中止下载！" >&2
    exit 3
  fi
  SPKI_PIN="$(openssl x509 -in "$PEER_CERT" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform der 2>/dev/null \
    | openssl dgst -sha256 -binary 2>/dev/null \
    | openssl enc -base64 2>/dev/null | tr -d '\r\n' || true)"
  if [[ -z "$SPKI_PIN" ]]; then
    echo "安全拦截：无法提取已验证证书公钥指纹，已中止下载！" >&2
    exit 3
  fi
  # 使用 curl 原生 --pinnedpubkey 锁定已通过 DER SHA-256 校验的公钥，杜绝预检与下载间的 TOCTOU MITM
  CURL_TLS_OPTS=(-k --pinnedpubkey "sha256//${SPKI_PIN}")
elif [[ "$ALLOW_INSECURE" == "1" ]]; then
  CURL_TLS_OPTS=(-k)
fi

install -d -m 0700 /etc/qwq-probe-agent
umask 0077
{
  printf 'QWQ_PROBE_ENDPOINT=%s\n' "$ENDPOINT"
  printf 'QWQ_PROBE_NODE=%s\n' "$NODE_ID"
  printf 'QWQ_PROBE_TOKEN=%s\n' "$TOKEN"
  if [[ -n "$NORM_PIN" ]]; then
    printf 'QWQ_PROBE_CA_SHA256=%s\n' "$NORM_PIN"
  elif [[ "$ALLOW_INSECURE" == "1" ]]; then
    printf 'QWQ_PROBE_INSECURE=1\n'
  fi
} > /etc/qwq-probe-agent/agent.env
chmod 0600 /etc/qwq-probe-agent/agent.env

echo "[qwq-probe-agent] 正在拉取单文件只读探针二进制 (linux/${BIN_ARCH})..."

BIN_URL="${PORTAL_BASE}/bin/qwq-probe-agent-linux-${BIN_ARCH}"
SHA_URL="${BIN_URL}.sha256"
DOWNLOADED=0
VERIFIED=0

if curl -fsSL "${CURL_TLS_OPTS[@]}" "$BIN_URL" -o "$TMP_BIN"; then
  DOWNLOADED=1
  if curl -fsSL "${CURL_TLS_OPTS[@]}" "$SHA_URL" -o "$TMP_SHA" 2>/dev/null; then
    WANT_SHA="$(awk '{print tolower($1)}' "$TMP_SHA" | head -n1)"
    GOT_SHA="$(sha256sum "$TMP_BIN" | awk '{print tolower($1)}')"
    if [[ ! "$WANT_SHA" =~ ^[0-9a-f]{64}$ ]] || [[ "$GOT_SHA" != "$WANT_SHA" ]]; then
      echo "错误：探针二进制 SHA-256 校验失败 (got=${GOT_SHA}, want=${WANT_SHA})" >&2
      exit 4
    fi
    VERIFIED=1
    echo "[qwq-probe-agent] SHA-256 校验通过 (${GOT_SHA:0:16}...)"
  elif [[ "$ALLOW_UNVERIFIED" != "1" ]]; then
    echo "错误：无法获取主控端二进制校验文件 (${SHA_URL})；为防止篡改已中止（如需跳过请显式传 --allow-unverified）。" >&2
    exit 4
  fi
fi

if [[ "$DOWNLOADED" != "1" ]]; then
  echo "[qwq-probe-agent] 主控端未内置该架构二进制，尝试从官方 GitHub Release 拉取..."
  GH_BASE="https://github.com/hajimilvdou/qwq-panel/releases/latest/download"
  curl -fsSL "${GH_BASE}/qwq-probe-agent-linux-${BIN_ARCH}" -o "$TMP_BIN"
  if curl -fsSL "${GH_BASE}/SHA256SUMS" -o "$TMP_SHA" 2>/dev/null; then
    WANT_SHA="$(awk -v f="qwq-probe-agent-linux-${BIN_ARCH}" '$2 == f || $2 == ("*" f) {print tolower($1); exit}' "$TMP_SHA")"
    GOT_SHA="$(sha256sum "$TMP_BIN" | awk '{print tolower($1)}')"
    if [[ ! "$WANT_SHA" =~ ^[0-9a-f]{64}$ ]] || [[ "$GOT_SHA" != "$WANT_SHA" ]]; then
      echo "错误：官方 Release 二进制 SHA-256 校验失败 (got=${GOT_SHA}, want=${WANT_SHA:-missing})" >&2
      exit 4
    fi
    VERIFIED=1
    echo "[qwq-probe-agent] 官方 Release SHA-256 校验通过 (${GOT_SHA:0:16}...)"
  elif [[ "$ALLOW_UNVERIFIED" != "1" ]]; then
    echo "错误：无法获取官方 Release SHA256SUMS，已中止安装（如需跳过请显式传 --allow-unverified）。" >&2
    exit 4
  fi
fi

if [[ "$VERIFIED" != "1" && "$ALLOW_UNVERIFIED" != "1" ]]; then
  echo "错误：探针二进制未通过完整性校验，已中止安装。" >&2
  exit 4
fi

install -m 0755 "$TMP_BIN" /usr/local/bin/qwq-probe-agent

echo "[qwq-probe-agent] 正在验证首包遥测上报与 TLS 连通性..."
env -i PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  QWQ_PROBE_ENDPOINT="$ENDPOINT" \
  QWQ_PROBE_NODE="$NODE_ID" \
  QWQ_PROBE_TOKEN="$TOKEN" \
  QWQ_PROBE_CA_SHA256="$NORM_PIN" \
  QWQ_PROBE_INSECURE="$([[ -z "$NORM_PIN" && "$ALLOW_INSECURE" == "1" ]] && echo 1 || echo 0)" \
  /usr/local/bin/qwq-probe-agent --check

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
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
MemoryMax=16M
CPUQuota=5%

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now qwq-probe-agent.service
  echo "[qwq-probe-agent] systemd 沙箱服务已启动并完成首包上报验收 (DynamicUser=yes, MemoryMax=16M, 零入站监听)。"
elif command -v rc-service >/dev/null 2>&1 || command -v openrc-run >/dev/null 2>&1; then
  cat > /etc/init.d/qwq-probe-agent <<'EOF'
#!/sbin/openrc-run
name="qwq-probe-agent"
description="qwq One-Way Read-Only Server Probe Agent"
command="/usr/local/bin/qwq-probe-agent"
command_user="nobody:nobody"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"

depend() {
  need net
  after firewall
}

start_pre() {
  if [ -f /etc/qwq-probe-agent/agent.env ]; then
    while IFS='=' read -r key val; do
      case "$key" in
        QWQ_PROBE_ENDPOINT|QWQ_PROBE_NODE|QWQ_PROBE_TOKEN|QWQ_PROBE_CA_SHA256|QWQ_PROBE_INSECURE)
          export "$key=$val"
          ;;
      esac
    done < /etc/qwq-probe-agent/agent.env
  fi
}
EOF
  chmod 0755 /etc/init.d/qwq-probe-agent
  rc-update add qwq-probe-agent default 2>/dev/null || true
  rc-service qwq-probe-agent restart
  echo "[qwq-probe-agent] Alpine OpenRC 服务已启动并完成首包上报验收 (command_user=nobody:nobody)。"
else
  echo "[qwq-probe-agent] 未检测到 systemd 或 OpenRC，二进制已安装至 /usr/local/bin/qwq-probe-agent，请手动配置守护进程。"
fi
