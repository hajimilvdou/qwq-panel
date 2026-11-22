#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# 在 Linux 构建机（或 CI）上安装 Go 工具链与开发工具，全部放在 $QWQ_DEV_HOME/.tools 下。
# 需要先 source scripts/dev-env.sh。可重复执行：版本与校验和都匹配时不重新下载。
set -euo pipefail
: "${QWQ_DEV_HOME:?先 source scripts/dev-env.sh}" "${GOROOT:?}" "${GOBIN:?}"
cd "$QWQ_ROOT"
# shellcheck disable=SC1091
source scripts/tools.lock

case $(uname -s)/$(uname -m) in
  Linux/x86_64) arch=amd64 ;;
  Linux/aarch64) arch=arm64 ;;
  *) echo "不支持的构建机：$(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac
want_sha_var=GO_SHA256_linux_$arch
want_sha=${!want_sha_var}

if [[ -x $GOROOT/bin/go ]] && [[ $("$GOROOT/bin/go" env GOVERSION) == "go$GO_VERSION" ]]; then
  echo "Go $GO_VERSION 已安装"
else
  tgz="go$GO_VERSION.linux-$arch.tar.gz"
  dl="$QWQ_DEV_HOME/.cache/dl"
  mkdir -p "$dl"
  echo "下载 $tgz"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$dl/$tgz.part" "https://go.dev/dl/$tgz"
  got_sha=$(sha256sum "$dl/$tgz.part" | cut -d' ' -f1)
  if [[ $got_sha != "$want_sha" ]]; then
    rm -f "$dl/$tgz.part"
    echo "sha256 不匹配：期望 $want_sha，实际 $got_sha" >&2
    exit 1
  fi
  rm -rf "$GOROOT.new"
  mkdir -p "$GOROOT.new"
  tar -xzf "$dl/$tgz.part" -C "$GOROOT.new" --strip-components=1
  rm -rf "$GOROOT"
  mv "$GOROOT.new" "$GOROOT"
  rm -f "$dl/$tgz.part"
  echo "Go $GO_VERSION 安装完成（sha256 已核对）"
fi

go telemetry off

# 工具模块各自锁版本：buf 依赖 protobuf 的预发布版，单独放一个模块，避免把 protoc-gen-go 也拖到预发布版；
# tools/release（cyclonedx-gomod、go-licenses）只有 release.sh 用，依赖多，同样隔离
for m in tools tools/buf tools/vacuum tools/release; do
  (cd "$m" && GOWORK=off go install tool)
done

go version
for t in buf protoc-gen-go protoc-gen-go-grpc staticcheck govulncheck cyclonedx-gomod go-licenses; do
  if [[ -x $GOBIN/$t ]]; then printf '%-20s %s\n' "$t" "$(go version -m "$GOBIN/$t" | awk '$1=="mod"{print $2, $3; exit}')"; fi
done
