# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
#  ldflags.sh —— 宿主二进制的链接参数（DEP-03），release.sh 与 tests/e2e/build.sh 共用
# -----------------------------------------------------------------------------
#  用法：source scripts/lib/ldflags.sh; go build -ldflags "$(qwq_ldflags v1.2.3)" ...
#
#  版本只有 buildinfo.Version 一个链接期变量：qwq、qwq-privileged（ping 上报）与
#  qwqctl 都从这里读取。Revision/Modified 来自 Go 工具链嵌入的 VCS 信息
#  （debug.ReadBuildInfo），所以发布构建不能加 -buildvcs=false。
# =============================================================================

# QWQ_BASE_LDFLAGS 去掉符号表与调试信息；插件等非宿主二进制也用它。
QWQ_BASE_LDFLAGS="-s -w"

# qwq_ldflags <version>：输出注入版本号的完整链接参数。
qwq_ldflags() {
  local v=${1:?qwq_ldflags <version>}
  [[ $v =~ ^[0-9A-Za-z._+-]+$ ]] || { echo "qwq_ldflags: 非法版本号 $v" >&2; return 2; }
  printf '%s -X github.com/qwq-panel/qwq/internal/buildinfo.Version=%s' "$QWQ_BASE_LDFLAGS" "$v"
}
