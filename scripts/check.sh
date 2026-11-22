#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# 质量门禁（IMPLEMENTATION-PLAN.md P0-T6）。在 Linux 构建机或 CI 上运行：
#
#   bash scripts/remote.sh run bash scripts/check.sh          # 从开发机
#   source scripts/dev-env.sh && bash scripts/check.sh        # 在 Linux 上
#
#   bash scripts/check.sh            全部静态检查、测试与交叉编译
#   bash scripts/check.sh race       -race 测试（需要 CGO 与 gcc，CI 中单独一个 job）
#   bash scripts/check.sh fuzz [秒]  对每个 Fuzz 目标做短时 fuzz（默认 20 秒）
#
# 环境变量：
#   QWQ_BREAKING_AGAINST  buf breaking 的基线，默认 .git#ref=main,subdir=api
#   QWQ_SKIP_VULN=1       跳过 govulncheck（离线时）
#
# ABI 冻结前 buf breaking 只报告不失败；platform.proto 头部写有 "ABI status: frozen" 之后失败即阻断。
set -uo pipefail

: "${QWQ_DEV_HOME:?先 source scripts/dev-env.sh}"
cd "$QWQ_ROOT"

GO_MODULES=(. sdk)
TOOL_MODULES=(tools tools/buf tools/catalog tools/release)
[[ -f tools/vacuum/go.mod ]] && TOOL_MODULES+=(tools/vacuum)
TARGETS=(linux/amd64 linux/arm64)
SDK_TARGETS=(linux/amd64 linux/arm64 linux/riscv64 linux/arm/v6 linux/arm/v7)
OPENAPI=api/public/v1/openapi.yaml

declare -a PASSED=() FAILED=() WARNED=()
# 检查函数以此退出码表示"通过，但需要在 PR 中说明"
WARN_RC=10

step() {
  local name=$1 start=$SECONDS rc
  shift
  printf '\n\033[1m== %s\033[0m\n' "$name"
  # 子 shell 不能放在 if 或 || 中，否则其中的 set -e 不生效
  ( set -e; "$@" )
  rc=$?
  case $rc in
    0) PASSED+=("$name ($((SECONDS - start))s)") ;;
    "$WARN_RC") WARNED+=("$name") ;;
    *) FAILED+=("$name"); printf '\033[31mFAIL: %s\033[0m\n' "$name" ;;
  esac
}

in_module() { (cd "$1" && shift && GOWORK=off "$@"); }

# ---------- 检查项 ----------

check_toolchain() {
  # shellcheck disable=SC1091
  source scripts/tools.lock
  local got
  got=$(go env GOVERSION)
  [[ $got == "go$GO_VERSION" ]] || { echo "go 为 $got，scripts/tools.lock 锁定 go$GO_VERSION（运行 bash scripts/bootstrap-tools.sh）"; return 1; }
  for t in buf protoc-gen-go protoc-gen-go-grpc staticcheck govulncheck; do
    command -v "$t" >/dev/null || { echo "缺少 $t（运行 bash scripts/bootstrap-tools.sh）"; return 1; }
  done
  echo "$got；工具齐全"
}

check_gofmt() {
  local out
  out=$(gofmt -l $(git ls-files -co --exclude-standard '*.go'))
  [[ -z $out ]] || { echo "需要 gofmt：" && echo "$out"; return 1; }
}

check_tidy() {
  local m
  for m in "${GO_MODULES[@]}" "${TOOL_MODULES[@]}"; do
    echo "-- $m"
    in_module "$m" go mod tidy -diff
  done
}

check_workspace() {
  go build ./... ./sdk/...
}

check_vet() {
  local m
  for m in "${GO_MODULES[@]}"; do echo "-- $m"; in_module "$m" go vet ./...; done
}

# tests/e2e 带 e2e 构建标签，普通 vet/test 看不到它；至少保证它随重构仍能编译。
check_e2e_vet() {
  GOWORK=off go vet -tags e2e ./tests/e2e/
}

check_staticcheck() {
  local m
  for m in "${GO_MODULES[@]}"; do echo "-- $m"; in_module "$m" staticcheck ./...; done
}

check_test() {
  local m
  for m in "${GO_MODULES[@]}"; do echo "-- $m"; in_module "$m" go test ./...; done
}

check_vuln() {
  local m
  for m in "${GO_MODULES[@]}"; do echo "-- $m"; in_module "$m" govulncheck ./...; done
}

check_sdk_boundary() {
  # sdk 模块的依赖闭包中不能出现宿主模块的包
  local bad
  bad=$(in_module sdk go list -deps ./... | grep -E '^github\.com/qwq-panel/qwq(/|$)' | grep -vE '^github\.com/qwq-panel/qwq/sdk(/|$)' || true)
  [[ -z $bad ]] || { echo "SDK 依赖了宿主包："; echo "$bad"; return 1; }
  echo "SDK 依赖闭包不含宿主包"
}

# target_env linux/arm/v7 输出 GOOS=linux GOARCH=arm GOARM=7（每行一个）
target_env() {
  local os arch arm
  IFS=/ read -r os arch arm <<<"$1"
  printf '%s\n' "GOOS=$os" "GOARCH=$arch"
  if [[ -n $arm ]]; then printf '%s\n' "GOARM=${arm#v}"; fi
}

check_cross() {
  local t
  # 宿主：发布架构完整编译
  for t in "${TARGETS[@]}"; do
    echo "-- host build $t"
    (cd . && env GOWORK=off $(target_env "$t") go build -o /dev/null ./cmd/...)
  done
  # SDK：插件可选的其余架构只做类型检查（go vet 不生成代码，比完整编译快一个数量级）
  for t in "${SDK_TARGETS[@]}"; do
    echo "-- sdk vet $t"
    (cd sdk && env GOWORK=off $(target_env "$t") go vet ./...)
  done
}

check_buf_lint() {
  buf format -d --exit-code
  buf lint
}

check_buf_breaking() {
  local against=${QWQ_BREAKING_AGAINST:-.git#ref=main,subdir=api}
  if buf breaking --against "$against"; then
    echo "与 $against 相比无破坏性变更"
    return 0
  fi
  if grep -q 'ABI status: frozen' api/qwq/platform/v1/platform.proto; then
    echo "ABI 已冻结，破坏性变更被拒绝"
    return 1
  fi
  echo "ABI 冻结前允许破坏性变更；以上变更需要在 PR 中说明"
  return "$WARN_RC"
}

check_generated() {
  local tmp rc=0
  tmp=$(mktemp -d)
  buf generate -o "$tmp"
  diff -r "$tmp/sdk/gen" sdk/gen || rc=1
  rm -rf "$tmp"
  ((rc == 0)) || { echo "sdk/gen 与 proto 不一致：运行 buf generate 并提交"; return 1; }
  bash spikes/corexray/generate-stats.sh --check || return 1
  echo "sdk/gen 与 proto 一致"
}

check_catalog() {
  local tmp rc=0
  tmp=$(mktemp)
  (cd tools/catalog && GOWORK=off go run . -in ../../api/public/v1/openapi.yaml -out "$tmp")
  cmp -s "$tmp" internal/catalog/host_gen.go || rc=1
  rm -f "$tmp"
  ((rc == 0)) || { echo "internal/catalog/host_gen.go 与 openapi.yaml 不一致：运行 go generate ./internal/catalog 并提交"; return 1; }
  echo "动作目录与 openapi.yaml 一致"
}

check_manifest() {
  python3 tools/manifest_check.py
}

check_repo() {
  python3 tools/repo_lint.py
}

check_openapi() {
  [[ -f $OPENAPI ]] || { echo "缺少 $OPENAPI"; return 1; }
  command -v vacuum >/dev/null || { echo "缺少 vacuum（运行 bash scripts/bootstrap-tools.sh）"; return 1; }
  # 项目规则集（qwq-* 契约规则）+ 内置规则；-n info：任何 info 及以上的结果都令门禁失败。
  # 每条规则默认只给 5s；解析后的文档（含全部 $ref 展开）已让遍历类规则接近该上限，
  # 会偶发超时。放宽到 30s 只是给足时间，不跳过任何规则。
  vacuum lint --no-update-check -b -q -d -n info --timeout 30 -r tools/vacuum/ruleset.mjs "$OPENAPI"
}

check_race() {
  local m
  for m in "${GO_MODULES[@]}"; do echo "-- $m"; CGO_ENABLED=1 in_module "$m" go test -race ./...; done
}

check_fuzz() {
  local secs=$1 m pkg fn
  for m in "${GO_MODULES[@]}"; do
    while read -r pkg; do
      while read -r fn; do
        [[ $fn == Fuzz* ]] || continue
        echo "-- $pkg $fn (${secs}s)"
        in_module "$m" go test -run='^$' -fuzz="^$fn\$" -fuzztime="${secs}s" "$pkg"
      done < <(in_module "$m" go test -list '^Fuzz' "$pkg" 2>/dev/null)
    done < <(in_module "$m" go list ./...)
  done
}

# ---------- 入口 ----------

mode=${1:-all}
case $mode in
  all)
    step toolchain check_toolchain
    step gofmt check_gofmt
    step "go mod tidy" check_tidy
    step "go.work 联合构建" check_workspace
    step "go vet" check_vet
    step "e2e 编译检查" check_e2e_vet
    step staticcheck check_staticcheck
    step "go test" check_test
    [[ ${QWQ_SKIP_VULN:-0} == 1 ]] || step govulncheck check_vuln
    step "SDK 模块边界" check_sdk_boundary
    step 交叉编译 check_cross
    step "buf format + lint" check_buf_lint
    step "buf breaking" check_buf_breaking
    step 生成代码无漂移 check_generated
    step 动作目录无漂移 check_catalog
    step manifest check_manifest
    step "SPDX/边界/密钥/版本" check_repo
    step OpenAPI check_openapi
    ;;
  race) step "go test -race" check_race ;;
  fuzz) step fuzz check_fuzz "${2:-20}" ;;
  *) sed -n '4,16p' "$0"; exit 2 ;;
esac

printf '\n\033[1m== 结果\033[0m\n'
for s in "${PASSED[@]}"; do printf '  ok    %s\n' "$s"; done
for s in "${WARNED[@]}"; do printf '  \033[33mwarn\033[0m  %s\n' "$s"; done
for s in "${FAILED[@]}"; do printf '  \033[31mFAIL\033[0m  %s\n' "$s"; done
((${#FAILED[@]} == 0))
