#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# 在 Linux 构建机上编译与测试（IMPLEMENTATION-PLAN.md §2）。本机只需要 git、ssh、tar。
#
#   bash scripts/remote.sh bootstrap        同步后安装 / 校验构建机上的 Go 与工具（scripts/tools.lock）
#   bash scripts/remote.sh sync             把工作区（已跟踪 + 未忽略的新文件 + .git）同步到构建机
#   bash scripts/remote.sh run <cmd...>     同步后在构建机仓库根目录执行；只给一个参数时按 shell 片段执行
#   bash scripts/remote.sh exec <cmd...>    不同步，直接执行
#   bash scripts/remote.sh pull <path...>   下载到自有临时目录，仅移动到不存在的本机目标；已有源码使用受检归档原位写回
#   bash scripts/remote.sh push <本地路径> <远程目录>  把仓库内的文件或目录（可以在被忽略的 .cache/ 下）
#                                           复制到 $QWQ_REMOTE_HOME/<远程目录>/，用于把构建机产物送到测试机
#
# 并行工作时用 QWQ_REMOTE_SRC=<名字> 让每个会话使用自己的源码目录（默认 src），工具链与缓存共用。
# QWQ_REMOTE_ENV=<文件> 选择另一台机器，默认 scripts/remote.env（构建机）；测试机见 scripts/remote-test.env。
#
# 构建机上的全部内容都在 $QWQ_REMOTE_HOME 下：src/（源码副本，每次同步整体替换）、
# .tools/（工具链）、.cache/（模块与构建缓存）。删除该目录即可完全清理。
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
TASK_LOCAL_WORKSPACE=$ROOT
cd "$ROOT"

ENV_FILE=${QWQ_REMOTE_ENV:-$ROOT/scripts/remote.env}
[[ -f $ENV_FILE ]] || { echo "缺少 $ENV_FILE，参考 scripts/remote.env.example" >&2; exit 2; }
# shellcheck disable=SC1090
source "$ENV_FILE"
[[ $ROOT == "$TASK_LOCAL_WORKSPACE" && $(pwd -P) == "$TASK_LOCAL_WORKSPACE" ]] || { echo "本机工作区路径被配置改写，停止执行" >&2; exit 2; }
: "${QWQ_REMOTE_HOST:?}" "${QWQ_REMOTE_PORT:?}" "${QWQ_REMOTE_USER:?}" "${QWQ_REMOTE_KEY:?}" "${QWQ_REMOTE_HOME:?}"
case $QWQ_REMOTE_HOME in /*/*) ;; *) echo "QWQ_REMOTE_HOME 必须是至少两级的绝对路径" >&2; exit 2 ;; esac

TMPS=()
TMP_PREFIXES=()
source "$ROOT/scripts/lib/local-temp-cleanup.sh"
cleanup() {
  local command_status=$? index cleanup_status=0
  trap - EXIT
  for index in "${!TMPS[@]}"; do
    if ! checked_remove_local_temp "$ROOT" "$ROOT/.cache/tmp" "${TMPS[$index]}" "${TMP_PREFIXES[$index]}"; then cleanup_status=1; fi
  done
  ((command_status != 0 || cleanup_status == 0)) || command_status=1
  exit "$command_status"
}
trap cleanup EXIT

mkdir -p .cache/ssh .cache/tmp
SSH=(ssh -F /dev/null -i "$QWQ_REMOTE_KEY" -p "$QWQ_REMOTE_PORT"
  -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=30
  -o UserKnownHostsFile="$ROOT/.cache/ssh/known_hosts" -o StrictHostKeyChecking=accept-new
  -o LogLevel=ERROR "$QWQ_REMOTE_USER@$QWQ_REMOTE_HOST")

R=$QWQ_REMOTE_HOME
RQ=$(printf %q "$R")
SRC=${QWQ_REMOTE_SRC:-src}
[[ $SRC =~ ^[A-Za-z0-9_-]+$ ]] || { echo "QWQ_REMOTE_SRC 只能包含字母、数字、_ 与 -" >&2; exit 2; }
# 构建机命令统一低优先级运行，避免影响机器上的其他服务
# 内存护栏：并行会话多时，可用内存低于阈值就等待（最多 20 分钟），并把 go build 并行度限制为 2，
# 避免挤占机器上的其他服务。阈值可用 QWQ_REMOTE_GUARD_MIB 覆盖；设为 0 时跳过（小内存测试机）。
GUARD_MIB=${QWQ_REMOTE_GUARD_MIB:-900}
GUARD=''
if ((GUARD_MIB > 0)); then
  GUARD="for _i in \$(seq 240); do _m=\$(awk '/MemAvailable/{print int(\$2/1024)}' /proc/meminfo); [ \"\$_m\" -ge $GUARD_MIB ] && break; sleep 5; done;"
fi
# 测试机只有运行环境、没有源码副本：src 不存在时直接进入 QWQ_REMOTE_HOME，不 source 工具链。
PRELUDE="set -euo pipefail; $GUARD export QWQ_DEV_HOME=$RQ; if [ -d $RQ/$SRC ]; then cd $RQ/$SRC; if [ -f scripts/dev-env.sh ]; then source scripts/dev-env.sh; fi; else cd $RQ; fi; export GOFLAGS=\"\${GOFLAGS:-} -p=2\";"
NICE="nice -n 15 ionice -c2 -n7"

quote_args() { local out="" a; for a in "$@"; do out+=" $(printf %q "$a")"; done; printf '%s' "$out"; }

sync_tree() {
  local list n
  list=$(mktemp .cache/tmp/remote-list.XXXXXXXX); TMPS+=("$list"); TMP_PREFIXES+=("remote-list.")
  # 已跟踪 + 未忽略的新文件；工作区中已删除的文件不发送；被忽略的目录（密钥、缓存）不会出现在列表里
  git ls-files -z --cached --others --exclude-standard | while IFS= read -r -d '' f; do
    if [[ -e $f ]]; then printf '%s\0' "$f"; fi
  done >"$list"
  n=$(tr -cd '\0' <"$list" | wc -c)
  tar --null --exclude=.git/index.lock -cf - .git -T "$list" | gzip -1 |
    "${SSH[@]}" "set -euo pipefail; mkdir -p $RQ; cd $RQ;
      rm -rf $SRC.new; mkdir $SRC.new; tar --no-same-owner -xzf - -C $SRC.new;
      rm -rf $SRC.old; if [ -d $SRC ]; then mv $SRC $SRC.old; fi; mv $SRC.new $SRC; rm -rf $SRC.old"
  echo "同步完成：$n 个文件 + .git → $QWQ_REMOTE_HOST:$R/$SRC" >&2
}

remote_exec() {
  local script
  if (($# == 1)); then script=$1; else script=$(quote_args "$@"); fi
  "${SSH[@]}" "$PRELUDE $NICE bash -c $(printf %q "$script")"
}

pull_paths() {
  local p tmp
  for p in "$@"; do
    case ${p,,} in /*|*:*|*\\*|*..*|.|.git|.git/*|'') echo "拒绝的路径：$p" >&2; exit 2 ;; esac
  done
  tmp=$(mktemp -d .cache/tmp/remote-pull.XXXXXXXX); TMPS+=("$tmp"); TMP_PREFIXES+=("remote-pull.")
  "${SSH[@]}" "cd $RQ/$SRC && tar -cf - $(quote_args "$@")" | tar --no-same-owner -xf - -C "$tmp"
  for p in "$@"; do
    [[ -e "$tmp/$p" ]] || { echo "构建机上不存在：$p" >&2; exit 1; }
    if [[ -e $ROOT/$p || -L $ROOT/$p ]]; then
      echo "本机取回目标已存在，保留原文件；请先核验自有临时目标或使用归档流程" >&2
      return 1
    fi
    checked_move_local_download "$ROOT" "$ROOT/.cache/tmp" "$tmp/$p" "$p" || return 1
    echo "已取回 $p" >&2
  done
}

push_path() {
  local src=$1 dest=$2 abs
  case $dest in /*|*..*|'') echo "拒绝的远程目录：$dest" >&2; exit 2 ;; esac
  [[ -e $src ]] || { echo "不存在：$src" >&2; exit 1; }
  abs=$(cd "$(dirname "$src")" && pwd)/$(basename "$src")
  case $abs in
    "$ROOT"/服务器*|"$ROOT"/scripts/remote*.env|"$ROOT"/.git|"$ROOT"/.git/*) echo "拒绝发送：$src" >&2; exit 2 ;;
    "$ROOT"/*) ;;
    *) echo "只能发送仓库内的路径：$src" >&2; exit 2 ;;
  esac
  local dq
  dq=$(printf %q "$dest")
  tar -C "$(dirname "$abs")" -cf - "$(basename "$abs")" |
    "${SSH[@]}" "mkdir -p $RQ/$dq && tar --no-same-owner -xf - -C $RQ/$dq"
  echo "已发送 $src → $QWQ_REMOTE_HOST:$R/$dest/" >&2
}

cmd=${1:-}
shift || true
case $cmd in
  sync) sync_tree ;;
  run) sync_tree; remote_exec "$@" ;;
  exec) remote_exec "$@" ;;
  pull) [[ $# -gt 0 ]] || { echo "pull 需要路径" >&2; exit 2; }; pull_paths "$@" ;;
  push) [[ $# -eq 2 ]] || { echo "push 需要 <本地路径> <远程目录>" >&2; exit 2; }; push_path "$1" "$2" ;;
  bootstrap) sync_tree; remote_exec bash scripts/bootstrap-tools.sh ;;
  *) sed -n '4,18p' "$0" >&2; exit 2 ;;
esac
