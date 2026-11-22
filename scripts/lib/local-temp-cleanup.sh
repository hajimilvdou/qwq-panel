#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
# 本机临时目录与普通文件共用边界；检查失败保留目标，不扩大工作区权限。
# Windows 在同一 PowerShell 中完成重解析点检查和原生删除。
# =============================================================================

_QWQ_TEMP_HELPER_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

_qwq_windows_local_path() {
  local action=$1 workspace=$2 cache=$3 candidate=$4 prefix=$5 destination=${6:-} runner
  # rrun 的摘要排序使用 C locale；原生 Windows 路径仍须完整传递 UTF-8。
  local LC_ALL=C.UTF-8
  runner=$(command -v pwsh.exe || command -v powershell.exe) || return 1
  MSYS2_ARG_CONV_EXCL='*' "$runner" -NoProfile -NonInteractive \
    -File "$(cygpath -aw -- "$_QWQ_TEMP_HELPER_DIR/local-temp-cleanup.ps1")" \
    -Workspace "$(cygpath -aw -- "$workspace")" -Cache "$(cygpath -aw -- "$cache")" \
    -Candidate "$(cygpath -aw -- "$candidate")" -Prefix "$prefix" \
    -Action "$action" -Destination "$destination"
}

_qwq_assert_local_path() {
  local current=$1
  while [[ $current != / ]]; do
    [[ ! -L $current ]] || { printf '[local] Parent link rejected; target retained.\n' >&2; return 1; }
    current=$(dirname -- "$current")
  done
}

_qwq_inspect_local_contents() {
  local candidate=$1 links entries bytes
  [[ -f $candidate || -d $candidate ]] || return 1
  links=$(find -P "$candidate" -type l -print -quit) || return 1
  [[ -z $links ]] || { printf '[local] Nested link rejected; target retained.\n' >&2; return 1; }
  if [[ -d $candidate ]]; then
    entries=$(find -P "$candidate" -mindepth 1 -printf '.\n' | wc -l) || return 1
    find -P "$candidate" -type f -exec sha256sum -- {} + >/dev/null || return 1
    bytes=$(du -sb -- "$candidate" | cut -f1) || return 1
  else
    entries=1
    sha256sum -- "$candidate" >/dev/null || return 1
    bytes=$(wc -c <"$candidate") || return 1
  fi
  printf '[local] Checked %s: %s entries, %s bytes, no links.\n' "$candidate" "$entries" "$bytes" >&2
}

checked_remove_local_temp() {
  local workspace=$1 cache=$2 candidate=$3 prefix=$4
  local workspace_abs cache_abs candidate_abs
  [[ -n $prefix && $prefix =~ ^[A-Za-z0-9_-]+\.$ ]] || return 1
  case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*)
      _qwq_windows_local_path remove "$workspace" "$cache" "$candidate" "$prefix"
      return $?
      ;;
  esac
  workspace_abs=$(realpath -sm -- "$workspace") || return 1
  cache_abs=$(realpath -sm -- "$cache") || return 1
  candidate_abs=$(realpath -sm -- "$candidate") || return 1
  [[ $workspace_abs != / && $cache_abs == "$workspace_abs/.cache/tmp" && $(dirname -- "$candidate_abs") == "$cache_abs" && $(basename -- "$candidate_abs") == "$prefix"?* ]] || {
    printf '[cleanup] Temp boundary rejected; target retained.\n' >&2; return 1;
  }
  [[ -e $candidate_abs || -L $candidate_abs ]] || return 0
  _qwq_assert_local_path "$candidate_abs" || return 1
  _qwq_inspect_local_contents "$candidate_abs" || return 1
  rm -rf -- "$candidate_abs"
}

# ======================== 下载对象的受检移动 ========================
checked_move_local_download() {
  local workspace=$1 cache=$2 candidate=$3 destination=$4 workspace_abs cache_abs candidate_abs destination_abs
  case "${destination,,}" in /*|*:*|*\\*|*..*|.|.git|.git/*|'') return 1;; esac
  case $(uname -s) in
    MINGW*|MSYS*|CYGWIN*) _qwq_windows_local_path move "$workspace" "$cache" "$candidate" "remote-pull." "$destination"; return $?;;
  esac
  workspace_abs=$(realpath -sm -- "$workspace") || return 1
  cache_abs=$(realpath -sm -- "$cache") || return 1
  candidate_abs=$(realpath -sm -- "$candidate") || return 1
  destination_abs=$(realpath -sm -- "$workspace/$destination") || return 1
  [[ $workspace_abs != / && $cache_abs == "$workspace_abs/.cache/tmp" && $candidate_abs == "$cache_abs"/remote-pull.?*/* && $destination_abs == "$workspace_abs"/* ]] || return 1
  [[ ! -e $destination_abs && ! -L $destination_abs ]] || { printf '[move] Existing destination retained.\n' >&2; return 1; }
  _qwq_assert_local_path "$candidate_abs" || return 1
  _qwq_assert_local_path "$destination_abs" || return 1
  _qwq_inspect_local_contents "$candidate_abs" || return 1
  mkdir -p -- "$(dirname -- "$destination_abs")" || return 1
  _qwq_assert_local_path "$destination_abs" || return 1
  mv -T --no-clobber -- "$candidate_abs" "$destination_abs" || return 1
  [[ ! -e $candidate_abs && ! -L $candidate_abs ]]
}
