# SPDX-License-Identifier: AGPL-3.0-only
#
# 用法：source scripts/dev-env.sh
# 把工具链、缓存与用户配置全部指向 $QWQ_DEV_HOME（默认是仓库根目录）下的 .tools/ 与 .cache/，
# 只影响当前 shell（IMPLEMENTATION-PLAN.md §2）。构建机上由 scripts/remote.sh 设置 QWQ_DEV_HOME，
# 使工具与缓存位于同步目录之外，不随每次同步被清掉。

_qwq_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export QWQ_ROOT=$_qwq_root
export QWQ_DEV_HOME=${QWQ_DEV_HOME:-$_qwq_root}
unset _qwq_root

_t=$QWQ_DEV_HOME/.tools
_c=$QWQ_DEV_HOME/.cache
mkdir -p "$_t/bin" "$_c/tmp" "$_c/xdg/config" "$_c/xdg/cache" "$_c/xdg/data"

export GOROOT=$_t/go
export GOBIN=$_t/bin
export GOPATH=$_c/gopath
export GOMODCACHE=$_c/gomod
export GOCACHE=$_c/gobuild
export GOENV=$_c/go.env
export GOTMPDIR=${GOTMPDIR:-$_c/tmp}
mkdir -p "$GOTMPDIR"
export GOTOOLCHAIN=local
export GOFLAGS=-modcacherw
export CGO_ENABLED=0
export BUF_CACHE_DIR=$_c/buf
export npm_config_cache=$_c/npm
export PYTHONDONTWRITEBYTECODE=1
export PYTHONIOENCODING=utf-8

# os.UserConfigDir()/UserCacheDir() 的落点（Go 遥测、staticcheck 缓存等）
export XDG_CONFIG_HOME=$_c/xdg/config
export XDG_CACHE_HOME=$_c/xdg/cache
export XDG_DATA_HOME=$_c/xdg/data
case $(uname -s) in
  MINGW*|MSYS*|CYGWIN*)
    mkdir -p "$_c/appdata/roaming" "$_c/appdata/local"
    export APPDATA=$(cygpath -w "$_c/appdata/roaming")
    export LOCALAPPDATA=$(cygpath -w "$_c/appdata/local")
    # 本机访问不到 proxy.golang.org / sum.golang.org（2026-11-01 实测），校验库保持开启
    export GOPROXY=https://goproxy.cn,direct
    export GOSUMDB=sum.golang.google.cn
    ;;
esac

case ":$PATH:" in
  *":$_t/go/bin:"*) ;;
  *) export PATH=$_t/go/bin:$_t/bin:$PATH ;;
esac
unset _t _c
