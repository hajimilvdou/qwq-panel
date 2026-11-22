# Xray 统计 wire 定义

本目录保留 Xray v26.11.9（commit `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`）StatsService 的兼容子集，仅含 QueryStats 及三个相关消息。字段号、proto package 与 RPC 全名保持一致；没有 HandlerService、在线用户或管理操作。精确 counter 查询也使用 QueryStats 的固定名称并核对响应，不依赖上游缺失 counter 的错误文本。

来源：[app/stats/command/command.proto](https://github.com/XTLS/Xray-core/blob/676eaf66f8f05d4d558ee7a74b4736623d3feeb9/app/stats/command/command.proto)。原文及修改后的子集遵循 MPL-2.0；完整许可证在插件的 `LICENSES/MPL-2.0.txt`。生成的 Go 文件沿用 MPL-2.0，外围客户端由本项目编写，遵循 AGPL-3.0-only。

从仓库根目录在 Linux 构建机执行 `bash spikes/corexray/generate-stats.sh`。生成工具复用仓库锁定的 buf/protoc-gen-go/protoc-gen-go-grpc，不新增依赖。`--check` 模式检查生成漂移；升级核心时须重新比对锁定原文的消息、字段号与 RPC。
