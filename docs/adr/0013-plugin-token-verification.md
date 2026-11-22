# ADR-0013：插件 token 持久化与 Host 通道校验

- 状态：已接受（Accepted，2026-11-09）。由审查任务卡 PRIV-05（方案 A）实施
- 关联：ADR-0003（插件沙箱）、ADR-0007（ABI 冻结规则）、ADR-0012（目录布局）、ARCH §5.4

## 背景

`LoadCredential=qwq-token:%t/qwq/creds/%i.token` 的源文件在 tmpfs 上，只在安装时写入：重启机器后插件统一 `243/CREDENTIALS` 起不来。同时这个 token 没有任何组件校验，只制造故障面。方案 B（删掉 token）放弃了一层与 `SO_PEERCRED` 正交的身份证明；选方案 A。

## 决策

1. **持久化**：token 存 `/var/lib/qwq-privileged/creds/<id>.token`（目录 root 0700，文件 root 0600，tmpfiles 创建目录）。模板改为 `LoadCredential=qwq-token:/var/lib/qwq-privileged/creds/%i.token`；per-plugin tmpfiles 不再有 creds 行。helper 经 `TrustPolicy.Open` 的可信句柄写入与删除（ADR-0012）。
2. **签发**：controller 每次安装 unit 生成新 token，经 helper 落盘后在迁移 `0010_plugin_credentials` 的 `plugin_credentials` 表记录 `sha256(token)`（每插件一行，重装替换）。token 本身不进数据库、不进日志。
3. **携带**：SDK（`pluginsdk.ServeSystemd`）从 `$CREDENTIALS_DIRECTORY/qwq-token` 读取 token，以 gRPC metadata `qwq-plugin-token`（`pluginsdk.HostTokenMetadataKey`）附在每个 Host 调用上。
4. **校验**：`hostsvc.Config.TokenDigest` 非空时，每个调用必须恰好携带一个该 metadata，其 SHA-256 与记录值常量时间相等，否则 `UNAUTHENTICATED`。摘要按调用读取，重装轮换后无需重建 Host 服务。controller 有数据库时总是启用；没有记录的插件（ADR 之前安装）被拒绝，重装即恢复（fail-closed）。

## 与 ABI 冻结的关系

proto 不变：token 走 transport metadata，不是消息字段。它是 Host 通道的认证前置条件，与 `SO_PEERCRED` 同层；旧 SDK 构建的插件不带 token 会被拒绝，因此首方插件必须用新 SDK 重新构建。冻结前（ADR-0007 推迟到 P4）接受此变化。

## 迁移

升级时（DEP-02）重新安装全部插件 unit：旧 `/run/qwq/creds` 下的 token 随 tmpfs 丢失，重装同时签发新 token、写入摘要。
