# 密码哈希默认 CPU 预算

范围：OPT-02。单核 VPS 的 identity 默认 Hasher 原来固定两个并发槽，两份默认 argon2 工作区可同时占用约 38 MiB。自动预算在创建时读取 `runtime.GOMAXPROCS(0)`，单 CPU 选择一个槽，多 CPU 至多两个；单核瞬时工作区预算因此为约 19 MiB。

`NewHasher` 的非正 concurrency 表示自动预算；显式正数保留原含义。`identity.New` 的默认装配使用自动预算，调用方注入的 Hasher 保持不变。保留公开常量 `DefaultHashConcurrency=2` 作为自动预算上限，不修改函数签名或引入全局可变配置。

此改动只限制并行数量，默认 argon2id 的内存、迭代、并行 lane、盐和密钥长度保持。Hash、Verify、DummyVerify 继续走同一信号量与原两秒排队限制；未命中账号仍执行真实哈希。槽数在 Hasher 创建时固定，不在已有哈希执行期间调整。

验收使用实际 Hash/Verify 检查单 CPU 自动默认、非正参数、多 CPU、显式两槽以及真实 identity 默认装配；占满额度后必须按上下文取消，释放后仍可正确验证。Linux RED 已确认单 CPU 构造及 identity 默认装配均错误使用两槽，多 CPU 和显式配置正对照通过。修复后四项定向全部通过，identity/authz/api/qwq 普通测试、identity race、受影响静态检查、仓库 lint 与宿主构建通过；严格三份 Go 格式归档受检恢复。

Root 自检：P0 未发现强度或权限改变；P1 实际装配使用单源自动预算，取消与释放回归通过，显式调用契约保持；P2 单 CPU 默认只占一份工作区，多 CPU 上限仍为两份，无新增后台任务或可变全局状态。

本项不能替代 1C1G 24 小时资源验收或完整身份/登录安全门禁。
