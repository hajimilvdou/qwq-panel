# root 代次记录基础组件

`GenerationRecordStore` 是独立私有存储组件。它只持久化已校验的数据，不调用 Pin、Signal、RPC 或 drain，也未装配到 generation helper 后端。现有三条 helper verb 仍返回 `Unavailable`；正常 kernfs 的原 `populated=0` 窗口 P1 仍未解决，CORE05 整体未完成。

## 固定目录与永久绑定

`OpenGenerationRecordStore(directory)` 只接收 root 启动配置。空值使用 `/var/lib/qwq-privileged/generation-stops`；目录必须是干净的绝对路径。复用 `OpenTrustedRoot` 校验真实祖先及 root 属主，拒绝组／其他用户可写的祖先。新建的自有目录逐级为0700，复用 `MkdirAllIn` 和 `SyncIn`；旧专用目录权限不符时拒绝，不自动修复。每次startup还沿可信祖先同步目录项，补齐此前mkdir后fsync失败留下的目录；这个过程不在每请求路径上。

目录句柄由 store 独占。记录相对 `os.Root` 访问，读取使用 `O_NOFOLLOW`，并比较打开前后 inode。每份记录必须为 root-owned、0600、普通文件、nlink=1；完整原文包括空白最多16KiB，复用原 exact-key、presence、non-null 和重复键扫描。损坏、硬链接、符号链接、错误权限或错误绑定均拒绝，保留原文件。

文件名为固定 domain `qwq.generation.record-key.v1` 和全局 `gen_` target_ref 的 canonical JSON SHA256，加 `.json` 后缀。plugin 或 operation 不参与文件选择；同一 target_ref 永久绑定同一 plugin、operation 和完整 proof 的 canonical digest。完整记录同时比较实际 proof 元组；压缩 guard 通过相同 proof_digest 校验原 proof，不能重新绑定。

## 状态与接口

| 状态 | 持久内容 | 允许行为 |
|---|---|---|
| bound | 完整原 proof、plugin/operation/target_ref/proof_digest，空 receipt_digest | 同元组 Bind 重放；匹配的完整 Complete |
| completed | 完整原 proof、完整引用和两个摘要、两条完成事实、规范时间 | 准确完成重放；匹配 Retire |
| retired | 永久引用和两个摘要、两条完成事实、规范时间 | 用原 proof 校验摘要后重建准确见证；匹配 Retire 重放 |

- `Bind(ctx, stopRequest)` 首次原子持久化绑定；返回 nil witness 仅表示 bound。已有 completed/retired 返回同一完成见证，不发 signal。
- `Complete(ctx, stopRequest, completion)` 复用 `ValidateFor`、`StopObservation.ValidateCompleted` 和 canonical receipt 校验。要求先存在同元组绑定；不同 receipt／时间不能覆盖已完成结果。
- `Retire(ctx, retireRequest)` 只压缩匹配的 completed 正文，保留永久 guard。bound-only 不能退休；没有物理 GC 或 TTL 删除。
- `Close()` 拒绝新操作，取消门禁等待，待已进入的真实 IO 结束后关闭全部自有句柄。

新绑定调用方必须先完成强 Pin。store 不能证明传入 proof 来自真实 root Pin，也不能把结构 flags 当作真实停止事实。未来调用方只能在确认原主退出和原组明确 populated=0 后构造 `NewGenerationCompletion`；不得从 ENODEV、路径删除、nlink 或新主存在推断完成。bound-only 在原对象丢失时继续失败安全；准确的已持久 completed/retired 才能用于恢复。

## 耐久与并发

复用 `WriteFileAtomicIn`：临时文件、file fsync、rename、directory fsync 都在可信根内，写入成功后重新读取校验。只有耐久完成且上下文仍有效时返回成功。已发布但目录 fsync 失败时仍返回错误；后续准确重放重新 `SyncIn` 目录，成功后才承认耐久状态，不回滚或覆盖该 guard。

同 target_ref 使用可取消门禁。等待者计入32个在途额度，引用归零即回收 gate map；每次只访问目标文件，不扫描全目录。目录 fd 的非阻塞 flock 串行跨实例／进程发布，避免两个首次 Bind 各自读取“不存在”后覆盖绑定。等待锁服从上下文和 Close；目录锁以串行 IO 换取永久绑定一致性。

已有原子 IO 不支持中途撤回。取消在 IO 前后检查；进入 IO 后必须等实际调用返回，已经持久的数据不擦除。本组件没有后台 goroutine 伪造硬30秒超时，也不宣称能够中断卡住的文件系统调用。

## Linux 验证

真实文件测试必须在 euid0 Linux 运行。测试只将 `TrustPolicy.StopAt` 显式限制在 root-owned 的0700临时 arena，仍使用真实 `os.Root`、文件权限、硬链接、符号链接、flock 和持久写入。生产 API 始终使用完整 `OpenTrustedRoot` 策略。

由 Root 统一执行：

```sh
go test ./internal/sandbox -run '^TestGenerationRecord' -count=1 -timeout=90s -json
go test -race ./internal/sandbox -run '^TestGenerationRecord' -count=1 -timeout=120s
```

故障测试保留 partial write、file fsync、directory fsync、坏文件及取消后的状态；不得以删除 guard 使重试变绿。构建、格式恢复及原 helper 回归由 Root 按本批清单统一验证。

Root已完成9源/8Go统一Linux验证：27个定向测试无fail/skip，六包普通、五包race、六包静态、仓库检查和qwq/privileged构建通过。8Go格式归档92160bytes经成员/token/路径守卫原位恢复，原始清单/失败与故障文件证据保留。本组件通过只证明数据存储；真实Pin、原组完成窗口、helper权限与五写恢复仍须继续验证。
