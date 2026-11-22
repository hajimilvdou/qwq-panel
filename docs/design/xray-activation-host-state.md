# Core 恢复后的宿主运行投影

P1-PLG-04 的 epoch 同步：SDK Activate 只从私有提交快照恢复，生成新进程 epoch 后目前只更新私有状态，宿主 running/current 仍是旧代次。后续跨插件观察会混用旧宿主投影与新统计。

恢复完成后复用同实例可信 SDK Host 与原 readHost/restoreHost/CAS 确认逻辑，固定同步 running/current；背景 operation_id 可以为空，但实例身份、peer/token 门禁保持，不能揭示秘密或写其他实例。响应丢失以重新读取实际目标确认，不重复写；宿主写入被拒绝或无法确认时不能把启动标为成功，按原 SDK 激活失败收口已启动进程。

复用真实 SDK/私有 Store 与现有宿主连接替身，核普通恢复、丢 CAS 响应、空 operation 背景上下文、实例 handle、写入拒绝和无新 reveal。换端口预检及真实连接广告随同一 PLG04 后续完成；X6 尚不证明真实转发，不能直接删未验声明。
