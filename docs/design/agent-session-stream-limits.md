# AI 会话 SSE 与删除边界

PLG07 当前缺陷已实读：Subscribe 没有数量/closed 门禁；Delete 先移除内存入口并关闭订阅，再提交 SQLite 删除，提交失败也丢失原活跃运行时；delta 按字节直接切片会产生坏 UTF-8，累积满额后仍广播后续文本。

复用原会话锁、只读 owner 查验、事务删除、clipText 和现有有界事件环。每会话最多8订阅、单服务全局64订阅，分配前收口；订阅关闭、溢出、删除、服务关闭统一释放一次额度。Subscribe 在取得原运行时锁后检查当前 closed 与实际数据库行，避免已经删除的旧行被延迟请求复活成可订阅运行时。

Delete 先按原 stopRuntime 停止并等待当前工作，再在同一运行时锁内检查重新进入的工作、提交原 SQLite 删除并关闭运行时，最后移除同一内存对象；提交失败保留原订阅与内存入口。保持秘密回收、审计和原取消/审批链，不新增持久状态或事务旁路。

按施工手册将单助手文本总预算落实为256KiB；每段先按剩余预算经 clipText 截到 Rune 边界，空段/满额不再分配事件序号或广播。公开 AgentSessionMessage.content / AgentSessionEvent.delta 的上限同步到262144，避免新产出超出旧65536契约。256KiB是总字节预算，Unicode字符数量仍受其约束。

先增加真实 SQLite/实际 Subscribe/publish 回归取得 RED，随后实施 Linux普通/race/静态/契约/lint验证；Root按P0/P1/P2复核。仍不替代真实模型、CLI、双VPS与1C1G24小时终验；PLG08/09、client_message_id和未知工具的剩余子项随后串行处理。
