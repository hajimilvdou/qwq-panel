# ADR-0031：AI 会话的角色与服务范围授权

状态：已接受，2026-11-20；对应已批准的 P1-CORE-03。

此前路由仅认证浏览器或服务账号，再按会话 owner 隔离。工具的 operations 授权能限制服务器写入，但不能阻止 viewer 或限定证书续期用途的服务账号创建会话、发送消息并消耗宿主模型。

12 条现有路由共享 agentSessionRoute 守卫：GET/HEAD 需要 host.agent_sessions:read，其余注册方法需要 write。调用既有 Authorizer，先重新核验当前角色、服务账号和完整作用域，再进入后端、解析内容或启动模型；服务失败继续拒绝，不接受客户端自报权限。Role 表及会话 ownership 不变。

viewer 仍可查看已有本人会话；创建、发送、配置、API key、取消和删除需要 write。普通获得角色权限的服务账号保留本人会话能力，限定续期动作/节点/资源/到期时间的账号不能跨用途进入全局模型路径。网关继续拒绝 delegation token，后端继续将非本人会话隐藏为404，工具仍需独立通过 operations 授权。

不新增迁移、依赖、缓存、goroutine、字段或路由，不改变会话权限模式与插件操作授权。回归覆盖真实角色降权后7条写路径403且不改会话/不触模型，限定范围服务账号12条路由拒绝，原普通服务账号以及管理员创建、CRUD、SSE继续可用。Linux 首轮完整验证通过：API、agentsession、authz、controller、cmd/qwq 的普通与 race 测试、vet、staticcheck、仓库 lint 和宿主构建；Root 独立 P0/P1/P2 复核未见本范围新增阻断项。
