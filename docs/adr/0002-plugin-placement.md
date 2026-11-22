# ADR-0002：插件放置位置与实例模型

- 状态：Accepted
- 日期：2026-11-01
- 关联：ADR-0001 A01、A17；架构审查 C1、F1

## 背景

ADR-0001 规定 Controller 不执行插件代码，插件只在 Agent 下运行；A17 规定同一插件的多个实例共享进程。但：

1. 插件商城、订阅、多用户套餐等插件天然是全局的，需要跨节点汇总，而 `controller` 角色没有本机 Agent，这类插件没有合法的运行位置。
2. v1 proto 只在少数调用里带 `instance_id`，`Start/Invoke/RunJob` 与 Host Service 无法区分同进程内的多个实例。

## 决策

1. manifest 增加 `placement: node | controller`。
   - `node`：在每个受管节点的 Agent 下运行，数据作用域是 `node_id + instance_id`。
   - `controller`：全局只运行一份，在 Controller 主机的 Agent 下运行；跨节点数据经公共版本化服务读取，不直接访问 Controller DB。
2. Controller 进程本身仍不加载任何插件。`standalone` 的本机 Agent 同时运行两类插件；`controller` 角色也附带一个本机 Agent，只运行 `placement=controller` 的插件，且不把本机注册为受管节点。
3. 实例模型：同一插件的实例默认共享一个进程。所有实例级调用在 `RequestContext.instance_id` 中标明目标实例；`ReleaseInstance` 释放单个实例，进程继续服务其他实例。进程级调用只有 `GetDescriptor` 和 gRPC 标准健康检查。
4. 对外路由：
   - node 级：`/api/v1/nodes/{node_id}/plugins/{plugin_id}/instances/{instance_id}/operations/{operation}`
   - controller 级：`/api/v1/plugins/{plugin_id}/operations/{operation}`
   - RBAC 的 resource 包含 `node_id`，可以按节点授权。
5. 公开路由（如订阅链接这类无会话访问）：插件经 `public.route:<name>` 能力注册，默认关闭，挂在独立前缀 `/p/{plugin_id}/...`，单独限流、限制请求体大小。会话 Cookie 的 `Path` 限定为 `/api/`，公开前缀永远收不到会话 Cookie。

## 后果

- 只装了 controller 级插件时，`controller` 角色才多出一个 Agent 进程（约 15–25 MiB）；否则不启动。
- 插件 SDK 必须按 `instance_id` 做命名空间隔离，并实现 `ReleaseInstance`。
- 节点视图、RBAC 与审计需要同时支持两种 resource 形态。

## 未采用

- Controller 直接加载 controller 级插件：第三方代码会进入宿主进程，违反 A08 和"信任边界不能热更"。
- 每个节点/实例一个插件进程：1G 机器无法承受，见 HANDOFF 附录 A。
