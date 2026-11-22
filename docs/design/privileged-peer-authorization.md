# 特权助手调用方 UID 门禁

状态：RED 已复现，GREEN 已接线，等待 Root 的 Linux 独立验证。P1-RT-03；基线 830adeb7a6b4fb5c70fc21d463c017b5305dc3ab，分支 codex/privileged-peer-authorization。原 PRIV-07、旧失败证据和实验额度继续保留。

## 真实问题与复用边界

修复前，qwq-privileged 的 serveConn 在连接建立后直接读取请求并调用 handle。socket 的 root:qwq 0660 只能限制组访问，不能证明连接来自配置的 agent 用户。同组的其他运维账号可以进入特权安装、删除等领域路径。

Linux SO_PEERCRED 提取已有 sandbox.HelperPeerUID；qwq-capability 已在读取正文前调用它，非 Linux 的失败实现也已存在。GREEN 仅在 serveConn 复用此函数和 helperServer 原 lookupUID 接缝，用配置 cfg.AgentUser 解析 agent UID，允许 root 与该 agent；身份提取或非 root 的用户解析失败均拒绝。请求 Spec.AgentUser 只参加既有安装字段校验，不能给连接授权。不增加另一套 peer 实现、服务、缓存、全局依赖或 Platform ABI。

连接超时设置在身份门禁前，设置失败即关闭。拒绝统一返回脱敏 UNAUTHENTICATED，写拒绝响应失败只记传输错误，随后关闭连接；日志不读取或输出请求正文。核验通过才进入原 JSON 解码和 handle，普通响应格式、原领域校验、socket 激活和一连接一请求的执行循环保持。

## RED 断言

新增两份 Linux 测试源码。复用 newTestHost、specFor、installRequest、token 和 fakeRunner，为安装和删除构造原本有效的领域请求；删除的受信安装只发生在快照之前。这样两个拒绝入口共同覆盖 runner、unit、tmpfiles、runtime、token、version 和 staging 的文件内容、模式与属主，既检查新增写入，也检查删除副作用。失败输出只列夹具路径，不打印凭据正文或摘要。

外来 UID 通过真实 Unix socket 连接。非 root 构建将配置的 agent UID 设为另一 UID；root 构建用当前测试二进制的受控降权连接进程，真实 UID 为 1，配置的 agent UID 为 2，避免 root 合法例外把错误测试变成通过。父测试不切换自身身份，不创建系统用户。合法 agent 在 root 构建中同样由 UID 1 子进程连接，root 另用父进程连接；两者都必须完成原安装协议和 one-shot 自然退出。原 TestHelperProtocolOverSocket 与 TestSocketActivatedServeHandlesOneRequest 保留。

身份无法提取使用 net.Pipe 调用真实 serveConn，不注入伪造 UID。收发并行允许服务在正文读取前拒绝；完整 UNAUTHENTICATED 或零正文的真实连接关闭都属于拒绝，超时、拨号失败、坏正文或其他领域错误不能冒充身份拒绝。

身份解析失败另用合法格式的随机配置用户名，先由生产 lookupUID 确认真实查询失败，再让实际非 root Unix peer 请求安装和删除，保持相同的无副作用断言。配置、installer 和请求 Spec.AgentUser 同步，避免错配字段把拒绝原因变成坏请求；peer 的 lookupUID 恢复为生产实现，不替换为假错误。原合法 one-shot 表追加 root_unresolved_agent 对照，同一无法解析的用户配置下 root 仍完成原安装协议和自然退出，原有 RED 不削弱。

## 资源与验收

连接子进程只接收测试 socket 环境变量和标准输入，不继承父进程环境。只在本次绝对临时根的随机 arena 内复制当前测试二进制；该目录在创建及递归删除前均检查绝对父目录、专用前缀、真实目录类型，删除后再核无残留。子进程有超时，完整 Wait 后核退出状态；监听器、连接、发送协程和服务协程均关闭或等待排空，之后才清理 arena。

Root 的 Linux RED（native 98289）已完整 exit 1：真实 UID 1 对配置 agent UID 2 的安装和删除、以及 net.Pipe 身份提取失败都进入了 runner 和文件副作用；root 与合法 agent 的 one-shot 对照通过，属于预期 RED。三源原 SHA 与 source/entry/payload 守卫未变，两份 Go 格式由 Root 严格恢复，所有失败证据保留。

GREEN native 83760 的 targeted 与三包普通通过；race 仅新用户夹具固定 UnknownUserError 类型失败，其他原断言未失败。Root 原 SHA 与三 Go 格式严格恢复后，native 16247 完整诊断 exit 0：CGO=0 返回 UnknownUserError，CGO=1 经 NSS 返回查询连接拒绝，getent 的生成用户名查询 exit 2，均无法得到真实 UID。回归改为验证生产查询确实失败，并要求非 root 无副作用/root 正常完成，拒绝条件和生产代码保持不变；全部失败保留。

当前准确四源、三份 Go，完整 Linux 验证、格式/SHA/成员/token 守卫、独立复核和本地集成由 Root 执行，当前不把 P1-RT-03 勾为完成。
