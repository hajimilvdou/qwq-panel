# 插件重连使用原生 gRPC 连接

P1-RT-07，基线810e2d6。GREEN待验收。原两个重连入口调用go-plugin.NewClient(Reattach)，只保留GRPCClient并丢弃外层Client。已读取构建机库源码client.go:987-1005：外层启动reattach.func1，在Background上下文等待进程退出；内层连接Close不能结束该等待。

复用两包已有真实Unix gRPC服务器、原初始化/版本/健康和Fake systemd PID夹具，以仍存活的测试PID做六次重连/释放。共享有界栈观测只数目标等待帧，不输出私有栈；服务或RPC不成功、进程退出、栈截断都不能冒充无泄漏。先Linux真实RED，再统一连接接缝。

GREEN改为共享原生ClientConn拨号，保留Unix目标、明确传输凭据、原消息上限和ready超时。Supervisor Instance/controller handle持ClientConn并只关闭连接；同步全部类型/调用点、客户端夹具和文档，不调用Kill、不复制第二套拨号或绕过当前进程/版本/权限核验。原签名/消息边界与Peer验证保持。普通/race/静态与有意义失败/取消/清理回归仍需验收，1C1G长期资源仍后续。

首轮native28803完整exit1：Supervisor六次真实RPC成功并保持PID存活，关闭后留下6个已核目标等待帧，属于真实RED；controller测试误用Start重连现存进程，被原Precondition保护挡住，不能当成该入口RED。原3Go10240 bytes格式严格恢复后，仅把夹具改成真实运行状态下Attach/Release；不改变原Start防重复启动逻辑，原失败保留。

修夹具后native96459完整exit1：真实Attach/健康/Release六次均完成且未stop/kill，仍留下6个PID等待协程。最新3Go格式严格恢复后实施共享OpenPluginConnection，原消息上限和就绪等待保留；取消/缺失socket失败关闭句柄，类型和全部调用点改ClientConn，移除重复controller等待代码与旧client fixture。仍须完整Linux验证和Root独立复核，未提交。
