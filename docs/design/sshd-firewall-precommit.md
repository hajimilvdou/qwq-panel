# SSH 摘旧前的防火墙入站门禁

状态：P1-RT-04 GREEN 待 Linux 验收，基线 8d2e5b2。

真实问题：COMMIT_NEW 只在宿主回环验证 SSH banner；已有 inet qwq input 链可能仍只放行旧端口，摘旧后公网无法重新连接。沿用现有 ADD_NEW、事务归属、原生候选预检、运行监听与回滚链路。

复用边界：Runtime 增加入站核验方法，SystemRuntime 复用 firewall.Service.readSnapshot 和 snapshotDefinition 的真实保护规则解析，同时核验运行态与持久态一致。未启用且未保存自有 input 策略时允许；已启用策略必须在首个真实 qwq:preserve TCP 接受规则中保护新端口，前面只允许自有回环/已建立连接接受规则。不能用任意文本包含端口、回环规则、被前置 drop 覆盖的后置保护规则或插件自报事实代替。原端口提取逻辑收为共用函数，避免两套解析规则漂移。

SystemRunner 的 firewall State 和 sshd Transactions 已共用 /run/qwq/capability.lock。COMMIT_NEW 在既有事务锁内读取防火墙并完成摘旧；核验方法不重复获取同一 flock，避免嵌套死锁。检查失败不得写 SSH 配置、执行 reload 或改事务记录；保留 ADDED 双端口后可先放行防火墙，再复用原事务提交。ADD_NEW 和回滚不受新门禁阻断。

native 16476 已完整 exit 1，sshd 包 0.020s：两个拒绝/重试回归在旧代码下确实摘旧并修改配置/监听/事务，ADD_NEW 对照通过；无编译、拨号或超时归因。三源/两 Go 的冻结 SHA 与 20480 bytes 格式归档严格受检恢复后才改生产，失败证据保留。

GREEN 补齐真实 nft 定义、运行/持久漂移、注释/回环伪装、前置 drop/后置保护、安全接受规则前缀与缺少适配后端回归。仍须完成受影响包普通/race/vet/staticcheck、lint、构建及独立 P0/P1/P2 复核，当前不勾项目验收项。所有旧失败和实验额度保留。
