# ADR-0009：首版插件范围与基础防护

- 状态：Accepted（范围已定；各插件的详细设计在 P6 开始前另写）
- 日期：2026-11-01
- 关联：ADR-0005 Q11；ADR-0004 D6；ADR-0007"本次不改"中的 Host Capability 服务；ARCH §4.1.1、§5.4、§10

## 决策

首版内置两个插件，其余业务插件（含路线图里的安全插件、商城、代理）都在首版之后：

| 插件 | 内容 |
|---|---|
| 基础监控 `monitor.basic` | 单机形态：CPU、内存、磁盘、网络、负载的实时值与短期历史 |
| 基础防护 `security.basic` | 防火墙；登录防爆破（fail2ban 同类功能）；修改 SSH 端口；修改登录方式（密码 / 密钥、root 登录）；SSH 密钥管理（列出、导入、生成、删除）；系统用户密码修改 |

更多的安全功能（巡检、基线、告警策略、漏洞扫描等，即示例 manifest 中的 `security.scan`）放在之后的安全插件里。

两者都是普通插件（`placement=node`），不进宿主：遵守"业务全插件"，也让第三方以后能用同一套能力做替代品。

## 为什么要单独定规则

基础防护改的是 SSH 与防火墙，出错的后果是用户被锁在服务器外，而 1C1G 的用户往往没有 VNC 控制台。2026-11-01 在测试机（Ubuntu 24.04，与宝塔共存）上实际看到的情况：

- 主配置 `sshd_config` 写着 `PasswordAuthentication no`，但更早被 Include 的 `sshd_config.d/50-cloud-init.conf` 写着 `yes`；sshd 对同一关键字取第一个值，`sshd -T` 显示**密码登录实际是开着的**。只改主配置的面板会给出错误的状态。
- SSH 由 `ssh.socket` 套接字激活（`sshd-socket-generator` 从配置生成监听端口），改端口要 `daemon-reload` 并重启 `ssh.socket`，只 reload `ssh.service` 不会生效。
- 防火墙是 ufw 管理的 iptables-nft（底层 nftables），宝塔的 fail2ban 已有 `sshd` jail。用户的机器上常常已经有另一个管理者。

## 安全规则（基础防护必须满足）

1. **读有效配置，不读文件**：SSH 状态取自 `sshd -T`（必要时 `sshd -T -C user=…`），并列出每个设置来自哪个文件；发现被其他文件覆盖时在界面上明确提示。
2. **只写自己的文件**：SSH 写 `sshd_config.d/` 下一个由 qwq 拥有、文件名排在最前的 drop-in（如 `00-qwq.conf`），不改主配置与其他 drop-in；写入前 `sshd -t` 校验，失败不应用。防火墙只操作 qwq 自己的 nftables 表或链，不清空、不改写别人的规则。
3. **改变可达性的操作并入普通审批分级**（ADR-0016 取代原"倒计时确认"）：`approval` 不得低于 `ai_confirm`、风险不得低于 `high`，宿主在目录加载时钳制；AI 在 safe 模式进审批、full 模式按授权直接执行，人在界面按高风险确认。配套防自锁规则仍须满足：
   - 改 SSH 端口：先在防火墙放行新端口，再让 sshd 同时监听新旧两个端口；确认新端口可用后才去掉旧端口（验证方式 P6 设计时定）。提示用户检查云厂商安全组。
   - 关闭密码登录 / 禁止 root 登录：目标用户没有可用的已授权密钥时拒绝执行。
   - 防火墙：任何规则集都强制保留当前 SSH 端口与面板端口。
4. **防止自锁的前置检查**：删除最后一把密钥且密码登录已关闭时拒绝；封禁名单永远不包含当前管理会话的来源 IP 与白名单。
5. **密钥**：
   - 导入：校验公钥格式与类型（拒绝 DSA 与短于 3072 位的 RSA），显示 SHA256 指纹与注释，按系统用户分别管理 `authorized_keys`，保持文件权限与属主。
   - 生成：默认在浏览器内用 WebCrypto 生成 Ed25519 密钥对，只把公钥发到服务器；需要服务器生成时，私钥只显示 / 下载一次，不落盘、不写日志、不进事件与审计。
6. **密码**：新密码经 secret 引用传递，由 privileged helper 通过标准输入交给 `chpasswd`，不出现在命令行、日志、事件、审计与配置历史中；做强度检查。
7. **风险**：以上写操作的 capability 下限为 `high`（ADR-0004 D6），AI 发起时停在 `AWAITING_APPROVAL`，由真人批准；面向小白用户的"一键加固"是一个 `mode=job` 的意图级 operation，确认卡片逐项列出将要改变的内容。
8. **与已有管理者共存**：检测宝塔、1Panel、ufw、firewalld、系统 fail2ban 等。检测到时默认只读展示状态，用户明确选择"由 qwq 接管"后才写入；不同时运行两套封禁。

## 实现边界

- 这些系统操作由 `qwq-privileged` 执行，经版本化的 Host Capability 服务暴露给插件（ARCH §5.4、ADR-0007"本次不改"）：防火墙、SSH 配置、系统账户（authorized_keys 与密码）、封禁。每个服务是独立的 proto package（如 `qwq.capability.firewall.v1`），不进入 Platform ABI v1，所以不影响 P0-T7 的冻结。服务的方法与参数 schema 在 P6 开始前写 ADR。
- 对应 capability（写进 ARCH §10.3 的示例）：`system.firewall.manage`、`system.sshd.configure`、`system.account.keys:<user>`、`system.account.password:<user>`、`system.ban.manage`。
- 登录防爆破的实现倾向：插件内置轻量封禁（从 journald 读取 sshd 认证失败，写入 nftables 带超时的集合），常驻开销远小于另装一个 fail2ban（测试机上 fail2ban-server 约 16 MiB RSS）；检测到系统已有 fail2ban 时只展示其状态。P6 设计时最终确定。

## 测试纪律

两台测试 VPS 都依赖 SSH 才能访问，**不在它们的真实 sshd 与防火墙上做破坏性测试**：

- SSH：用独立配置文件与回环端口另起一个 sshd 实例，所有改端口、改登录方式、回滚的测试都针对它。
- 防火墙：在独立的网络命名空间里测试 nftables 规则。
- 只有改 SSH 端口、改防火墙这类改动的端到端验收若必须用真实环境时，先确认 VNC 控制台可用，并由发起人在场。

## 代价

- 两个首版插件都依赖 P2 的插件运行时与 privileged helper，P6 之前无法交付。
- 共存检测与"接管"流程增加工作量，但不做就会在已有宝塔等面板的机器上互相覆盖规则。
