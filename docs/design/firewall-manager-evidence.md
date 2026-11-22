# UFW 共存判断的实际证据

状态：P1-RT-05 GREEN 待验收，基线2335e99。复用原 TrustPolicy/os.Root 提供可隔离文件系统接缝，零值仍读取真实固定路径，主体不能提供目录或信任策略。

真实问题：SystemGuard.Managers 对任何现存 /etc/ufw/ufw.conf 都标记 Uncertain，导致预装且明确停用 UFW 的 Ubuntu 无法应用自有防火墙。不能把“有文件”当成“正在管理规则”，也不能只凭 inactive 推断已停用。

后续只有三个当前事实共同成立才解除 UFW 的配置文件疑虑：systemd 明确 inactive；可信、有限大小配置只含明确 ENABLED=no；原生 nft 没有 UFW 表或链。active/unknown/失败/过渡态、配置启用/不明/不可读，以及残留原生对象继续阻断；其他管理者策略保持。文件读取复用 local.FileState 的祖先/属主/模式/NOFOLLOW/大小检查，解析不使用 shell，输出不回显文件内容。

RED 使用真实临时文件和原 SystemGuard 路径，保留已有 nft/端口夹具，分别验证 Manager 状态与真实 Service.apply 的原生预检/写入链路。只增加文件系统接缝以避免改动 /etc，原 Uncertain 条件仍真实复现。Linux RED 后才修条件，补启用/未知/残留/不可信文件回归，完成受影响验证、独立 P0/P1/P2 复核后集成。所有旧失败与限定额度保留。

native91298完整exit1，firewall0.021s：明确停用仍Uncertain，实际Service.apply返回CONFLICT，原生checks/writes均0；不是夹具、编译或超时失败。三源/两Go SHA与20480 bytes格式归档365571b58f0a44e9d777979793a7c715d77a58cadcf57f0f6dd2638923cefee2严格恢复后才修改判定。

GREEN用独立原生事实布尔值收口，不依赖Detail文案。唯一明确ENABLED=no只使配置成为停用候选，现有chain证据继续阻断，再查table事实；无残留才清UFW疑虑，其他管理者条件保持。新增实际apply链路的active/启用/注释/冲突赋值/unknown/失败/过渡/残留链表/不可信文件/超大文件/坏原生响应/其他管理者回归；当前仍须完整Linux验证与独立复核。
