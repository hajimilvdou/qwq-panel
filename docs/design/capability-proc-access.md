# 能力助手识别真实 SSH 监听的 /proc 权限

状态：P0-RT-02 GREEN 待验收，基线397e2d0。

当前能力助手启用 ProtectProc=invisible、ProcSubset=pid，CapabilityBoundingSet 没有 CAP_SYS_PTRACE。RuntimeSSHPorts 使用标准 SSH 单元的 MainPID 与 ss 的真实 pid 归属交叉确认，不接受进程自报名称；non-dumpable 的常驻 sshd 在此沙箱下无法被确认。

先使用独立 UID 1、PR_SET_DUMPABLE=0 的自有回环监听进程和随机 transient systemd 单元复现。探针读取冻结的能力服务属性，在同样 /proc、能力边界、只读 home/system 和 NoNewPrivileges 下实际运行 ss；只输出可见性布尔值，监听内容/系统地址不输出。带 default /proc 与 CAP_SYS_PTRACE 的正对照必须先成功，夹具不可启动或无法清理不能冒充 RED。

后续 GREEN 仅调整所需 /proc 访问和 ptrace 检查能力，保留 ProcSubset=pid、空 AmbientCapabilities、NoNewPrivileges 与其余沙箱限制；不为尚未接通的 account 能力扩大 home 读取。测试只创建本次随机 transient 单元，完整等待 listener/检查进程并核自动收集；不安装正式服务、不修改现有 SSH、防火墙、用户或权限。所有旧失败、限定额度与 CAP-10 真机终验仍保留。

首轮 native10894 完整 exit1，因探针假设 /usr/bin 工具路径而尚未创建 listener/单元，不能当成漏洞 RED。只读预检确认构建机 systemctl/ss 位于 /bin，systemd245 未达到项目249最低版本；探针改为核验现有 root-owned 绝对工具路径和支持版本，将在已有受支持测试机继续，不安装全局工具或改变构建机系统。失败记录保留。

修正后的探针语法及两源冻结已在 Linux 构建机通过；原单元与探针两文件 SHA 在已有 systemd255 测试机再次核验。capability-proc-vps-red-retry1-20261120 完整 exit1：正对照实际能看到非 dumpable UID1 监听进程，原配置确实看不到所有者。每个随机 transient 单元已自动收集、监听子进程完整退出，owned_proc_probe_cleanup=pass，属于真实预期 RED；没有修改正式 SSH/防火墙或系统用户。

GREEN 将单元 ProtectProc 改为 default，CapabilityBoundingSet 仅追加 CAP_SYS_PTRACE，其余限制保持。探针验证的是冻结单元中的 /proc/能力与只读/NoNewPrivileges 属性，完整能力服务全部沙箱和真实业务部署仍随 CAP-10 终验检查；当前不勾完成，先收受支持测试机 GREEN 与 Linux 受影响检查、独立复核及组合集成。
