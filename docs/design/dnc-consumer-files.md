# DNC 消费者证书文件后端

`internal/prerequisites/consumerfiles` 是独立的 Linux 文件后端。它从宿主已确认的 plugin/default StateDirectory FD 保存证书材料和完整许可快照，提供 Stage、按完整 Proof 的 Load、单 current CAS 和精确前代。它不授予消费权限，不返回 Healthy，也没有替代真实部署、续期或 H2 验收。

## 材料与许可分别保存

```text
<可信 state 根>/tls/bindings/<binding ID>/
  current.json                         # 唯一切换点：完整 active + previous
  generations/
    gN/
      fullchain.pem
      privkey.pem
      material.json                    # 完整材料范围与两份字节摘要
      proofs/
        p-<PolicyRevision SHA256>.json # 独立完整 HostBinding + 两份摘要
```

目录精确 0700，所有材料和元数据精确 0600，UID/GID 继承可信 state 根 FD 的实际 backing owner。`Consumer.ProfileID` 仍是逻辑 profile，不能作为 systemd 实例目录。New 通过传入 os.Root 的 Open(".") 取得独立 FD；传入句柄和 Store 各自负责关闭，已开始调用持有独立 FD，不被 Close 中途关闭。

逐层 openat/NOFOLLOW 后 fstat 校验目录关联、设备、属主和 mode；普通文件须单硬链接、有界且读取稳定。current 的旧打开 FD 被原子替换后可以 nlink=0，材料和许可快照没有这个例外。现存不安全 inode 不会被 chmod/chown 修正。

Stage 首次在随机临时代写链、私钥、material.json 和首个完整许可，再 NOREPLACE 发布 gN。文件、首许可的直接父目录 proofs、临时代和 generations 均按顺序 fsync。已有 gN 只在完整材料范围和两份摘要相同的情况下复用；新的许可单独 NOREPLACE 留存，不覆盖原材料或旧许可。

Load 按宿主可信 wanted 固定 gN，核完整许可快照、材料范围及两份实际 PEM 字节摘要。材料记录排除 PolicyRevision，但它自身不能补出许可；缺失或伪造的快照会拒绝。current 和磁盘快照都是文件事实，不能升级成实时授权来源。

同绑定使用独立打开目录 FD 的可取消 flock，首次容器目录创建由短根锁串行。current 和新增许可共用私有元数据发布器：O_EXCL 临时文件、mode/owner/fsync、内容及 inode 重核、目录边围栏和单 rename。许可使用 NOREPLACE，current 在完整前代 CAS 成功后替换。rename 后取消仍完成持久化围栏，失败带 Uncertain；元数据清理只处理仍关联本次 O_EXCL FD 的名字。

## 为什么修改冻结草稿

1. 私钥输入校验缺口：标准 TLS 配对器实际接受了首尾垃圾、重复块、损坏首块和 PEM header。五项真实 RED 后，增加 `tlsmgr.ValidatePrivateKeyPEM` 薄入口，复用原严格解析器，不复制解析代码；坏输入在任何目录或材料写入前拒绝。
2. P1 真实重授权冲突：新受理的 ReserveBinding 保留稳定 ID 并 Version++，PolicyRevision 随之变化；Manager 允许同一 generation 再绑定。原 gN/proof.json 固定完整旧许可，第二次合法 Stage 必然冲突。已将材料与许可快照分开，并用两个真实受理 operation、同一份签名材料证明修复。
3. P2 首许可目录项未同步：首个许可文件新增后，需要 fsync 其直接父目录 proofs，单独同步上层 generation 不足以覆盖它。顺序审查发现后已补齐；没有把审查结论写成 crash 故障注入实测。

Proof 的字符串、Go 格式和 slog 表示均脱敏；私钥副本用后清除。公开 DTO 没有新增材料、摘要或文件路径。非 Linux 明确 BACKEND_REQUIRED，无权限弱化替代。

## 实际 Linux 验证

| 阶段 | 完整结果 |
|---|---|
| dnc-consumer-files-red-20261121 | exit1：明确缺少 Store/Proof 等生产实现，原失败保留 |
| dnc-consumer-files-green-first-20261121 | exit0：原边界测试、真实 root backing owner PASS |
| dnc-consumer-private-pem-red-20261121 | exit1：五类坏私钥被原草稿接受 |
| dnc-consumer-files-final-green-20261121 | 修复后定向及三包普通全过；因运行器 CGO_ENABLED=0 无法启动 race，完整 exit1，静态/lint/build 未执行 |
| dnc-consumer-files-cgo-retry1-20261121 | race、vet/staticcheck 过；秘密检查命中固定损坏 PEM 测试文本，完整 exit1，build 未执行 |
| dnc-consumer-regrant-red-20261121 | 两个真实受理 operation 得到同代新许可，第二次 Stage 真实冲突，完整 exit1 |
| dnc-consumer-regrant-green-first-20261121 | exit0：同一真实回归 0.530s、27 个 consumerfiles 命名测试的完整普通 2.042s、lint 过 |
| dnc-consumer-regrant-final-green-20261121 | P2 修复后的完整 exit0；以下门禁全部通过 |

最终实际 UID0 的 backing owner 定向 PASS 0.026s；四包普通 consumerfiles/tlsmgr/certificates/hostauth 为 1.703s/0.233s/0.450s/23.564s；三包 race 为 3.775s/1.511s/221.878s。相关 vet/staticcheck、repo_lint 的四组检查和 CLI 构建全过。race 显式 CGO_ENABLED=1，损坏 PEM 负例从运行时 block.Type 生成，没有关闭秘密检查规则。

回归包括：同代重试与不可换材料、完整材料范围和许可失配、双实例两代/同代多许可竞争只有一个 CAS 胜者、反复切换按固定证明读取不混 pair、精确回滚、材料不能补缺失许可、每层目录及材料/许可的 symlink/hardlink/FIFO/特殊文件/mode、严格有界元数据、取消锁等待和 FD 收尾、输入根生命周期、实际 root→nobody owner 移交与日志脱敏。

所有失败、源码冻结清单、入口、完整日志和格式归档保留在当前 DNC 克隆 `.cache/dnc-consumer-*`。最终 15 源冻结清单 SHA256 `8098634b05e0d2dfd3472020ae62a8f0e6aa34ccd8569588a0ea8fc7680a7f8c`；14 Go/112640 bytes 格式归档 `ca36d4953a063b779e72ec2d50fce85381ebef4fafccde36ff8457f473dcadcc`，已按成员/token/父路径/非 reparse 守卫严格恢复。恢复后 14 Go 清单 `.cache/dnc-consumer-files-final-go-20261121.json`，SHA256 `811f04852bc0c149a6eda70abbdbdb75d8d07cd2c9fdf5c748d7b078485b7840`。

Root 完整独立复核及唯一既有代理只读复核均已完成，当前组件没有遗留确定 P0/P1/P2。未开启开发服务，本轮所有 exec/格式恢复 session 已收终态，增量同步没有 full 回退。

## 交接边界

0600 的消费者属主仍能写文件；完整性依赖宿主保存的 wanted、受控读取和独立实时授权。no-op 返回的 previous 也是磁盘事实，必须与宿主账本比较后才用于回滚。

先前真实 StateDirectory 只证明 legacy owner 的 0600 可读，mapped=false。idmap namespace、crash/fsync 故障注入、窄特权 helper 固定读写根与可信 FD 取得、私有部署日志/当前许可/References 删除排他、真实 reload/健康/回滚、续期 runtime/serve 装配和双插件/H2 都仍未验证。后续复用 Vault.LoadMaterial 与 Authority.ConfirmConsumerBinding，不能凭这个组件勾完整 Track01、真实连接或 24 小时验收。

用户要求本轮跑完后交接，由接手人继续上述工作；原 perf Go 真机步骤保持延期，前端风格和 agent/CLI 适配分工、旧 WIP 和迁移序列保持。
