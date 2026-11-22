# DNC 宿主信任根

`certificates.HostTrustRoots` 实现现有 `TrustRoots`，供 Vault 和后续消费者部署使用。public 在启动时读取系统根；staging 使用独立的 Let’s Encrypt 官方测试根，或宿主明确注入的测试根。两者不会互相扩展信任，未知类别不会回退成 public。test 保留 `tlsmgr.ValidateMaterial` 对该自签名证书的用途与专属根校验。

PEM 解析复用原严格解析器，经 `tlsmgr.ParseCertificateChain` 薄入口共享，原材料验证调用不变。根池构造与返回均克隆，32 KiB/8 根上限，拒绝损坏首块、尾部垃圾、私钥、非 CA、重复根和无效自签名。公共根使用 `CertPool.Equal` 校验空池，避免依赖废弃的 Subjects API。

## 官方公开材料

两份只含公开 CERTIFICATE 的 `.crt` 嵌入构建，运行时不联网获取根：

| 来源 | PEM SHA256 | bytes |
|---|---|---:|
| https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem | `3a5e1171e5f5c2d41522d438f225602e4236a68fb29c32399a95921a4ae80e73` | 2000 |
| https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem | `497c36c1b50c0daff30870d5908c9b97af29223d5510c5e6c24957d0cc502fb8` | 859 |

首次下载的 PowerShell Content 是 byte[]，字符串强转导致校验失败，未写入错误证书；已读取实际响应类型并正确 UTF-8 解码，旧失败保存。官方根与签名测试夹具分开，未嵌入测试私钥。

## Linux 验证

- RED `dnc-host-trust-roots-red-20261121` 完整 exit 1：新构造器尚不存在，不能把测试缺失当成已实现。
- 首 GREEN `dnc-host-trust-roots-green-20261121`：真实 public/staging 四组合、八类非法根、克隆/取消/官方根、四包普通和双包 race 均过；staticcheck 因废弃 Subjects API 返回 exit 1，lint/build 未执行，记录保留。
- `dnc-host-trust-roots-static-retry1-20261121` 完整 exit 0：同一安全回归、certificates/tlsmgr/hostauth/capability 普通 0.438s/0.309s/23.402s/2.772s；certificates/tlsmgr race 4.274s/1.582s；四包 vet/staticcheck、repo_lint 与 CLI build 通过。
- 追加真实 Vault 对接：正确类别经 AES-GCM 保存并再次 Inspect，错误类别不写材料、不推进 SQLite 水位。`dnc-host-trust-vault-integration-20261121` 四组合普通及全部 HostTrustRoots race 2.038s、lint 完整 exit 0。生产代码未再改变。
- 最终 3 Go 格式归档 `13ce8c1e84796e484aa51d2d3516ca564cafaf28b691293d0c5542299ec43459`，30720 bytes，已严格取回；成员/token/父路径/非 reparse 守卫通过。6 源冻结清单 `af67af5b91ed6c2a1de37d97a0fe85b4b6a012e4966582aa072da1dd494d8640`。

所有源码、失败、日志和格式归档保留在 `wt-dnc-plugins/.cache/dnc-host-trust-*`。没有全局依赖、Windows 工具链、开发服务器或延期中的 perf Go 探针。

## Root 复核与后续

本组件 P0/P1/P2 无遗留阻断：根配置只来自宿主，签名链真正区分类别，材料继续由原 owner/purpose 加密 Vault 管理，池的外部修改不影响已构造服务。原严格 PEM 解析和真实 Vault 路径已验证。

完整 Track01 仍继续：可信单代文件部署、真实 DynamicUser/StateDirectory 下 0600 读取、reload/健康与回滚、私有引用删除排他、续期 runtime 与启动装配、双插件和首次 H2 字节通信。当前 Root 新组件没有被描述为整条轨道已完成。
