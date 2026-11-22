# 候选包许可证与对应源码

发布模式补充：`GOWORK=off` 实际链接 `golang.org/x/net v0.60.0`，源码 h1 已与二进制和模块锁核验。该版本的 LICENSE/PATENTS 与已保留原文完全一致，无重复文件。精确清单现覆盖47个版本身份；单次构建仍只记录实际链接的46项外部身份。补充原始归档 SHA256：f7007f4ca0288c53f0e66bbdee807c97798a527c14866eb31c8a8efe39650fae。

| 补充模块 | 版本 | 许可 | 对应源码 |
|---|---|---|---|
| golang.org/x/net | v0.60.0 | BSD-3-Clause | https://proxy.golang.org/golang.org/x/net/@v/v0.60.0.zip |

本目录保留实际链接模块的许可证、版权、PATENTS、NOTICE 和 AUTHORS 原文。相同字节按 SHA256 保存一次；`attestations/dependencies.lock.json` 关联每个精确路径、版本、h1、原文件名和保留文件摘要。分类是模块级汇总，SBOM 的 filesAnalyzed=false。

驱动采用 AGPL-3.0-only，本地 SDK 采用 Apache-2.0。Xray 为 v26.11.9，提交 676eaf66f8f05d4d558ee7a74b4736623d3feeb9，核心摘要 e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d。驱动 Go 许可由本次工具链保留；上游核心 Go 1.27.3 的官方 BSD-3-Clause 许可单独保留。

对应源码：

- Xray 完整原源码：[固定提交归档](https://github.com/XTLS/Xray-core/archive/676eaf66f8f05d4d558ee7a74b4736623d3feeb9.tar.gz)。MPL 许可位于 MPL-2.0.txt。
- 修改的统计 wire 子集随包放在 sources/stats-wire，包含 proto、生成文件和生成/来源说明；外围驱动仍采用 AGPL。
- 各库原源码的精确版本下载链接见下表；h1 校验和记录在依赖清单中，可用 go mod download 核验。REALITY 与 gopher-luar 的 MPL 原文及对应源码链接都保留。
- juju/ratelimit 采用 LGPL-3.0-only WITH LGPL-3.0-linking-exception。例外原文与 [SPDX 官方例外](https://spdx.org/licenses/LGPL-3.0-linking-exception.html) 完整文本一致；LGPL 原文与完整 GPLv3 基础条款均保留。

ghodss/yaml、go-toml、compress、REALITY、yaml.v2 含多种源文件许可，组合表达式保留各自条件。嵌套通知及 quic-go 资产政策原文也保留；构建包只收集运行程序和许可材料。

## 实际模块清单

| 模块 | 实际版本 | 模块许可汇总 | 对应源码 |
|---|---|---|---|
| github.com/apernet/quic-go | v0.61.1-0.20260806010916-184d081eef3e | MIT | [源码](https://proxy.golang.org/github.com/apernet/quic-go/@v/v0.61.1-0.20260806010916-184d081eef3e.zip) |
| github.com/ghodss/yaml | v1.0.1-0.20220118164431-d8423dcdf344 | BSD-3-Clause AND MIT | [源码](https://proxy.golang.org/github.com/ghodss/yaml/@v/v1.0.1-0.20220118164431-d8423dcdf344.zip) |
| github.com/google/gopacket | v1.1.19 | BSD-3-Clause | [源码](https://proxy.golang.org/github.com/google/gopacket/@v/v1.1.19.zip) |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause | [源码](https://proxy.golang.org/github.com/google/uuid/@v/v1.6.0.zip) |
| github.com/gorilla/websocket | v1.5.3 | BSD-2-Clause | [源码](https://proxy.golang.org/github.com/gorilla/websocket/@v/v1.5.3.zip) |
| github.com/huin/goupnp | v1.2.0 | BSD-2-Clause | [源码](https://proxy.golang.org/github.com/huin/goupnp/@v/v1.2.0.zip) |
| github.com/jackpal/go-nat-pmp | v1.0.2 | Apache-2.0 | [源码](https://proxy.golang.org/github.com/jackpal/go-nat-pmp/@v/v1.0.2.zip) |
| github.com/juju/ratelimit | v1.0.2 | LGPL-3.0-only WITH LGPL-3.0-linking-exception | [源码](https://proxy.golang.org/github.com/juju/ratelimit/@v/v1.0.2.zip) |
| github.com/klauspost/compress | v1.20.1 | Apache-2.0 AND BSD-3-Clause AND MIT | [源码](https://proxy.golang.org/github.com/klauspost/compress/@v/v1.20.1.zip) |
| github.com/klauspost/cpuid/v2 | v2.4.2 | MIT | [源码](https://proxy.golang.org/github.com/klauspost/cpuid/v2/@v/v2.4.2.zip) |
| github.com/koron/go-ssdp | v0.0.4 | MIT | [源码](https://proxy.golang.org/github.com/koron/go-ssdp/@v/v0.0.4.zip) |
| github.com/libp2p/go-nat | v1.0.1-0.20250821073202-01afc089f138 | Apache-2.0 | [源码](https://proxy.golang.org/github.com/libp2p/go-nat/@v/v1.0.1-0.20250821073202-01afc089f138.zip) |
| github.com/libp2p/go-netroute | v0.2.1 | BSD-3-Clause | [源码](https://proxy.golang.org/github.com/libp2p/go-netroute/@v/v0.2.1.zip) |
| github.com/miekg/dns | v1.1.73 | BSD-3-Clause | [源码](https://proxy.golang.org/github.com/miekg/dns/@v/v1.1.73.zip) |
| github.com/molecule-man/go-brrr | v1.2.0 | MIT | [源码](https://proxy.golang.org/github.com/molecule-man/go-brrr/@v/v1.2.0.zip) |
| github.com/pelletier/go-toml | v1.9.5 | Apache-2.0 AND MIT | [源码](https://proxy.golang.org/github.com/pelletier/go-toml/@v/v1.9.5.zip) |
| github.com/pion/dtls/v3 | v3.1.5 | MIT | [源码](https://proxy.golang.org/github.com/pion/dtls/v3/@v/v3.1.5.zip) |
| github.com/pion/logging | v0.2.4 | MIT | [源码](https://proxy.golang.org/github.com/pion/logging/@v/v0.2.4.zip) |
| github.com/pion/stun/v3 | v3.1.7 | MIT | [源码](https://proxy.golang.org/github.com/pion/stun/v3/@v/v3.1.7.zip) |
| github.com/pion/transport/v4 | v4.1.0 | MIT | [源码](https://proxy.golang.org/github.com/pion/transport/v4/@v/v4.1.0.zip) |
| github.com/pires/go-proxyproto | v0.16.0 | Apache-2.0 | [源码](https://proxy.golang.org/github.com/pires/go-proxyproto/@v/v0.16.0.zip) |
| github.com/quic-go/qpack | v0.6.0 | MIT | [源码](https://proxy.golang.org/github.com/quic-go/qpack/@v/v0.6.0.zip) |
| github.com/refraction-networking/utls | v1.8.3-0.20261108164504-a13c59ffe98b | BSD-3-Clause | [源码](https://proxy.golang.org/github.com/refraction-networking/utls/@v/v1.8.3-0.20261108164504-a13c59ffe98b.zip) |
| github.com/robfig/cron/v3 | v3.0.1 | MIT | [源码](https://proxy.golang.org/github.com/robfig/cron/v3/@v/v3.0.1.zip) |
| github.com/santhosh-tekuri/jsonschema/v6 | v6.0.3 | Apache-2.0 | [源码](https://proxy.golang.org/github.com/santhosh-tekuri/jsonschema/v6/@v/v6.0.3.zip) |
| github.com/vishvananda/netlink | v1.3.1 | Apache-2.0 | [源码](https://proxy.golang.org/github.com/vishvananda/netlink/@v/v1.3.1.zip) |
| github.com/vishvananda/netns | v0.0.5 | Apache-2.0 | [源码](https://proxy.golang.org/github.com/vishvananda/netns/@v/v0.0.5.zip) |
| github.com/wlynxg/anet | v0.0.5 | BSD-3-Clause | [源码](https://proxy.golang.org/github.com/wlynxg/anet/@v/v0.0.5.zip) |
| github.com/xtls/reality | v0.0.0-20261108101329-4bb46b2afd8b | BSD-3-Clause AND MPL-2.0 | [源码](https://proxy.golang.org/github.com/xtls/reality/@v/v0.0.0-20261108101329-4bb46b2afd8b.zip) |
| github.com/yuin/gopher-lua | v1.1.2 | MIT | [源码](https://proxy.golang.org/github.com/yuin/gopher-lua/@v/v1.1.2.zip) |
| go4.org/netipx | v0.0.0-20231129151722-fdeea329fbba | BSD-3-Clause | [源码](https://proxy.golang.org/go4.org/netipx/@v/v0.0.0-20231129151722-fdeea329fbba.zip) |
| golang.org/x/crypto | v0.58.0 | BSD-3-Clause | [源码](https://proxy.golang.org/golang.org/x/crypto/@v/v0.58.0.zip) |
| golang.org/x/crypto/x509roots/fallback | v0.0.0-20261020153306-9f2b28d4331a | BSD-3-Clause | [源码](https://proxy.golang.org/golang.org/x/crypto/x509roots/fallback/@v/v0.0.0-20261020153306-9f2b28d4331a.zip) |
| golang.org/x/exp | v0.0.0-20240506185415-9bf2ced13842 | BSD-3-Clause | [源码](https://proxy.golang.org/golang.org/x/exp/@v/v0.0.0-20240506185415-9bf2ced13842.zip) |
| golang.org/x/net | v0.61.0 | BSD-3-Clause | [源码](https://proxy.golang.org/golang.org/x/net/@v/v0.61.0.zip) |
| golang.org/x/net | v0.62.0 | BSD-3-Clause | [源码](https://proxy.golang.org/golang.org/x/net/@v/v0.62.0.zip) |
| golang.org/x/sync | v0.24.0 | BSD-3-Clause | [源码](https://proxy.golang.org/golang.org/x/sync/@v/v0.24.0.zip) |
| golang.org/x/sys | v0.49.0 | BSD-3-Clause | [源码](https://proxy.golang.org/golang.org/x/sys/@v/v0.49.0.zip) |
| golang.org/x/text | v0.43.0 | BSD-3-Clause | [源码](https://proxy.golang.org/golang.org/x/text/@v/v0.43.0.zip) |
| golang.zx2c4.com/wireguard | v0.0.0-20250521234502-f333402bd9cb | MIT | [源码](https://proxy.golang.org/golang.zx2c4.com/wireguard/@v/v0.0.0-20250521234502-f333402bd9cb.zip) |
| google.golang.org/genproto/googleapis/rpc | v0.0.0-20260817212433-ac3dfec99bb1 | Apache-2.0 | [源码](https://proxy.golang.org/google.golang.org/genproto/googleapis/rpc/@v/v0.0.0-20260817212433-ac3dfec99bb1.zip) |
| google.golang.org/grpc | v1.85.0 | Apache-2.0 | [源码](https://proxy.golang.org/google.golang.org/grpc/@v/v1.85.0.zip) |
| google.golang.org/protobuf | v1.36.12 | BSD-3-Clause | [源码](https://proxy.golang.org/google.golang.org/protobuf/@v/v1.36.12.zip) |
| gopkg.in/yaml.v2 | v2.4.0 | Apache-2.0 AND MIT | [源码](https://proxy.golang.org/gopkg.in/yaml.v2/@v/v2.4.0.zip) |
| layeh.com/gopher-luar | v1.0.11 | MPL-2.0 | [源码](https://proxy.golang.org/layeh.com/gopher-luar/@v/v1.0.11.zip) |
| lukechampine.com/blake3 | v1.4.1 | MIT | [源码](https://proxy.golang.org/lukechampine.com/blake3/@v/v1.4.1.zip) |
