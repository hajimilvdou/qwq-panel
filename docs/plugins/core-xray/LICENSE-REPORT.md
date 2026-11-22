# X12 依赖许可核验

状态：原始来源、46项分类、76份通知摘要与对应源码链接已核验；打包校验已编译，新签名候选及许可核验通过。完整X12、生命周期和三协议验收仍未完成。

2026-11-16 本轮实际执行：许可目录4项顶层/race回归已核验；当前源码完整门禁g25为18/18与两个模块race通过。重新构建0.1.1、0.1.2和专用故障0.1.3，实际嵌入版本/descriptor、pack/sign/verify及包读取/篡改7项事件全部通过。每包51个组件，46个精确模块身份和58份来源原文摘要一致，包内63份许可相关文件，licenseConcluded/Declared无NOASSERTION。Go1.27.3核心与Go1.27.4驱动的标准库分别记录。

自审发现Git全局换行转换会改变一份CRLF原文，导致新检出后摘要失配；已用内容地址目录的binary属性保留原始字节，58份源摘要不变、过滤变化数0，core.autocrlf=true与空白检查通过。独立修复19127da已合main。新包来源仍如实记录候选源码modified=true，真实安装/流量及整项X12保持待验收。

实际包SHA256：0.1.1为9f5f45a539f4d9a84eeaf891fc19c59891915c0d0817f5fe772802d928439e5b；0.1.2为fc32703b9e62f6a81e19984b9fd4ce31e4cdfee738854c2e4604772c40f8fa6a；故障0.1.3为1072f9285029578de1509af3bb1572a2ee1d627f1c112cb025ef3224ccd9695f。Root本机公开收据为.cache/core-xray/out/x12-license-verification.json，含各SBOM摘要与实际pass事件；旧包证据仍保留。

原正式包SBOM实际50个组件，其中46项licenseConcluded为NOASSERTION。逐项按实际ELF/SBOM记录的路径、版本和h1下载源模块，46/46 h1匹配；收集76份原始LICENSE/NOTICE/PATENTS/AUTHORS/COPYRIGHT，245,826字节。通知归档SHA256为7261f14dc8b9b125469d25692b1389237f6a0d27991f6e98c54e682ec3d2329b，46,683字节；取回后全部成员、路径、类型与摘要已核验。

内容相同的56份原文去重保存，另补GNU官方GPLv3完整条款和上游Go1.27.3官方许可，共58份许可文件。Go1.27.3由固定核心buildinfo实际核验，驱动工具链为Go1.27.4，SBOM分别记录这两套标准库。LGPL链接例外原文与SPDX官方文本按空白规范化后完全一致；组合许可保留各源文件条件。

[依赖清单](../../../plugins/builtin/core.xray/attestations/dependencies.lock.json)给出精确版本/h1/原文件名/原文摘要，[分发说明与46项列表](../../../plugins/builtin/core.xray/LICENSES/README.md)给出许可和对应源码。MPL修改wire源码继续随包保留。分类是模块级，filesAnalyzed=false；嵌套原通知完整保留，不把整个模块粗标为单一MIT/BSD。

构建从本次驱动和固定核心实际buildinfo读取依赖，使用同一许可清单精确匹配路径/版本/h1，核验全部保留原文。未审查版本、校验和或未知许可会终止打包；本地SDK单独核验工作区来源，平台ABI和代理运行逻辑不受影响。

日志：x12-notice-fetch.log、x12-core-license-metadata.log。新helper/正式包测试结果、门禁与自审将在实际执行后回填，不能把数据核验当作真实客户端/生命周期通过。
