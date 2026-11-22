// SPDX-License-Identifier: Apache-2.0

// Package coreapi 定义独立版本化的 Core Intent v2 多协议完整快照。
//
// Decode 严格解析 JSON，Validate 检查联合类型、资源上限与端口重叠。
// 模型不解析 DNS、不访问文件、不揭示秘密，也不宣称某协议通过运行门禁。
// FromV1 只生成显式迁移候选；宿主继续分别保存 desired 与 running revision。
package coreapi
