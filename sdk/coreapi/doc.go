// SPDX-License-Identifier: Apache-2.0

// Package coreapi 定义面板自有的 Core Intent v1。
//
// Decode 只解析严格 JSON；Validate 只检查语义。两者均不解析 DNS、不访问文件、
// 不启动进程、不揭示秘密。配置必须是完整快照；revision 由宿主管理。
// 首版支持单个 VLESS / RAW / Vision / REALITY 入站与 direct 出站。
package coreapi
