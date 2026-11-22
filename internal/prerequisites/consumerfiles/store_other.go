// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package consumerfiles

import (
	"context"
	"os"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 显式的非 Linux 后端缺失 ========================

// Store 在非 Linux 平台不提供 FD/owner/flock 的弱化替代实现。
type Store struct{}

func unsupported() error {
	return fault.New("BACKEND_REQUIRED", "消费者材料文件后端需要 Linux FD、属主与目录锁能力")
}

// New 在非 Linux 平台明确返回后端缺失。
func New(*os.Root) (*Store, error) { return nil, unsupported() }

// Close 无需回收资源。
func (*Store) Close() error { return nil }

// Stage 不在非 Linux 平台落下消费者私钥。
func (*Store) Stage(context.Context, certificates.HostBinding, tlsmgr.Material) (Proof, error) {
	return Proof{}, unsupported()
}

// Activate 不在非 Linux 平台宣称完成原子切换。
func (*Store) Activate(context.Context, *Proof, Proof) (*Proof, error) {
	return nil, unsupported()
}

// Current 不把后端缺失解释为没有文件。
func (*Store) Current(context.Context, string) (*Proof, error) { return nil, unsupported() }

// Load 不提供任意路径读取替代品。
func (*Store) Load(context.Context, Proof) (tlsmgr.Material, error) {
	return tlsmgr.Material{}, unsupported()
}

// Remove 不在非 Linux 平台删除消费者材料目录。
func (*Store) Remove(context.Context, string) error { return unsupported() }
