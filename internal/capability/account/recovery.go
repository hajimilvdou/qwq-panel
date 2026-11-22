// SPDX-License-Identifier: AGPL-3.0-only

package account

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"

	"github.com/qwq-panel/qwq/internal/capability/sshd"
)

// ======================== SSHD 登录策略收紧的公钥恢复守卫 ========================

var errNoRecoveryKey = errors.New("account: no verifiable strong SSH public key for recovery user")

type recoveryGuard struct {
	svc *Service
}

// RecoveryGuard 返回满足 sshd.RecoveryGuard 的守卫实现，彻底消除 sshd.SetLoginPolicy 的空守卫死锁。
func (s *Service) RecoveryGuard() sshd.RecoveryGuard {
	return recoveryGuard{svc: s}
}

// Check 实地核验目标交互用户存在规范权限的 .ssh/authorized_keys 且至少含一把无 no-pty 限制的强公钥。
func (g recoveryGuard) Check(ctx context.Context, user, _ string, _ sshd.Snapshot) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if g.svc == nil {
		return errNoRecoveryKey
	}
	entry, code := g.svc.lookupInteractiveUser(user)
	if code != "" {
		return errNoRecoveryKey
	}
	root, err := os.OpenRoot(entry.HomeDir)
	if err != nil {
		return errNoRecoveryKey
	}
	defer root.Close()

	dirInfo, err := root.Lstat(".ssh")
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm()&0o022 != 0 {
		return errNoRecoveryKey
	}
	fileInfo, err := root.Lstat(".ssh/authorized_keys")
	if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0o022 != 0 {
		return errNoRecoveryKey
	}
	_, keys, _, rcode := readAuthorizedKeys(entry)
	if rcode != "" {
		return errNoRecoveryKey
	}
	for _, k := range keys {
		strong := k.Type == "ed25519" || k.Type == "ecdsa" || (k.Type == "rsa" && k.Bits >= 3072)
		if !strong {
			continue
		}
		if hasNoPTY(k.Options) {
			continue
		}
		return nil
	}
	return errNoRecoveryKey
}

func hasNoPTY(opts []string) bool {
	return slices.ContainsFunc(opts, func(opt string) bool {
		return strings.EqualFold(strings.TrimSpace(opt), "no-pty")
	})
}
