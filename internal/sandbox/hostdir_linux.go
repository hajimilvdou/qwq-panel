// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ============================================================================
//  /run/qwq/host/<id>（PRIV-04）
// ----------------------------------------------------------------------------
//  父目录 /run/qwq/host 归 qwq：qwq 能在里面预置同名符号链接或目录。root 若按
//  路径 chown，就会把链接目标（例如 /run/qwq/plugin/<id>）交给 qwq。所以这里全程
//  用目录 fd：mkdirat → openat(O_NOFOLLOW|O_DIRECTORY) → fstat → 取回属主
//  → fchmod → 移交属主 → fstat，
//  每一步都钉在同一个 inode 上，最后一级永远不跟随链接。
// ============================================================================

// hostDirMode 是 host.sock 所在目录：agent 可写，插件组可进入，setgid 让
// hostsvc 创建的 socket 自动继承插件组。
const hostDirMode = 0o2750

// ensureHostDir 在 rt（可信的 /run/qwq 句柄）下创建 host/<id>，属主 uid、属组
// gid、权限 2750。
func ensureHostDir(rt *os.Root, id string, uid, gid int) error {
	parent, err := rt.Open(hostDirName)
	if err != nil {
		return fmt.Errorf("sandbox: opening the host channel root (install deployments/tmpfiles/qwq.conf): %w", err)
	}
	defer func() { _ = parent.Close() }()
	if fi, err := parent.Stat(); err != nil || !fi.IsDir() {
		return fmt.Errorf("sandbox: the host channel root is not a directory")
	}
	pfd := int(parent.Fd())
	if err := syscall.Mkdirat(pfd, id, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("sandbox: creating host dir %s: %w", id, err)
	}
	fd, err := syscall.Openat(pfd, id, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		// ELOOP（链接）或 ENOTDIR（文件）：qwq 预置的东西，一律拒绝。
		return fmt.Errorf("sandbox: host dir %s is not a real directory: %w", id, err)
	}
	defer func() { _ = syscall.Close(fd) }()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("sandbox: inspecting host dir %s: %w", id, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("sandbox: host dir %s is not a directory", id)
	}
	// helper 没有 CAP_FOWNER/CAP_FSETID。先钉住当前 uid/gid 设置目录 setgid，
	// 再交给目标；Linux 保留目录的 setgid。这样重装已有目录也使用同一顺序。
	if err := syscall.Fchown(fd, os.Geteuid(), os.Getegid()); err != nil {
		return fmt.Errorf("sandbox: preparing owner of host dir %s: %w", id, err)
	}
	if err := syscall.Fchmod(fd, hostDirMode); err != nil {
		return fmt.Errorf("sandbox: mode of host dir %s: %w", id, err)
	}
	if err := syscall.Fchown(fd, uid, gid); err != nil {
		return fmt.Errorf("sandbox: owner of host dir %s: %w", id, err)
	}
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("sandbox: checking final host dir %s: %w", id, err)
	}
	if st.Uid != uint32(uid) || st.Gid != uint32(gid) || st.Mode&0o7777 != hostDirMode {
		return fmt.Errorf("sandbox: host dir %s ownership or mode did not persist", id)
	}
	return nil
}
