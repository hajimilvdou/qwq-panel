// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ============================================================================
//  可信根目录（PRIV-01）
// ----------------------------------------------------------------------------
//  root helper 的攻击者模型是"以 qwq 身份执行代码的进程"。只要某一级祖先目录
//  可被 qwq 改写，它就能 rename 走 root 子目录、放一个同名符号链接，让按路径
//  调用的 RemoveAll / Chmod / Rename 落到 /etc 之类的位置。
//
//  因此 helper 的每个写操作都先经 OpenTrustedRoot 拿到 *os.Root 句柄：
//    1. 校验 path 及每一级祖先：真实目录、属主为可信 uid、组与其他用户不可写；
//    2. 打开句柄后确认它与刚校验的 inode 相同（校验与打开之间不能被替换）；
//    3. 之后所有操作都相对句柄进行，os.Root 拒绝任何逃出根的符号链接。
// ============================================================================

// TrustPolicy 决定祖先链校验的属主与终点。零值即生产策略：属主 root，一直
// 校验到 "/"。只有测试会把它改成当前用户与 t.TempDir()——测试进程不是
// root，且 /tmp 本身是全局可写的。
type TrustPolicy struct {
	// UID 是每一级祖先必须属于的用户；零值为 root。
	UID int
	// StopAt 是校验的终点（含）；空串表示 "/"。
	StopAt string
}

// OpenTrustedRoot 按生产策略打开 path。
func OpenTrustedRoot(path string) (*os.Root, error) {
	return TrustPolicy{}.Open(path)
}

// Open 校验祖先链后打开目录句柄，并确认句柄与刚校验的 inode 相同（防止
// 校验与打开之间被替换）。
func (tp TrustPolicy) Open(path string) (*os.Root, error) {
	if err := tp.check(path); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	a, err1 := r.Stat(".")
	b, err2 := os.Lstat(path)
	if err1 != nil || err2 != nil || !os.SameFile(a, b) {
		_ = r.Close()
		return nil, fmt.Errorf("sandbox: %s changed while it was being opened", path)
	}
	return r, nil
}

// check 要求 path 及其每一级祖先：真实目录（非符号链接）、属主为 tp.UID、
// 组与其他用户不可写。
func (tp TrustPolicy) check(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("sandbox: trusted root %q is not absolute", path)
	}
	stop := "/"
	if tp.StopAt != "" {
		stop = filepath.Clean(tp.StopAt)
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		uid, ok := FileOwner(fi)
		switch {
		case !ok || fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir():
			return fmt.Errorf("sandbox: %s is not a real directory", p)
		case uid != tp.UID:
			return fmt.Errorf("sandbox: %s is owned by uid %d, want %d", p, uid, tp.UID)
		case fi.Mode().Perm()&0o022 != 0:
			return fmt.Errorf("sandbox: %s is group or world writable", p)
		}
		if p == "/" || p == stop {
			return nil
		}
	}
}

// errNotRealDir 表示句柄内的某一项不是真实目录。
var errNotRealDir = errors.New("is not a real directory")

// MkdirAllIn 在 r 内创建 rel（含中间目录）并把每一级设为 mode。
// os.Root.MkdirAll 受 umask 影响，单元与 agent 依赖精确的权限，所以逐级 Chmod；
// 每一级都先 Lstat 确认是真实目录，os.Root 本身也拒绝逃逸的符号链接。
func MkdirAllIn(r *os.Root, rel string, mode fs.FileMode) error {
	if err := r.MkdirAll(rel, mode); err != nil {
		return err
	}
	fi, err := r.Lstat(rel)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("sandbox: %s %w", rel, errNotRealDir)
	}
	return r.Chmod(rel, mode)
}

// RemoveAllIn 删除 r 内的 rel，返回它此前是否存在。符号链接只删链接本身。
func RemoveAllIn(r *os.Root, rel string) (bool, error) {
	if _, err := r.Lstat(rel); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := r.RemoveAll(rel); err != nil {
		return false, err
	}
	return true, nil
}
