// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

const generationDirectoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// ======================== 只读 FD 工具：目录逐层 nofollow，文件读取有界 ========================

func closeGenerationFD(fd int) error {
	if fd < 0 {
		return nil
	}
	// Linux close 即使 EINTR 也已释放 FD；重试可能关闭已被别处复用的号码。
	return unix.Close(fd)
}

func openAbsoluteGenerationDirectory(ctx context.Context, directory string) (fd int, err error) {
	if !path.IsAbs(directory) || path.Clean(directory) != directory || strings.ContainsAny(directory, "\x00\r\n") {
		return -1, ErrGenerationIdentity
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	fd, err = unix.Open("/", generationDirectoryFlags, 0)
	if err != nil {
		return -1, err
	}
	if directory == "/" {
		return fd, nil
	}
	for _, component := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		if err := ctx.Err(); err != nil {
			return -1, errors.Join(err, closeGenerationFD(fd))
		}
		next, openErr := unix.Openat(fd, component, generationDirectoryFlags, 0)
		closeErr := closeGenerationFD(fd)
		fd = -1
		if openErr != nil {
			return -1, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			return -1, errors.Join(closeErr, closeGenerationFD(next))
		}
		fd = next
	}
	return fd, nil
}

func requireGenerationFilesystem(fd int, expected int64) error {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(fd, &stat); err != nil {
		return errors.Join(ErrGenerationIdentity, err)
	}
	if int64(stat.Type) != expected {
		return fmt.Errorf("%w: unexpected kernel filesystem", ErrGenerationIdentity)
	}
	return nil
}

func openPinnedGenerationFile(ctx context.Context, directoryFD int, leaf string) (int, error) {
	if leaf == "" || leaf == "." || leaf == ".." || strings.ContainsAny(leaf, "/\x00\r\n") {
		return -1, ErrGenerationIdentity
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	return unix.Openat(directoryFD, leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
}

func readPinnedGenerationFile(ctx context.Context, directoryFD int, leaf string, limit int) (body []byte, err error) {
	if limit <= 0 || limit > 64<<10 {
		return nil, ErrGenerationIdentity
	}
	fd, err := openPinnedGenerationFile(ctx, directoryFD, leaf)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeGenerationFD(fd)) }()
	return readGenerationFD(ctx, fd, limit)
}

func readGenerationFD(ctx context.Context, fd, limit int) ([]byte, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, ErrGenerationIdentity
	}
	var body []byte
	scratch := make([]byte, min(limit+1, 4096))
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, readErr := unix.Read(fd, scratch)
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		if n == 0 {
			return body, nil
		}
		if len(body)+n > limit {
			return nil, errors.New("sandbox: kernel identity file exceeds its read bound")
		}
		body = append(body, scratch[:n]...)
	}
}

// ======================== Boot ID：仅可信 procfs 文件或它的窄只读 bind ========================

func readGenerationBootID(ctx context.Context, bootIDPath string) (bootID string, err error) {
	if !path.IsAbs(bootIDPath) || path.Clean(bootIDPath) != bootIDPath || strings.ContainsAny(bootIDPath, "\x00\r\n") {
		return "", ErrGenerationIdentity
	}
	parentFD, err := openAbsoluteGenerationDirectory(ctx, path.Dir(bootIDPath))
	if err != nil {
		return "", errors.Join(ErrGenerationIdentity, err)
	}
	defer func() { err = errors.Join(err, closeGenerationFD(parentFD)) }()
	fd, err := openPinnedGenerationFile(ctx, parentFD, path.Base(bootIDPath))
	if err != nil {
		return "", errors.Join(ErrGenerationIdentity, err)
	}
	defer func() { err = errors.Join(err, closeGenerationFD(fd)) }()
	if err := requireGenerationFilesystem(fd, unix.PROC_SUPER_MAGIC); err != nil {
		return "", err
	}
	// 与 proc/cgroup 复用同一有界读取；完整读到 EOF，拒绝有效 UUID 后的额外字节。
	body, err := readGenerationFD(ctx, fd, 128)
	if err != nil {
		return "", errors.Join(ErrGenerationIdentity, err)
	}
	if len(body) == 0 {
		return "", ErrGenerationIdentity
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return parseGenerationBootID(string(body))
}

func parseGenerationBootID(data string) (string, error) {
	value := strings.TrimSuffix(data, "\n")
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return "", ErrGenerationIdentity
	}
	compact := strings.ReplaceAll(value, "-", "")
	if !validGenerationID(compact) {
		return "", ErrGenerationIdentity
	}
	return compact, nil
}
