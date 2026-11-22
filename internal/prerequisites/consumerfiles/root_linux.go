// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
)

// ======================== 已可信 state 根的独立 FD 生命周期 ========================

const (
	directoryMode = 0o700
	materialMode  = 0o600
	directoryOpen = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fileOpen      = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	lockInterval  = 20 * time.Millisecond
)

// Store 仅持有调用方已经可信固定的 plugin/default state 根，不重新解析绝对路径。
// UID/GID 是该 FD 的实际 backing owner；其值可能是动态 UID，也可能是 idmap 的 nobody。
type Store struct {
	mu       sync.Mutex
	root     *os.File
	identity unix.Stat_t
}

// New 从给定 os.Root 取得独立目录 FD；调用方仍拥有并负责关闭传入的 os.Root。
// 根目录必须已由宿主确认属于目标 plugin/default，ProfileID 只是逻辑身份。
func New(root *os.Root) (*Store, error) {
	if root == nil {
		return nil, fault.New("CONSUMER_FILES_INVALID", "消费者材料需要已经可信固定的 state 根")
	}
	file, err := root.Open(".")
	if err != nil {
		return nil, fileFailure("CONSUMER_FILES_IO", "无法取得消费者 state 根 FD", false)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o7777 != directoryMode || stat.Nlink == 0 {
		_ = file.Close()
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "消费者 state 根不是存活的 0700 目录")
	}
	return &Store{root: file, identity: stat}, nil
}

// Close 只关闭本 Store 的根 FD；已开始的调用持有独立 FD，可正常收尾。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil
	}
	err := s.root.Close()
	s.root = nil
	if err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者材料根 FD 关闭失败", false)
	}
	return nil
}

func (s *Store) begin(ctx context.Context) (*directoryPath, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.root == nil {
		s.mu.Unlock()
		return nil, fault.New("CONSUMER_FILES_CLOSED", "消费者材料存储已关闭")
	}
	fd, err := unix.Openat(int(s.root.Fd()), ".", directoryOpen, 0)
	s.mu.Unlock()
	if err != nil {
		return nil, fileFailure("CONSUMER_FILES_IO", "无法固定消费者 state 根 FD", false)
	}
	file := os.NewFile(uintptr(fd), "consumer-state")
	stat, err := s.directoryStat(file)
	if err != nil || !sameInode(stat, s.identity) {
		_ = file.Close()
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "消费者 state 根的身份或权限已变化")
	}
	return &directoryPath{store: s, files: []*os.File{file}}, nil
}

type directoryPath struct {
	store *Store
	files []*os.File
	names []string
}

func (path *directoryPath) last() *os.File { return path.files[len(path.files)-1] }

func (path *directoryPath) close() {
	for index := len(path.files) - 1; index >= 0; index-- {
		_ = path.files[index].Close()
	}
}

func (path *directoryPath) child(ctx context.Context, name string, create bool) (*os.File, error) {
	file, err := path.store.openDirectory(ctx, path.last(), name, create)
	if err != nil {
		return nil, err
	}
	path.files = append(path.files, file)
	path.names = append(path.names, name)
	return file, nil
}

// check 重新打开每条固定目录边并比较 FD 身份；不采用 Lstat 后 Open 的检查方式。
func (path *directoryPath) check(ctx context.Context) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	for index, file := range path.files {
		stat, err := path.store.directoryStat(file)
		if err != nil {
			return err
		}
		if index == 0 {
			if !sameInode(stat, path.store.identity) {
				return fault.New("CONSUMER_FILES_UNSAFE", "消费者 state 根身份已变化")
			}
			continue
		}
		if err := path.store.directoryLink(path.files[index-1], path.names[index-1], file); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) openBinding(ctx context.Context, bindingID string, create bool) (*directoryPath, error) {
	if !bindingIDValid(bindingID) {
		return nil, fault.New("CONSUMER_FILES_INVALID", "消费者绑定 ID 不是单个安全路径分量")
	}
	path, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	if create {
		// 首次逐层 mkdir/chown 由独立根 FD 的短锁串行，避免另一个 writer 读到尚未移交的目录。
		// 进入绑定锁前释放；generations 的创建随后由绑定目录锁保护。
		if err := lockBinding(ctx, path.files[0]); err != nil {
			path.close()
			return nil, err
		}
		defer func() { _ = unix.Flock(int(path.files[0].Fd()), unix.LOCK_UN) }()
	}
	for _, name := range []string{"tls", "bindings", bindingID} {
		if _, err := path.child(ctx, name, create); err != nil {
			path.close()
			return nil, err
		}
	}
	return path, nil
}

func sameInode(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

func (s *Store) directoryStat(file *os.File) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return stat, fileFailure("CONSUMER_FILES_IO", "消费者材料目录 FD 核验失败", false)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Nlink == 0 || stat.Dev != s.identity.Dev ||
		stat.Mode&0o7777 != directoryMode || stat.Uid != s.identity.Uid || stat.Gid != s.identity.Gid {
		return stat, fault.New("CONSUMER_FILES_UNSAFE", "消费者材料目录的类型、属主或权限不符")
	}
	return stat, nil
}

func (s *Store) directoryLink(parent *os.File, name string, wanted *os.File) error {
	fd, err := unix.Openat(int(parent.Fd()), name, directoryOpen, 0)
	if err != nil {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者材料目录关联已变化")
	}
	file := os.NewFile(uintptr(fd), "consumer-directory-check")
	defer file.Close()
	actual, err := s.directoryStat(file)
	if err != nil {
		return err
	}
	expected, err := s.directoryStat(wanted)
	if err != nil || !sameInode(actual, expected) {
		return fault.New("CONSUMER_FILES_UNSAFE", "消费者材料目录关联已被替换")
	}
	return nil
}

func (s *Store) openDirectory(ctx context.Context, parent *os.File, name string, create bool) (*os.File, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, directoryOpen, 0)
	if errors.Is(err, unix.ENOENT) && create {
		created := false
		if err = unix.Mkdirat(int(parent.Fd()), name, directoryMode); err == nil {
			created = true
		} else if !errors.Is(err, unix.EEXIST) {
			return nil, fileFailure("CONSUMER_FILES_IO", "消费者材料目录创建失败", false)
		}
		fd, err = unix.Openat(int(parent.Fd()), name, directoryOpen, 0)
		if err != nil {
			return nil, fault.New("CONSUMER_FILES_UNSAFE", "新消费者材料目录无法安全固定")
		}
		file := os.NewFile(uintptr(fd), "consumer-directory")
		if created {
			if entries, err := file.ReadDir(1); !errors.Is(err, io.EOF) || len(entries) != 0 {
				_ = file.Close()
				return nil, fault.New("CONSUMER_FILES_UNSAFE", "新消费者材料目录不是空目录")
			}
			if err := s.finishNewOwner(file, true); err != nil {
				_ = file.Close()
				return nil, err
			}
			if err := syncFile(parent, false); err != nil {
				_ = file.Close()
				return nil, err
			}
		}
		if _, err := s.directoryStat(file); err != nil {
			_ = file.Close()
			return nil, err
		}
		return file, nil
	}
	if errors.Is(err, unix.ENOENT) {
		return nil, fault.New("NOT_FOUND", "消费者材料目录不存在")
	}
	if err != nil {
		return nil, fault.New("CONSUMER_FILES_UNSAFE", "消费者材料目录无法以 NOFOLLOW 打开")
	}
	file := os.NewFile(uintptr(fd), "consumer-directory")
	if _, err := s.directoryStat(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// finishNewOwner 仅用于本调用新建且仍由 writer 所有的 inode；绝不改已有 state 根。
// helper 无 CAP_FOWNER，所以必须在移交 backing owner 前完成 Fchmod。
func (s *Store) finishNewOwner(file *os.File, directory bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Dev != s.identity.Dev {
		return fault.New("CONSUMER_FILES_UNSAFE", "新材料 inode 未由当前 writer 持有")
	}
	wantedType, wantedMode := uint32(unix.S_IFREG), uint32(materialMode)
	if directory {
		wantedType, wantedMode = unix.S_IFDIR, directoryMode
	}
	if stat.Mode&unix.S_IFMT != wantedType || (directory && stat.Nlink == 0) || (!directory && stat.Nlink != 1) {
		return fault.New("CONSUMER_FILES_UNSAFE", "新材料 inode 类型或链接数不符")
	}
	if err := unix.Fchmod(int(file.Fd()), wantedMode); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "新材料权限设置失败", false)
	}
	if err := unix.Fchown(int(file.Fd()), int(s.identity.Uid), int(s.identity.Gid)); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "新材料 backing owner 设置失败", false)
	}
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil || stat.Mode&0o7777 != wantedMode ||
		stat.Uid != s.identity.Uid || stat.Gid != s.identity.Gid {
		return fault.New("CONSUMER_FILES_UNSAFE", "新材料最终属主或权限未保持")
	}
	return syncFile(file, false)
}

func syncFile(file *os.File, uncertain bool) error {
	if err := file.Sync(); err != nil {
		return fileFailure("CONSUMER_FILES_IO", "消费者材料文件或目录同步失败", uncertain)
	}
	return nil
}

// ======================== 跨 Store/进程的绑定目录锁 ========================

func lockBinding(ctx context.Context, file *os.File) error {
	for {
		if err := checkContext(ctx); err != nil {
			return err
		}
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return fileFailure("CONSUMER_FILES_IO", "消费者绑定目录加锁失败", false)
		}
		timer := time.NewTimer(lockInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return checkContext(ctx)
		case <-timer.C:
		}
	}
}
