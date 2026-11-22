// SPDX-License-Identifier: AGPL-3.0-only

package main

// =============================================================================
//  localdb —— 离线运维命令（recover / setup-token）共用的数据库打开流程
// -----------------------------------------------------------------------------
//  1. 必须 root：命令在本机控制台执行，root 是"能登录这台机器"的证明。
//  2. 数据库与主密钥必须已存在：这里只读写既有数据，从不创建——以 root
//     建出来的 root 属主文件会让 controller（User=qwq）永远起不来。
//  3. 降权到数据目录属主后再打开，WAL/SHM 等新文件的属主才正确。
//  4. NoMigrate：二进制已升级而 controller 未重启时，不能替旧进程迁移库。
//  5. 离线命令签发的初始化链接有效期为 30 分钟，与控制台提示一致。
// =============================================================================

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/qwq-panel/qwq/internal/controller"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// geteuid 可在测试中替换。
var geteuid = os.Geteuid

// localDatabase 是离线命令打开的数据库与身份服务。
type localDatabase struct {
	DB       *storage.DB
	Clock    clock.Clock
	Keys     *secrets.KeyRing
	Secrets  *secrets.Store
	Identity *identity.Service
}

// openLocalDatabase 按上面四条规则打开 cfg 指向的数据库。返回的 close
// 关闭数据库；错误信息可直接展示给运维人员。
func openLocalDatabase(ctx context.Context, cfg config.Config, logger *slog.Logger) (*localDatabase, func(), error) {
	if geteuid() != 0 {
		return nil, nil, errors.New("must run as root (use sudo)")
	}
	dbPath := filepath.Join(cfg.DataDir, "qwq.db")
	keyPath := filepath.Join(cfg.DataDir, "keys", "master.key")
	for _, p := range []string{dbPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			return nil, nil, fmt.Errorf("%s: %w (start qwq-controller once to initialize the data directory)", p, err)
		}
	}
	if err := dropToOwner(cfg.DataDir); err != nil {
		return nil, nil, err
	}

	clk := clock.System{}
	gen := ids.New(clk.Now)
	db, err := storage.Open(ctx, storage.Options{
		Path:      dbPath,
		Clock:     clk,
		IDs:       gen,
		Logger:    logger,
		NoMigrate: true,
	})
	if errors.Is(err, storage.ErrPendingMigrations) {
		return nil, nil, fmt.Errorf("%w; restart qwq-controller with the new version first", err)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	keys, err := secrets.LoadKeyRing(cfg.DataDir)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("secret keys: %w", err)
	}
	sec, err := secrets.New(secrets.Options{DB: db, Keys: keys, Logger: logger})
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("secrets: %w", err)
	}
	id, err := identity.New(identity.Options{
		DB:            db,
		Clock:         clk,
		IDs:           gen,
		Logger:        logger,
		Sealer:        sec,
		Auditor:       controller.NewAuditor(),
		SetupTokenTTL: 30 * time.Minute,
	})
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("identity: %w", err)
	}
	return &localDatabase{DB: db, Clock: clk, Keys: keys, Secrets: sec, Identity: id}, func() { db.Close() }, nil
}

// dropToOwner 把进程（全部线程，Go ≥1.16）的身份切换为 dir 的属主。
// 属主就是当前用户时什么也不做。降权不可逆，进程此后不再是 root。
func dropToOwner(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	uid, gid, ok := ownerOf(fi)
	if !ok {
		return fmt.Errorf("data directory %s: owner unavailable", dir)
	}
	if uid == os.Geteuid() && gid == os.Getegid() {
		return nil
	}
	if err := syscall.Setgroups(nil); err != nil {
		return fmt.Errorf("drop supplementary groups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid %d: %w", uid, err)
	}
	return nil
}
