// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/config"
)

// ======================== 主密钥轮换命令（OPT-13 / Track 06） ========================

type rotateMasterKeyResult struct {
	PreviousKeyID string   `json:"previous_key_id"`
	NewKeyID      string   `json:"new_key_id"`
	RewrittenRows int64    `json:"rewritten_rows"`
	DroppedKeys   []string `json:"dropped_keys,omitempty"`
	RemainingKeys []string `json:"remaining_keys"`
}

// runRotateMasterKey 实现 `qwq rotate-master-key [--config FILE] [--drop-retired] [--batch N] [--json]`。
// 轮换顺序严格保证崩溃安全：先原子写入退役副本与新主密钥 -> 分批重加密 secrets 表 ->
// 核验 KeyUsage 归零后仅在显式 --drop-retired 时删除退役密钥文件。
func runRotateMasterKey(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rotate-master-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: sudo qwq rotate-master-key [--config FILE] [--drop-retired] [--batch 100] [--json]

Rotates the AES-256 master key in the host keyring and re-encrypts all stored
secret rows in bounded transactions. Retired keys remain on disk unless
--drop-retired is passed and zero rows still reference them.

`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	dropRetired := fs.Bool("drop-retired", false, "remove retired key files once zero rows reference them")
	batch := fs.Int("batch", 100, "rows re-encrypted per write transaction")
	asJSON := fs.Bool("json", false, "print machine-readable JSON summary")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "qwq rotate-master-key: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *batch <= 0 || *batch > 10000 {
		fmt.Fprintln(stderr, "qwq rotate-master-key: --batch must be between 1 and 10000")
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "qwq rotate-master-key: %v\n", err)
		return 1
	}

	if *dropRetired && controllerActive() {
		fmt.Fprintln(stderr, "qwq rotate-master-key: refusing --drop-retired while qwq-controller is running; run `qwq rotate-master-key` without --drop-retired first so the live controller hot-reloads the new key, then stop qwq-controller or re-run --drop-retired once safe")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})).
		With("service", "rotate-master-key")
	local, closeDB, err := openLocalDatabase(ctx, cfg, logger)
	if err != nil {
		fmt.Fprintf(stderr, "qwq rotate-master-key: %v\n", err)
		return 1
	}
	defer closeDB()

	// Acquire the rotation lock AFTER openLocalDatabase drops privileges from
	// root to the DataDir owner (qwq) so <DataDir>/keys and .lock are never
	// created owned by root:root.
	unlock, err := acquireKeyRotationLock(cfg.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "qwq rotate-master-key: %v\n", err)
		return 1
	}
	defer unlock()

	res, err := executeMasterKeyRotation(ctx, local, *batch, *dropRetired)
	if err != nil {
		fmt.Fprintf(stderr, "qwq rotate-master-key: %v\n", err)
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return 0
	}
	fmt.Fprintf(stdout, "rotated master key: %s -> %s (rewritten=%d, dropped=%d, remaining_keys=%d)\n",
		res.PreviousKeyID, res.NewKeyID, res.RewrittenRows, len(res.DroppedKeys), len(res.RemainingKeys))
	return 0
}

func executeMasterKeyRotation(ctx context.Context, local *localDatabase, batch int, dropRetired bool) (rotateMasterKeyResult, error) {
	prev := local.Keys.Primary()
	next, err := local.Keys.Rotate()
	if err != nil {
		return rotateMasterKeyResult{}, fmt.Errorf("rotate keyring: %w", err)
	}
	rewritten, err := local.Secrets.Rotate(ctx, batch)
	if err != nil {
		return rotateMasterKeyResult{}, fmt.Errorf("re-encrypt secrets: %w", err)
	}

	usage, err := local.Secrets.KeyUsage(ctx)
	if err != nil {
		return rotateMasterKeyResult{}, fmt.Errorf("verify key usage: %w", err)
	}

	var dropped []string
	if dropRetired {
		for _, id := range local.Keys.Retired() {
			if usage[id] > 0 {
				continue
			}
			if err := local.Keys.DropRetired(id); err != nil {
				return rotateMasterKeyResult{}, fmt.Errorf("drop retired key %s: %w", id, err)
			}
			dropped = append(dropped, id)
		}
	}

	return rotateMasterKeyResult{
		PreviousKeyID: prev.ID,
		NewKeyID:      next.ID,
		RewrittenRows: rewritten,
		DroppedKeys:   dropped,
		RemainingKeys: local.Keys.IDs(),
	}, nil
}
