// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/qwq-panel/qwq/internal/storage"
)

// ============================================================================
//  插件 token 摘要（PRIV-05，ADR-0013）
// ----------------------------------------------------------------------------
//  安装 unit 时 controller 生成 token 交给 root helper 落盘；数据库只存
//  SHA-256。hostsvc 每次调用都拿插件出示的 token 与这里的摘要做常量时间比较。
// ============================================================================

// ErrNoPluginToken reports a plugin without a recorded token digest, for
// example one installed before ADR-0013. Its host calls are rejected until it
// is reinstalled.
var ErrNoPluginToken = errors.New("controller: the plugin has no recorded token")

// PluginTokens stores the token digest of each installed plugin.
type PluginTokens struct {
	DB *storage.DB
}

// Put records sha256(token) for pluginID, replacing an earlier digest.
func (p PluginTokens) Put(ctx context.Context, pluginID string, token []byte) error {
	if p.DB == nil || len(token) == 0 {
		return errors.New("controller: plugin credential storage or material is unavailable")
	}
	sum := sha256.Sum256(token)
	return p.DB.Update(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO plugin_credentials (plugin_id, token_sha256, issued_at)
			VALUES (?, ?, ?)
			ON CONFLICT (plugin_id) DO UPDATE
			   SET token_sha256 = excluded.token_sha256, issued_at = excluded.issued_at`,
			pluginID, hex.EncodeToString(sum[:]), storage.FormatTime(tx.Now()))
		return err
	})
}

// Digest returns the recorded SHA-256 of pluginID's token.
func (p PluginTokens) Digest(ctx context.Context, pluginID string) ([]byte, error) {
	if p.DB == nil {
		return nil, ErrNoPluginToken
	}
	var digest string
	err := p.DB.Reader().QueryRowContext(ctx,
		`SELECT token_sha256 FROM plugin_credentials WHERE plugin_id = ?`, pluginID).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNoPluginToken, pluginID)
	}
	if err != nil {
		return nil, err
	}
	return decodePluginDigest(digest)
}

// ======================== 同一 saga 的两个摘要槽 ========================

// BeginRotationTx 与新 saga 的插入同事务，仅固定一次原进程凭据。
// Put 只替换当前槽，故同阶段重试不会挤掉仍存活的原上一槽。
func (p PluginTokens) BeginRotationTx(ctx context.Context, tx *storage.Tx, pluginID string) error {
	if p.DB == nil || tx == nil {
		return errors.New("controller: plugin credential transaction is unavailable")
	}
	_, err := tx.ExecContext(ctx, `UPDATE plugin_credentials SET prev_token_sha256 = token_sha256 WHERE plugin_id = ?`, pluginID)
	return err
}

// FinishRotationTx 仅在实际进程已对齐后的健康终态事务清理上一槽。
func (p PluginTokens) FinishRotationTx(ctx context.Context, tx *storage.Tx, pluginID string) error {
	if p.DB == nil || tx == nil {
		return errors.New("controller: plugin credential transaction is unavailable")
	}
	_, err := tx.ExecContext(ctx, `UPDATE plugin_credentials SET prev_token_sha256 = '' WHERE plugin_id = ?`, pluginID)
	return err
}

// Digests 用同一读取快照返回最多两个摘要；上一槽仅在本插件有运行中 saga
// 时可用。FAILED 或历史残留不延长认证窗口，也不借其他插件的 saga 放行。
func (p PluginTokens) Digests(ctx context.Context, pluginID string) ([][]byte, error) {
	if p.DB == nil {
		return nil, ErrNoPluginToken
	}
	var current, previous string
	err := p.DB.Reader().QueryRowContext(ctx, `SELECT c.token_sha256,
		CASE WHEN EXISTS (SELECT 1 FROM plugin_update_sagas s WHERE s.plugin_id = c.plugin_id AND s.state = 'RUNNING')
		THEN c.prev_token_sha256 ELSE '' END FROM plugin_credentials c WHERE c.plugin_id = ?`, pluginID).Scan(&current, &previous)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoPluginToken
	}
	if err != nil {
		return nil, err
	}
	digest, err := decodePluginDigest(current)
	if err != nil {
		return nil, err
	}
	digests := [][]byte{digest}
	if previous != "" && previous != current {
		digest, err := decodePluginDigest(previous)
		if err != nil {
			return nil, err
		}
		digests = append(digests, digest)
	}
	return digests, nil
}

func decodePluginDigest(value string) ([]byte, error) {
	digest, err := hex.DecodeString(value)
	if err != nil || len(digest) != sha256.Size {
		return nil, errors.New("controller: the plugin credential digest is invalid")
	}
	return digest, nil
}
