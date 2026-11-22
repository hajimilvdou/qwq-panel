// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
)

// ArgumentProtector 在任何业务参数持久化前提取秘密，并为幂等比较生成带密钥的
// 指纹。Protect 的清理函数只回收本次新建且尚未被 operation/plan 引用的秘密。
type ArgumentProtector interface {
	Fingerprint(scope string, raw []byte) string
	Protect(ctx context.Context, schema, args []byte, owner, purpose string) ([]byte, func(context.Context) error, error)
}

// ======================== 参数保护入口 ========================
func (s *Service) argumentsSensitive(act Action, args []byte) (bool, error) {
	if act.Source != PluginSource {
		return false, nil
	}
	if err := secrets.RejectClientReferences(args); err != nil {
		return false, err
	}
	if len(act.ArgsSchema) == 0 {
		return false, nil
	}
	redacted, err := secrets.RedactForExport(act.ArgsSchema, args)
	if err != nil {
		return false, problem.New(problem.ValidationFailed, "The action's secret schema is not usable.")
	}
	sensitive := !bytes.Equal(args, redacted)
	if sensitive && s.argumentProtector == nil {
		return false, problem.New(problem.Unavailable, "Operation secret storage is not configured.")
	}
	return sensitive, nil
}

func (s *Service) protectArguments(ctx context.Context, act Action, args []byte, sensitive bool) (json.RawMessage, func(context.Context) error, error) {
	if !sensitive {
		return args, nil, nil
	}
	protected, cleanup, err := s.argumentProtector.Protect(ctx, act.ArgsSchema, args, "plugins/"+act.PluginID, "plugin.operation")
	if err == nil {
		clear(args)
	}
	return protected, cleanup, err
}

func (s *Service) discardArguments(ctx context.Context, cleanup func(context.Context) error) {
	if cleanup == nil {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := cleanup(cleanupCtx); err != nil {
		// 不记录秘密引用、参数或存储器的错误正文。
		s.log.ErrorContext(cleanupCtx, "operations: unreferenced secret cleanup failed", "code", "SECRET_CLEANUP_FAILED")
	}
}
