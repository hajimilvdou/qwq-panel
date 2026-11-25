// SPDX-License-Identifier: AGPL-3.0-only

package apply

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// RunningRecord 是宿主 KV 的公开投影，不复制私有 Intent 指纹。
type RunningRecord struct {
	SchemaVersion    string `json:"schema_version"`
	RunningRevision  string `json:"running_revision"`
	PreviousRevision string `json:"previous_revision,omitempty"`
	ConfigDigest     string `json:"config_digest"`
	CoreVersion      string `json:"core_version"`
	Enabled          bool   `json:"enabled"`
	State            string `json:"state"`
	ResetEpoch       string `json:"reset_epoch,omitempty"`
}

type hostSnapshot struct {
	raw      []byte
	revision string
	found    bool
	record   RunningRecord
}

// SyncHost 仅供恢复激活使用，固定同步本实例 running/current，不读取配置或秘密。
// 复用原 CAS 与丢响应确认；失败不能把已启动但投影未确认的实例宣称激活成功。
func (e *Engine) SyncHost(ctx context.Context, host Host) (err error) {
	unlock, err := e.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	e.beginMutation()
	defer e.endMutation()
	defer func() {
		if err != nil {
			e.Cancel()
			if cleanupErr := e.stopBounded(ctx); cleanupErr != nil {
				err = failure("RECOVERY_FAILED", contextCause(ctx))
			}
			e.setFailure(ErrorCode(err))
		}
	}()
	if host == nil || !e.Active() {
		return failure("CORE_STATE_UNAVAILABLE", contextCause(ctx))
	}
	metadata, err := e.options.Store.Committed(ctx)
	if err != nil {
		return stateFailure(err)
	}
	if metadata == nil {
		return nil
	}
	observed := e.options.Process.Snapshot(ctx)
	if !runtimeMatches(metadata, observed) || metadata.Current.Enabled &&
		(metadata.State != "RUNNING" || observed.Epoch != metadata.ResetEpoch) {
		return failure("CORE_STATE_UNAVAILABLE", contextCause(ctx))
	}
	before, err := readHost(ctx, host)
	if err != nil {
		return err
	}
	if err := restoreHost(ctx, host, before, before.record, metadata); err != nil {
		return failure("STATE_COMMIT_FAILED", contextCause(ctx))
	}
	return nil
}

func recordFor(metadata *state.Metadata) RunningRecord {
	if metadata == nil {
		return RunningRecord{}
	}
	record := RunningRecord{SchemaVersion: "1", RunningRevision: metadata.Current.Revision, ConfigDigest: metadata.Current.Digest, CoreVersion: metadata.Current.Version, Enabled: metadata.Current.Enabled, State: metadata.State, ResetEpoch: metadata.ResetEpoch}
	if metadata.Previous != nil {
		record.PreviousRevision = metadata.Previous.Revision
	}
	return record
}

func readHost(ctx context.Context, host Host) (hostSnapshot, error) {
	ctx, cancel := boundedHostContext(ctx)
	defer cancel()
	raw, revision, found, err := host.GetState(ctx, RunningKey)
	if err != nil {
		return hostSnapshot{}, failure("CORE_STATE_UNAVAILABLE", ctx.Err())
	}
	result := hostSnapshot{raw: raw, revision: revision, found: found}
	if !found {
		return result, nil
	}
	number, err := strconv.ParseUint(revision, 10, 64)
	if err != nil || number == 0 || strconv.FormatUint(number, 10) != revision || len(raw) > state.MaxMetadataBytes || sandbox.DecodeHelperDocument(raw, &result.record) != nil || !validRecord(result.record) {
		return hostSnapshot{}, failure("SNAPSHOT_CORRUPT", nil)
	}
	return result, nil
}

func validRecord(record RunningRecord) bool {
	if record.SchemaVersion != "1" || !state.ValidRevision(record.RunningRevision) || !state.ValidDigest(record.ConfigDigest) || record.CoreVersion != state.CoreVersion || record.PreviousRevision != "" && !state.ValidRevision(record.PreviousRevision) {
		return false
	}
	if record.State != "RUNNING" && record.State != "STOPPED" && record.State != "FAILED" {
		return false
	}
	return len(record.ResetEpoch) <= 64 && validToken(record.ResetEpoch, true)
}

func sameHost(a hostSnapshot, record *RunningRecord) bool {
	if record == nil {
		return !a.found
	}
	return a.found && a.record == *record
}

func writeHost(ctx context.Context, host Host, before hostSnapshot, record RunningRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return failure("STATE_COMMIT_FAILED", nil)
	}
	option := pluginsdk.PutOption{MustNotExist: !before.found, ExpectedRevision: before.revision}
	ctx, cancel := boundedHostContext(ctx)
	defer cancel()
	_, err = host.PutState(ctx, RunningKey, data, option)
	if err != nil {
		return failure("STATE_COMMIT_FAILED", ctx.Err())
	}
	return nil
}

// restoreHost 先读取实际值，只补偿仍属于本事务的记录；不重放不确定写入。
func restoreHost(ctx context.Context, host Host, before hostSnapshot, candidate RunningRecord, restored *state.Metadata) error {
	current, err := readHost(ctx, host)
	if err != nil {
		return err
	}
	var target *RunningRecord
	if restored != nil {
		record := recordFor(restored)
		target = &record
	}
	if sameHost(current, target) {
		return nil
	}
	allowed := current.found && (current.record == candidate || before.found && current.record == before.record) || !current.found && !before.found
	if !allowed {
		return failure("RECOVERY_FAILED", nil)
	}
	callContext, cancel := boundedHostContext(ctx)
	if target == nil {
		if !current.found {
			cancel()
			return nil
		}
		err = host.DeleteState(callContext, RunningKey, current.revision)
	} else {
		err = writeHost(callContext, host, current, *target)
	}
	cancel()
	if err == nil {
		return nil
	}
	// 响应丢失后，只用重新读取的已提交事实确认补偿，不再次盲写。
	after, readErr := readHost(ctx, host)
	if readErr == nil && sameHost(after, target) {
		return nil
	}
	return errors.New("core apply: host recovery is unconfirmed")
}
