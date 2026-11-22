// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"
	"encoding/json"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	certificatesv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/certificates/v1"
)

// ======================== 私有任务收据；显式来源不等于可恢复的运行对象 ========================

type taskOrigin struct {
	PluginID    string `json:"plugin_id"`
	InstanceID  string `json:"instance_id"`
	OperationID string `json:"operation_id"`
	Operation   string `json:"operation"`
	Subject     string `json:"subject"`
}

type taskRecord struct {
	Version          uint32              `json:"version"`
	ID               string              `json:"id"`
	Kind             TaskKind            `json:"kind"`
	Origin           hostauth.Invocation `json:"-"`
	SavedOrigin      taskOrigin          `json:"origin"`
	CertificateID    string              `json:"certificate_id"`
	AttemptID        string              `json:"attempt_id"`
	ExpectedRevision string              `json:"expected_revision"`
	State            string              `json:"state"`
	Stage            string              `json:"stage"`
	Percent          uint32              `json:"percent"`
	ErrorCode        string              `json:"error_code,omitempty"`
	RetryAt          time.Time           `json:"retry_at,omitempty"`
	CreatedAt        time.Time           `json:"created_at"`
}

func taskView(record taskRecord, revision string) *certificatesv1.TaskView {
	retry := ""
	if !record.RetryAt.IsZero() {
		retry = record.RetryAt.UTC().Format(time.RFC3339Nano)
	}
	return &certificatesv1.TaskView{Id: record.ID, CertificateId: record.CertificateID, Status: record.State, Stage: record.Stage,
		Percent: record.Percent, ErrorCode: record.ErrorCode, RetryAt: retry, Revision: revision}
}

func taskKey(id string) string { return "task/" + id }

func validTaskStage(stage string) bool {
	switch stage {
	case "queued", "starting", "completed", "validating", "authorizing", "generating_key", "publishing_dns", "waiting_dns", "verifying", "issuing", "validating_certificate", "persisting_generation", "cleaning_dns", "deploying":
		return true
	}
	return false
}

func validTaskErrorCode(code string) bool {
	if len(code) > 64 {
		return false
	}
	for _, character := range code {
		if character != '_' && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func (m *Tasks) loadTask(ctx context.Context, id string) (taskRecord, string, bool, error) {
	if m == nil || m.repository == nil || !names.ID(id) {
		return taskRecord{}, "", false, fault.New("VALIDATION_FAILED", "任务查询后端或 ID 无效")
	}
	entry, found, err := m.repository.Get(ctx, taskKey(id))
	if err != nil || !found {
		return taskRecord{}, "", found, err
	}
	defer clear(entry.Value)
	var record taskRecord
	if !hostauth.DecodePersistedObject(entry.Value, &record, 64<<10) || record.Version != 1 || record.ID != id ||
		!names.ID(record.CertificateID) || !names.ID(record.AttemptID) || record.ExpectedRevision == "" || len(record.ExpectedRevision) > 128 || record.CreatedAt.IsZero() ||
		entry.Revision == "" || len(entry.Revision) > 128 || !validTaskStage(record.Stage) || !validTaskErrorCode(record.ErrorCode) ||
		record.Percent > 100 || taskOperation(record.Kind) != record.SavedOrigin.Operation || record.SavedOrigin.PluginID != "tls.certificates" ||
		record.SavedOrigin.InstanceID != "default" || !names.ID(record.SavedOrigin.OperationID) ||
		record.SavedOrigin.Subject != "plugins/tls.certificates/resources/certificates/"+record.CertificateID {
		return taskRecord{}, "", false, fault.New("STATE_INVALID", "任务收据的固定范围无效")
	}
	if record.State != "queued" && record.State != "running" && record.State != "succeeded" && record.State != "failed" && record.State != "cancelled" && record.State != "outcome_unknown" {
		return taskRecord{}, "", false, fault.New("STATE_INVALID", "任务收据状态无效")
	}
	record.Origin = hostauth.Invocation{PluginID: record.SavedOrigin.PluginID, InstanceID: record.SavedOrigin.InstanceID, OperationID: record.SavedOrigin.OperationID,
		Operation: record.SavedOrigin.Operation, Subject: record.SavedOrigin.Subject}
	return record, entry.Revision, true, nil
}

func (m *Tasks) saveTask(ctx context.Context, record taskRecord, expected string) (string, error) {
	invocation := record.Origin
	record.SavedOrigin = taskOrigin{invocation.PluginID, invocation.InstanceID, invocation.OperationID, invocation.Operation, invocation.Subject}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > 64<<10 {
		return "", fault.New("STATE_INVALID", "任务收据无法编码")
	}
	defer clear(raw)
	return m.repository.Put(ctx, taskKey(record.ID), expected, raw)
}
