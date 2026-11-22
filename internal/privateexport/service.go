// SPDX-License-Identifier: AGPL-3.0-only

// Package privateexport 提供受限人类会话的一次性私密材料交付。
package privateexport

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

const SSHPrivateKey = "ssh.private-key"
const secretPurpose = "private.export"
const exportPrefix = "pex"
const lifetime = 5 * time.Minute
const activeLimit = 16

var actionPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
var sshSubject = regexp.MustCompile(`^account/[a-z_][a-z0-9_.-]{0,31}/keys$`)

// CreateRequest 的 subject 是资源标识，不能是文件路径或秘密引用。
type CreateRequest struct {
	Action     string `json:"action"`
	PluginID   string `json:"plugin_id"`
	InstanceID string `json:"instance_id"`
	NodeID     string `json:"node_id"`
	Purpose    string `json:"purpose"`
	Subject    string `json:"subject"`
}

type Grant struct {
	ID        string    `json:"export_id"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

// KeyMaterial 只有公开信息；加密值与内部 secret ref 永远不进入此结构。
type KeyMaterial struct {
	ExportID    string `json:"export_id,omitempty"`
	Status      string `json:"status,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	Fingerprint string `json:"fingerprint_sha256,omitempty"`
	Type        string `json:"type,omitempty"`
	Bits        uint32 `json:"bits,omitempty"`
	Revision    string `json:"revision,omitempty"`
}

// Caller 只能由宿主当前派发绑定构造，不能相信插件自报的 Actor。
type Caller struct {
	ExportID    string
	Binding     CreateRequest
	Actor       actor.Actor
	OperationID string
}

func (Caller) String() string   { return "privateexport.Caller{[REDACTED]}" }
func (Caller) GoString() string { return "privateexport.Caller{[REDACTED]}" }

type Authorization func(context.Context, actor.Actor, CreateRequest) error
type Options struct {
	DB        *storage.DB
	Secrets   *secrets.Store
	Clock     clock.Clock
	IDs       *ids.Generator
	NodeID    string
	Authorize Authorization
}
type Service struct{ opts Options }

func New(opts Options) (*Service, error) {
	if opts.DB == nil || opts.Secrets == nil || opts.Authorize == nil {
		return nil, errors.New("privateexport: database, secrets and authorization are required")
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.IDs == nil {
		opts.IDs = ids.New(opts.Clock.Now)
	}
	if opts.NodeID == "" {
		opts.NodeID = "local"
	}
	return &Service{opts: opts}, nil
}

func (s *Service) validBinding(binding CreateRequest) bool {
	return actionPattern.MatchString(binding.Action) && sandbox.ValidateID(binding.PluginID) == nil && sandbox.ValidateID(binding.InstanceID) == nil && binding.NodeID == s.opts.NodeID && binding.Purpose == SSHPrivateKey && sshSubject.MatchString(binding.Subject)
}

// Create 只准备会话交付范围，不代替生成 operation 的权限和审批。
func (s *Service) Create(ctx context.Context, act actor.Actor, request CreateRequest) (Grant, error) {
	if !s.validBinding(request) || !act.IsHumanSession() || !ids.Valid(act.ID, ids.User) || !ids.Valid(act.SessionID, ids.Session) {
		return Grant{}, problem.New(problem.PermissionDenied, "需要有效人类会话和受控导出范围")
	}
	var grant Grant
	err := s.opts.DB.Update(ctx, func(tx *storage.Tx) error {
		if err := s.session(ctx, tx, act.ID, act.SessionID); err != nil {
			return err
		}
		if err := s.opts.Authorize(ctx, act, request); err != nil {
			return err
		}
		if _, err := s.prune(ctx, tx); err != nil {
			return err
		}
		now := s.opts.Clock.Now()
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM private_exports WHERE owner_user_id=? AND status NOT IN ('CONSUMED','CANCELED') AND expires_at>?`, act.ID, storage.FormatTime(now)).Scan(&count); err != nil {
			return err
		}
		if count >= activeLimit {
			return problem.New(problem.RateLimited, "活跃私密导出达到上限，请取消未使用项")
		}
		grant = Grant{ID: s.opts.IDs.New(exportPrefix), Status: "PREPARED", ExpiresAt: now.Add(lifetime)}
		_, err := tx.ExecContext(ctx, `INSERT INTO private_exports
			(export_id,owner_user_id,session_id,action,plugin_id,instance_id,node_id,purpose,subject,status,created_at,updated_at,expires_at)
			VALUES (?,?,?,?,?,?,?,?,?,'PREPARED',?,?,?)`, grant.ID, act.ID, act.SessionID, request.Action, request.PluginID, request.InstanceID, request.NodeID, request.Purpose, request.Subject, storage.FormatTime(now), storage.FormatTime(now), storage.FormatTime(grant.ExpiresAt))
		if err != nil {
			return err
		}
		return audit(ctx, tx, act, "prepare", grant.ID, "", request.NodeID)
	})
	return grant, problemResult(err)
}

func (s *Service) Reserve(ctx context.Context, call Caller) (KeyMaterial, error) {
	var material KeyMaterial
	err := s.opts.DB.Update(ctx, func(tx *storage.Tx) error {
		entry, err := s.producer(ctx, tx, call)
		if err != nil {
			return err
		}
		if entry.Grant.Status == "PREPARED" {
			if _, err := tx.ExecContext(ctx, `UPDATE private_exports SET status='RESERVED',operation_id=?,updated_at=? WHERE export_id=?`, call.OperationID, storage.FormatTime(s.opts.Clock.Now()), call.ExportID); err != nil {
				return err
			}
			entry.Grant.Status, entry.operationID = "RESERVED", call.OperationID
			if err := audit(ctx, tx, call.Actor, "reserve", call.ExportID, call.OperationID, call.Binding.NodeID); err != nil {
				return err
			}
		}
		if entry.Grant.Status != "RESERVED" && entry.Grant.Status != "MATERIALIZED" && entry.Grant.Status != "READY" {
			return notFound()
		}
		material = entry.material
		material.ExportID, material.Status = call.ExportID, entry.Grant.Status
		return nil
	})
	return material, problemResult(err)
}

func audit(ctx context.Context, tx *storage.Tx, act actor.Actor, phase, id, operation, node string) error {
	return operations.Audit(ctx, tx, operations.AuditRecord{Actor: act, Action: "private_export." + phase, Subject: "private_exports/" + id, Outcome: operations.AuditSuccess, OperationID: operation, NodeID: node})
}
func problemResult(err error) error {
	if err == nil {
		return nil
	}
	return problem.From(err)
}
func notFound() error { return problem.New(problem.NotFound, "私密导出不可用或已过期") }
func validRevision(revision string) bool {
	_, err := hex.DecodeString(revision)
	return len(revision) == 64 && err == nil
}
