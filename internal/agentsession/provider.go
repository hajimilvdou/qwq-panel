// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

// ============================================================================
//  Global AI providers (GAP-2, ADR-0017)
//
//  A provider is a model endpoint an administrator configured for the whole
//  installation: any owner of a session may pick one by provider_id, and a
//  session without its own endpoint uses the default one. The API key is not
//  part of the resource: it is a secret owned by ai_providers/<id> with the
//  purpose agent.native.api_key, write-only through the API, and only ever
//  decrypted by RevealOwned under exactly that owner and purpose — a planted
//  reference to any other secret fails closed. The key is bound to the address
//  it was stored for: changing base_url drops it, so a stolen session cannot
//  repoint the endpoint and harvest the key.
//
//  The provider actions of the operation surface (host.ai_providers.*) live in
//  internal/api; this file owns the rows, the secret, the resolution the native
//  core uses at turn time, and the connectivity probe behind
//  POST /api/v1/ai/providers/{id}/test.
// ============================================================================

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// providerPrefix is the TypeID prefix of a provider (ids only names the shared
// resources; this package owns its own).
const providerPrefix = "aip"

// providerKind is the only kind of the first release: an OpenAI-compatible
// chat-completions endpoint.
const providerKind = "openai_compatible"

// providerKeyPurpose is the secret purpose of a provider's API key.
const providerKeyPurpose = "agent.native.api_key"

// Bounds of the AiProvider schemas.
const (
	maxProviderName  = 64
	maxProviderModel = 128
	maxProviderURL   = 2048
)

// providerProbeTimeout bounds one connectivity probe of POST .../test.
const providerProbeTimeout = 20 * time.Second

// Audit actions written by this package for provider changes.
const (
	ActionProviderCreated  = "ai_provider.created"
	ActionProviderUpdated  = "ai_provider.updated"
	ActionProviderDeleted  = "ai_provider.deleted"
	ActionProviderKeySet   = "ai_provider.api_key.set"
	ActionProviderKeyClear = "ai_provider.api_key.clear"
)

// AIProvider is one global AI provider (OpenAPI AiProvider).
type AIProvider struct {
	ID        string
	Name      string
	Kind      string
	BaseURL   string
	Model     string
	APIKeyRef secrets.Ref
	IsDefault bool
	CreatedAt time.Time
	UpdatedAt time.Time
	Revision  string
}

// HasAPIKey reports whether the provider has a stored API key
// (OpenAPI AiProvider.has_api_key). The key itself never leaves the host.
func (p *AIProvider) HasAPIKey() bool { return p.APIKeyRef != "" }

// providerSubject is the resource.changed subject of a provider.
func providerSubject(id string) string { return "ai_providers/" + id }

// providerSecretOwner is the secret namespace of a provider's API key. Only
// this owner with providerKeyPurpose ever opens through RevealOwned.
func providerSecretOwner(id string) string { return providerSubject(id) }

// --- validation --------------------------------------------------------------

// ValidateProviderName trims and checks a provider name. The HTTP routes and
// the host action executors share it, so a bad value is a 400 before anything
// is queued and a stored argument is re-validated the same way.
func ValidateProviderName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", problem.Validation(problem.Violation{
			Pointer: "/name", Code: "REQUIRED", Message: "A name is required.",
		})
	}
	if utf8.RuneCountInString(name) > maxProviderName {
		return "", problem.Validation(problem.Violation{
			Pointer: "/name", Code: "too_long", Message: "The name is at most 64 characters.",
		})
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", problem.Validation(problem.Violation{
				Pointer: "/name", Code: "INVALID", Message: "The name must not contain control characters.",
			})
		}
	}
	return name, nil
}

// ValidateProviderModel trims and checks a model name.
func ValidateProviderModel(raw string) (string, error) {
	model := strings.TrimSpace(raw)
	if model == "" {
		return "", problem.Validation(problem.Violation{
			Pointer: "/model", Code: "REQUIRED", Message: "A model is required.",
		})
	}
	if utf8.RuneCountInString(model) > maxProviderModel {
		return "", problem.Validation(problem.Violation{
			Pointer: "/model", Code: "too_long", Message: "The model is at most 128 characters.",
		})
	}
	for _, r := range model {
		if unicode.IsControl(r) {
			return "", problem.Validation(problem.Violation{
				Pointer: "/model", Code: "INVALID", Message: "The model must not contain control characters.",
			})
		}
	}
	return model, nil
}

// ValidateModelBaseURL checks an OpenAI-compatible endpoint address: an
// absolute http or https URL without credentials, query or fragment. The
// trailing slash is dropped. pointer names the request member in violations,
// so the session config and the provider resource share one rule.
func ValidateModelBaseURL(raw, pointer string) (string, error) {
	if raw == "" {
		return "", problem.Validation(problem.Violation{
			Pointer: pointer, Code: "REQUIRED", Message: "An endpoint address is required.",
		})
	}
	if len(raw) > maxProviderURL {
		return "", problem.Validation(problem.Violation{
			Pointer: pointer, Code: "too_long", Message: "The address is at most 2048 bytes.",
		})
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || strings.ContainsAny(raw, "?#") {
		return "", problem.Validation(problem.Violation{
			Pointer: pointer, Code: "INVALID",
			Message: "The address must be an absolute http or https URL without credentials, query or fragment.",
		})
	}
	return strings.TrimRight(raw, "/"), nil
}

// --- store -------------------------------------------------------------------

// providerColumns is the SELECT list of the provider lookups.
const providerColumns = `provider_id, name, kind, base_url, model, api_key_ref, is_default,
	created_at, updated_at, revision`

// scanProvider reads one ai_providers row.
func scanProvider(row interface{ Scan(...any) error }) (*AIProvider, error) {
	var (
		p                AIProvider
		ref              string
		def              int
		createdAt, updAt string
		revision         int64
	)
	if err := row.Scan(&p.ID, &p.Name, &p.Kind, &p.BaseURL, &p.Model, &ref, &def,
		&createdAt, &updAt, &revision); err != nil {
		return nil, err
	}
	p.APIKeyRef = secrets.Ref(ref)
	p.IsDefault = def != 0
	p.Revision = storage.Revision(revision)
	var err error
	if p.CreatedAt, err = storage.ParseTime(createdAt); err != nil {
		return nil, fmt.Errorf("agentsession: provider created_at: %w", err)
	}
	if p.UpdatedAt, err = storage.ParseTime(updAt); err != nil {
		return nil, fmt.Errorf("agentsession: provider updated_at: %w", err)
	}
	return &p, nil
}

// providerNotFound is the NOT_FOUND of a provider (OpenAPI getAIProvider).
func providerNotFound() error { return problem.New(problem.NotFound, "No such AI provider.") }

// loadProviderTx reads one provider inside a transaction.
func loadProviderTx(ctx context.Context, tx *storage.Tx, id string) (*AIProvider, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+providerColumns+` FROM ai_providers WHERE provider_id = ?`, id)
	p, err := scanProvider(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, providerNotFound()
	}
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return p, nil
}

// GetProvider returns one provider by ID.
func (s *Service) GetProvider(ctx context.Context, id string) (*AIProvider, error) {
	row := s.db.Reader().QueryRowContext(ctx, `SELECT `+providerColumns+` FROM ai_providers WHERE provider_id = ?`, id)
	p, err := scanProvider(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, providerNotFound()
	}
	if err != nil {
		return nil, problem.Wrap(err)
	}
	return p, nil
}

// ListProviders returns every provider, ordered by ID.
func (s *Service) ListProviders(ctx context.Context) ([]AIProvider, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT `+providerColumns+` FROM ai_providers ORDER BY provider_id`)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	defer rows.Close()
	out := []AIProvider{}
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, problem.Wrap(err)
		}
		out = append(out, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, problem.Wrap(err)
	}
	return out, nil
}

// providerRecord returns the provider named by id, or the default provider
// when id is empty. found=false means "neither exists"; it never reveals the
// key, so preflight can probe the configuration cheaply.
func (s *Service) providerRecord(ctx context.Context, id string) (*AIProvider, bool, error) {
	query := `SELECT ` + providerColumns + ` FROM ai_providers WHERE provider_id = ?`
	args := []any{id}
	if id == "" {
		query = `SELECT ` + providerColumns + ` FROM ai_providers WHERE is_default = 1`
		args = nil
	}
	p, err := scanProvider(s.db.Reader().QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, problem.Wrap(err)
	}
	return p, true, nil
}

// checkProviderRevision refuses a stale expected_revision.
func checkProviderRevision(expected int64, cur string) error {
	if expected <= 0 {
		return problem.Validation(problem.Violation{
			Pointer: "/expected_revision", Code: "REQUIRED",
			Message: "expected_revision is required and must be a positive revision.",
		})
	}
	if storage.Revision(expected) != cur {
		return problem.Conflict(cur)
	}
	return nil
}

// flipProviderDefault clears the is_default flag of every other provider in the
// caller's transaction. It runs before a new default is written, so the partial
// unique index never sees two defaults, and every flipped row gets its own
// resource.changed event and revision move.
func flipProviderDefault(ctx context.Context, tx *storage.Tx, exceptID string) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT provider_id FROM ai_providers WHERE is_default = 1 AND provider_id != ?`, exceptID)
	if err != nil {
		return problem.Wrap(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return problem.Wrap(err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return problem.Wrap(err)
	}
	for _, id := range ids {
		rev, err := tx.Changed(ctx, storage.Change{
			Subject: providerSubject(id), Kind: storage.Updated, Pointers: []string{"/is_default"},
		})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE ai_providers SET is_default = 0, revision = ? WHERE provider_id = ?`, rev, id); err != nil {
			return fmt.Errorf("agentsession: clear default: %w", err)
		}
	}
	return nil
}

// CreateProviderInput carries one host.ai_providers.create.
type CreateProviderInput struct {
	Actor     actor.Actor
	Name      string
	Kind      string
	BaseURL   string
	Model     string
	IsDefault bool
}

// CreateProvider inserts a provider in the caller's transaction. Making it the
// default flips the previous default in the same transaction.
func (s *Service) CreateProvider(ctx context.Context, tx *storage.Tx, in CreateProviderInput) (*AIProvider, error) {
	name, err := ValidateProviderName(in.Name)
	if err != nil {
		return nil, err
	}
	kind := in.Kind
	if kind == "" {
		kind = providerKind
	}
	if kind != providerKind {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/kind", Code: "INVALID", Message: fmt.Sprintf("kind must be %s.", providerKind),
		})
	}
	baseURL, err := ValidateModelBaseURL(in.BaseURL, "/base_url")
	if err != nil {
		return nil, err
	}
	model, err := ValidateProviderModel(in.Model)
	if err != nil {
		return nil, err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ai_providers WHERE name = ?`, name).Scan(&exists); err != nil {
		return nil, fmt.Errorf("agentsession: check provider name: %w", err)
	}
	if exists > 0 {
		return nil, &problem.Error{
			Code: problem.StateConflict, Detail: "An AI provider with this name already exists.",
		}
	}
	if in.IsDefault {
		if err := flipProviderDefault(ctx, tx, ""); err != nil {
			return nil, err
		}
	}
	now := tx.Now()
	id := tx.NewID(providerPrefix)
	def := 0
	if in.IsDefault {
		def = 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ai_providers
		(provider_id, name, kind, base_url, model, api_key_ref, is_default, created_at, updated_at, revision)
		VALUES (?, ?, ?, ?, ?, '', ?, ?, ?, 0)`,
		id, name, kind, baseURL, model, def, storage.FormatTime(now), storage.FormatTime(now)); err != nil {
		return nil, fmt.Errorf("agentsession: insert provider: %w", err)
	}
	rev, err := tx.Changed(ctx, storage.Change{Subject: providerSubject(id), Kind: storage.Created})
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE ai_providers SET revision = ? WHERE provider_id = ?`, rev, id); err != nil {
		return nil, fmt.Errorf("agentsession: set provider revision: %w", err)
	}
	if err := operations.Audit(ctx, tx, operations.AuditRecord{
		Actor: in.Actor, Action: ActionProviderCreated, Subject: providerSubject(id),
		Outcome: operations.AuditSuccess,
		Details: providerAuditDetails(map[string]any{"name": name, "is_default": in.IsDefault}),
	}); err != nil {
		return nil, err
	}
	return loadProviderTx(ctx, tx, id)
}

// UpdateProviderInput carries one host.ai_providers.update. Nil members are
// left unchanged.
type UpdateProviderInput struct {
	Actor            actor.Actor
	ProviderID       string
	ExpectedRevision int64
	Name             *string
	BaseURL          *string
	Model            *string
	IsDefault        *bool
}

// UpdateProvider applies a patch in the caller's transaction. Changing base_url
// clears the stored API key: the key is bound to the address it was entered
// for, so a changed address must not silently receive it.
func (s *Service) UpdateProvider(ctx context.Context, tx *storage.Tx, in UpdateProviderInput) (*AIProvider, error) {
	if in.Name == nil && in.BaseURL == nil && in.Model == nil && in.IsDefault == nil {
		return nil, problem.Validation(problem.Violation{
			Pointer: "/", Code: "empty",
			Message: "At least one of name, base_url, model or is_default is required.",
		})
	}
	cur, err := loadProviderTx(ctx, tx, in.ProviderID)
	if err != nil {
		return nil, err
	}
	if err := checkProviderRevision(in.ExpectedRevision, cur.Revision); err != nil {
		return nil, err
	}
	name, baseURL, model, isDefault := cur.Name, cur.BaseURL, cur.Model, cur.IsDefault
	var pointers []string
	if in.Name != nil {
		v, err := ValidateProviderName(*in.Name)
		if err != nil {
			return nil, err
		}
		if v != name {
			name, pointers = v, append(pointers, "/name")
		}
	}
	if in.BaseURL != nil {
		v, err := ValidateModelBaseURL(*in.BaseURL, "/base_url")
		if err != nil {
			return nil, err
		}
		if v != baseURL {
			baseURL, pointers = v, append(pointers, "/base_url")
		}
	}
	if in.Model != nil {
		v, err := ValidateProviderModel(*in.Model)
		if err != nil {
			return nil, err
		}
		if v != model {
			model, pointers = v, append(pointers, "/model")
		}
	}
	if in.IsDefault != nil && *in.IsDefault != isDefault {
		isDefault, pointers = *in.IsDefault, append(pointers, "/is_default")
	}
	if len(pointers) == 0 {
		return cur, nil
	}
	if name != cur.Name {
		var exists int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM ai_providers WHERE name = ? AND provider_id != ?`, name, cur.ID).Scan(&exists); err != nil {
			return nil, fmt.Errorf("agentsession: check provider name: %w", err)
		}
		if exists > 0 {
			return nil, &problem.Error{
				Code: problem.StateConflict, Detail: "An AI provider with this name already exists.",
			}
		}
	}
	clearKey := false
	if baseURL != cur.BaseURL && cur.APIKeyRef != "" {
		if s.secrets == nil {
			return nil, problem.New(problem.Unavailable, "The provider's API key cannot be removed: this host has no secret store.")
		}
		if _, err := s.secrets.DeleteOwner(ctx, tx, providerSecretOwner(cur.ID)); err != nil {
			return nil, err
		}
		clearKey = true
		pointers = append(pointers, "/has_api_key")
	}
	if isDefault && !cur.IsDefault {
		if err := flipProviderDefault(ctx, tx, cur.ID); err != nil {
			return nil, err
		}
	}
	now := tx.Now()
	ref := string(cur.APIKeyRef)
	if clearKey {
		ref = ""
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ai_providers SET
		name = ?, base_url = ?, model = ?, api_key_ref = ?, is_default = ?, updated_at = ?
		WHERE provider_id = ?`,
		name, baseURL, model, ref, providerBoolInt(isDefault), storage.FormatTime(now), cur.ID); err != nil {
		return nil, fmt.Errorf("agentsession: update provider: %w", err)
	}
	rev, err := tx.Changed(ctx, storage.Change{
		Subject: providerSubject(cur.ID), Kind: storage.Updated, Pointers: pointers,
	})
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE ai_providers SET revision = ? WHERE provider_id = ?`, rev, cur.ID); err != nil {
		return nil, fmt.Errorf("agentsession: set provider revision: %w", err)
	}
	if err := operations.Audit(ctx, tx, operations.AuditRecord{
		Actor: in.Actor, Action: ActionProviderUpdated, Subject: providerSubject(cur.ID),
		Outcome: operations.AuditSuccess,
		Details: providerAuditDetails(map[string]any{"name": name, "is_default": isDefault}),
	}); err != nil {
		return nil, err
	}
	if clearKey {
		if err := operations.Audit(ctx, tx, operations.AuditRecord{
			Actor: in.Actor, Action: ActionProviderKeyClear, Subject: providerSubject(cur.ID),
			Outcome: operations.AuditSuccess,
			Details: providerAuditDetails(map[string]any{"reason": "base_url_changed"}),
		}); err != nil {
			return nil, err
		}
	}
	return loadProviderTx(ctx, tx, cur.ID)
}

// DeleteProviderInput carries one host.ai_providers.delete.
type DeleteProviderInput struct {
	Actor            actor.Actor
	ProviderID       string
	ExpectedRevision int64
}

// DeleteProvider removes a provider and its API key in the caller's
// transaction. The default provider is refused while another provider exists,
// so a delete cannot leave the installation without a usable default by
// accident.
func (s *Service) DeleteProvider(ctx context.Context, tx *storage.Tx, in DeleteProviderInput) error {
	cur, err := loadProviderTx(ctx, tx, in.ProviderID)
	if err != nil {
		return err
	}
	if err := checkProviderRevision(in.ExpectedRevision, cur.Revision); err != nil {
		return err
	}
	if cur.IsDefault {
		var others int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM ai_providers WHERE provider_id != ?`, cur.ID).Scan(&others); err != nil {
			return fmt.Errorf("agentsession: count providers: %w", err)
		}
		if others > 0 {
			return &problem.Error{
				Code: problem.StateConflict,
				Detail: "The default AI provider cannot be deleted while other providers exist; " +
					"make another one the default first.",
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ai_providers WHERE provider_id = ?`, cur.ID); err != nil {
		return fmt.Errorf("agentsession: delete provider: %w", err)
	}
	if s.secrets != nil {
		if _, err := s.secrets.DeleteOwner(ctx, tx, providerSecretOwner(cur.ID)); err != nil {
			return err
		}
	}
	if _, err := tx.Changed(ctx, storage.Change{Subject: providerSubject(cur.ID), Kind: storage.Deleted}); err != nil {
		return err
	}
	return operations.Audit(ctx, tx, operations.AuditRecord{
		Actor: in.Actor, Action: ActionProviderDeleted, Subject: providerSubject(cur.ID),
		Outcome: operations.AuditSuccess,
		Details: providerAuditDetails(map[string]any{"name": cur.Name}),
	})
}

// SetProviderAPIKey stores (or replaces) a provider's API key. It is not an
// operation: the plaintext must not appear in an operation record or an
// idempotent replay. The secret row, api_key_ref, the resource.changed event
// and the audit row commit together.
func (s *Service) SetProviderAPIKey(ctx context.Context, act actor.Actor, id, key string) (*AIProvider, error) {
	plaintext, err := validateAPIKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	return s.writeProviderKey(ctx, act, id, plaintext)
}

// ClearProviderAPIKey removes a provider's API key. Clearing a provider
// without a key changes nothing.
func (s *Service) ClearProviderAPIKey(ctx context.Context, act actor.Actor, id string) (*AIProvider, error) {
	return s.writeProviderKey(ctx, act, id, nil)
}

// writeProviderKey replaces (key != nil) or removes (key == nil) a provider's
// API key in one transaction. Like a session's key, the old secret is dropped
// through the owner namespace, never through the reference in the row.
func (s *Service) writeProviderKey(ctx context.Context, act actor.Actor, id string, key []byte) (*AIProvider, error) {
	if s.secrets == nil {
		return nil, problem.New(problem.Unavailable, "API keys cannot be stored: this host has no secret store.")
	}
	var out *AIProvider
	err := s.db.Update(ctx, func(tx *storage.Tx) error {
		cur, err := loadProviderTx(ctx, tx, id)
		if err != nil {
			return err
		}
		out = cur
		if key == nil && cur.APIKeyRef == "" {
			return nil
		}
		tx.SetOrigin(storage.Origin{Actor: act})
		if _, err := s.secrets.DeleteOwner(ctx, tx, providerSecretOwner(cur.ID)); err != nil {
			return err
		}
		action := ActionProviderKeyClear
		cur.APIKeyRef = ""
		if key != nil {
			if cur.APIKeyRef, err = s.secrets.Put(ctx, tx, providerSecretOwner(cur.ID), providerKeyPurpose, key); err != nil {
				return err
			}
			action = ActionProviderKeySet
		}
		cur.UpdatedAt = tx.Now()
		rev, err := tx.Changed(ctx, storage.Change{
			Subject: providerSubject(cur.ID), Kind: storage.Updated, Pointers: []string{"/has_api_key"},
		})
		if err != nil {
			return err
		}
		cur.Revision = storage.Revision(rev)
		if _, err := tx.ExecContext(ctx, `UPDATE ai_providers SET api_key_ref = ?, updated_at = ?, revision = ?
			WHERE provider_id = ?`,
			string(cur.APIKeyRef), storage.FormatTime(cur.UpdatedAt), rev, cur.ID); err != nil {
			return fmt.Errorf("agentsession: update provider key: %w", err)
		}
		return operations.Audit(ctx, tx, operations.AuditRecord{
			Actor: act, Action: action, Subject: providerSubject(cur.ID),
			Outcome: operations.AuditSuccess,
		})
	})
	if err != nil {
		return nil, problem.From(err)
	}
	return out, nil
}

// providerAuditDetails marshals small non-secret facts; a failure is impossible
// for the plain values used here and falls back to {}.
func providerAuditDetails(v map[string]any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

// providerBoolInt stores a boolean as the STRICT table's 0/1.
func providerBoolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- resolution --------------------------------------------------------------

// ProviderEndpoint is the resolved model endpoint of a provider.
type ProviderEndpoint struct {
	ID      string
	BaseURL string
	Model   string
	// Key is the revealed API key, empty when the provider has none. The
	// caller must clear it after use.
	Key []byte
}

// ProviderResolver resolves the global AI provider a session names, or the
// default one when the session names none (GAP-2, ADR-0017). The native core
// depends on this narrow interface; the host's session service implements it.
type ProviderResolver interface {
	ResolveProvider(ctx context.Context, id string) (ProviderEndpoint, bool, error)
}

// ResolveProvider resolves the provider named by id, or the default provider
// when id is empty. found=false means "neither exists". The key is decrypted
// with RevealOwned under the provider's own namespace, so a reference to any
// other secret fails closed.
func (s *Service) ResolveProvider(ctx context.Context, id string) (ProviderEndpoint, bool, error) {
	p, found, err := s.providerRecord(ctx, id)
	if err != nil || !found {
		return ProviderEndpoint{}, false, err
	}
	ep := ProviderEndpoint{ID: p.ID, BaseURL: p.BaseURL, Model: p.Model}
	if p.APIKeyRef == "" {
		return ep, true, nil
	}
	if s.secrets == nil {
		return ProviderEndpoint{}, false, problem.New(problem.Unavailable,
			"The provider's API key cannot be read: this host has no secret store.")
	}
	secret, err := s.secrets.RevealOwned(ctx, p.APIKeyRef, providerSecretOwner(p.ID), providerKeyPurpose)
	if err != nil {
		return ProviderEndpoint{}, false, problem.New(problem.Unavailable,
			"The provider's API key is not available; set it again with PUT /api/v1/ai/providers/{provider_id}/api-key.")
	}
	defer secret.Clear()
	ep.Key = append([]byte(nil), secret.Bytes()...)
	return ep, true, nil
}

// --- connectivity probe ------------------------------------------------------

// ProviderProbe is the outcome of TestProvider (OpenAPI AiProviderTestResult).
type ProviderProbe struct {
	OK        bool
	LatencyMS int64
	// Category classifies a failure: auth, network, denied, 4xx or 5xx. It
	// never carries the address, the exact status or the response body.
	Category string
}

// TestProvider probes one provider: a GET of {base_url}/models through the
// same outbound-controlled client the turns use. The answer only says whether
// it worked, how long it took and, on failure, the class — never the address,
// the exact status code or the body (AGT-03).
func (s *Service) TestProvider(ctx context.Context, id string) (ProviderProbe, error) {
	p, err := s.GetProvider(ctx, id)
	if err != nil {
		return ProviderProbe{}, err
	}
	var key []byte
	if p.APIKeyRef != "" {
		ep, found, err := s.ResolveProvider(ctx, id)
		if err != nil {
			return ProviderProbe{}, err
		}
		if !found {
			return ProviderProbe{}, providerNotFound()
		}
		key = ep.Key
		defer clear(key)
	}
	switch core := s.cores[string(CoreNative)].(type) {
	case *NativeCore:
		return core.probeProvider(ctx, p.BaseURL, key), nil
	case *EnhancedNativeCore:
		return core.base.probeProvider(ctx, p.BaseURL, key), nil
	default:
		return ProviderProbe{}, problem.New(problem.Unavailable, "The native core is not available on this host.")
	}
}

// probeProvider performs one minimal request against an OpenAI-compatible
// endpoint and classifies the outcome. It shares the client (and therefore the
// egress policy) of the model turns.
func (c *NativeCore) probeProvider(ctx context.Context, baseURL string, apiKey []byte) ProviderProbe {
	ctx, cancel := context.WithTimeout(ctx, providerProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/models", nil)
	if err != nil {
		return ProviderProbe{Category: "network"}
	}
	req.Header.Set("Accept", "application/json")
	if len(apiKey) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(apiKey))
	}
	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, errEgressDenied) {
			return ProviderProbe{Category: "denied"}
		}
		return ProviderProbe{Category: "network"}
	}
	defer resp.Body.Close()
	// The body is untrusted and may echo the Authorization header; it is read
	// only to keep the connection reusable and is never inspected or logged.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	latency := time.Since(start).Milliseconds()
	switch {
	case resp.StatusCode == http.StatusOK:
		return ProviderProbe{OK: true, LatencyMS: latency}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ProviderProbe{Category: "auth"}
	case resp.StatusCode >= 500:
		return ProviderProbe{Category: "5xx"}
	case resp.StatusCode >= 400:
		return ProviderProbe{Category: "4xx"}
	default:
		return ProviderProbe{Category: "network"}
	}
}

// --- agent cores -------------------------------------------------------------

// CoreInfo is one entry of GET /api/v1/agent-cores (OpenAPI AgentCoreInfo).
type CoreInfo struct {
	Core      CoreName
	Available bool
	Reason    string
}

// coreReasonUnavailable is the fixed reason of a core this host does not serve
// yet; the external CLI cores arrive with P6 (ADR-0010 §5).
const coreReasonUnavailable = "外部核心尚未接入"

// coreOrder is the fixed order of the core list.
var coreOrder = []CoreName{CoreNative, CoreClaudeCode, CoreCodex, CoreOpencode}

// Cores lists every selectable core of ADR-0010 with its live availability.
func (s *Service) Cores() []CoreInfo {
	out := make([]CoreInfo, 0, len(coreOrder))
	for _, name := range coreOrder {
		c, ok := s.cores[string(name)]
		if !ok {
			out = append(out, CoreInfo{Core: name, Available: false, Reason: coreReasonUnavailable})
			continue
		}
		if cc, hasDesc := c.(CapableCore); hasDesc {
			desc := cc.Descriptor(context.Background())
			reason := desc.Reason
			if !desc.Available && reason == "" {
				reason = coreReasonUnavailable
			}
			out = append(out, CoreInfo{Core: name, Available: desc.Available, Reason: reason})
			continue
		}
		out = append(out, CoreInfo{Core: name, Available: true})
	}
	return out
}
