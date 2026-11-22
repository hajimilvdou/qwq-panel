// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/qwq-panel/qwq/internal/gateway"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// maxOptionalBody bounds the body of a route whose requestBody is not required
// (POST .../cancel): the gateway does not install its body limit middleware
// there, so the handler bounds the read itself.
const maxOptionalBody = 1 << 20

// fail renders err as a Problem. Errors that are not *problem.Error become
// INTERNAL and their cause is logged with the request ID, never sent.
func (a *api) fail(w http.ResponseWriter, r *http.Request, err error) {
	requestID := gateway.RequestID(r.Context())
	p := problem.Write(w, err, requestID, r.URL.Path)
	if p.Status >= http.StatusInternalServerError {
		a.d.Logger.ErrorContext(r.Context(), "api request failed",
			slog.String("code", string(p.Code)),
			slog.String("path", r.URL.Path),
			slog.Any("error", err))
	}
}

// decodeJSON decodes the request body strictly. It exists so handlers read the
// same way everywhere; the gateway owns the limits and the content-type check.
func (a *api) decodeJSON(r *http.Request, dst any) error {
	return a.g.DecodeJSON(r, dst)
}

// decodeOptionalJSON decodes a body that the OpenAPI document does not require.
// An empty body leaves dst untouched; a non-JSON body is UNSUPPORTED_MEDIA_TYPE.
func (a *api) decodeOptionalJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxOptionalBody+1))
	if err != nil {
		return problem.Wrap(err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if int64(len(data)) > maxOptionalBody {
		e := problem.New(problem.PayloadTooLarge, "The request exceeds max_body_bytes (%d).", maxOptionalBody)
		e.Limit = &problem.Limit{Name: "max_body_bytes", Max: maxOptionalBody}
		return e
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType, _, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "application/json" {
			return problem.New(problem.UnsupportedMediaType, "The request body must be application/json.")
		}
	}
	clone := r.Clone(r.Context())
	clone.Body = io.NopCloser(bytes.NewReader(data))
	return a.g.DecodeJSON(clone, dst)
}

// fields parses the `fields` query parameter of a single-resource GET. Lists go
// through gateway.ListQuery, which parses it with the configured limit.
func (a *api) fields(r *http.Request) (*gateway.Projection, error) {
	return gateway.ParseFields(r.URL.Query().Get("fields"), gateway.DefaultLimits().FieldsMax)
}

// writeResource writes one resource, applying the `fields` projection before
// encoding.
func (a *api) writeResource(w http.ResponseWriter, r *http.Request, status int, v any, fields *gateway.Projection) {
	out, err := project(fields, v)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := gateway.WriteJSON(w, status, out); err != nil {
		a.d.Logger.WarnContext(r.Context(), "api: write response", slog.Any("error", err))
	}
}

// project turns v into its JSON form and applies the projection. Projection
// works on JSON Pointers, so the resource is rendered once into a generic map.
func project(fields *gateway.Projection, v any) (any, error) {
	if fields == nil {
		return v, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, problem.Wrap(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, problem.Wrap(err)
	}
	return fields.Apply(doc)
}

// listResponse is the ListMeta envelope shared by every list route.
type listResponse struct {
	Items      []any    `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
	Revision   string   `json:"revision"`
	Delta      bool     `json:"delta"`
	DeletedIDs []string `json:"deleted_ids,omitempty"`
}

// writeList writes one page, projecting each item (the `fields` parameter of a
// list is relative to each item, never to the envelope).
func (a *api) writeList(w http.ResponseWriter, r *http.Request, l listResponse, fields *gateway.Projection) {
	if l.Items == nil {
		l.Items = []any{}
	}
	if fields != nil {
		projected := make([]any, 0, len(l.Items))
		for _, item := range l.Items {
			out, err := project(fields, item)
			if err != nil {
				a.fail(w, r, err)
				return
			}
			projected = append(projected, out)
		}
		l.Items = projected
	}
	if err := gateway.WriteJSON(w, http.StatusOK, l); err != nil {
		a.d.Logger.WarnContext(r.Context(), "api: write response", slog.Any("error", err))
	}
}

// pageLimit returns how many rows to fetch for one page: one extra row tells the
// handler whether another page exists. The domain list functions clamp at 200,
// so a full 200-item page reports no cursor (the next request starts again from
// the same watermark).
func pageLimit(limit int) int {
	if limit < 200 {
		return limit + 1
	}
	return limit
}

// nextCursor returns the cursor of the following page and trims the extra row.
// The domain queries order by ID, so the cursor is the last returned ID and is
// opaque to clients.
func nextCursor[T any](items []T, limit int, id func(T) string) ([]T, string) {
	if len(items) <= limit {
		return items, ""
	}
	return items[:limit], id(items[limit-1])
}

// watermark is the collection revision of a page: the journal head, which is the
// same watermark operations uses, so a client can pass it back as
// `since_revision` without missing a change.
func (a *api) watermark() string {
	return storage.Revision(a.d.DB.HeadSeq())
}
