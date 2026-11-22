// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import "context"

// StaticCatalog is a ToolCatalog over a fixed list. It is what the A2
// integration and the tests use until the host wires the action catalog: a
// ToolCatalog must be able to enumerate actions, and internal/catalog only
// searches, so the adapter belongs to the integration step that also owns the
// catalog's enumeration (see REPORT.md).
type StaticCatalog struct {
	Tools []ToolSpec
}

// Actions implements ToolCatalog.
func (c StaticCatalog) Actions(context.Context) []ToolSpec { return c.Tools }
