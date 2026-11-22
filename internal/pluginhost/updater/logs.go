// SPDX-License-Identifier: AGPL-3.0-only

package updater

import (
	"context"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/sandbox"
)

// LogSource is the installer's ability to read a plugin's journal. Only the
// production installer has it: it goes through the privileged helper, because
// the journal of another unit is not readable as qwq (GAPS gap 7).
type LogSource interface {
	Logs(ctx context.Context, pluginID, cursor, stream string, limit int) (sandbox.LogResult, error)
}

// Logs reads one page of a plugin's journal. The updater only forwards: the
// helper builds every journalctl argument and addresses only this plugin's unit.
func (u *Updater) Logs(ctx context.Context, pluginID, cursor, stream string, limit int) (sandbox.LogResult, error) {
	if err := checkPluginID(pluginID); err != nil {
		return sandbox.LogResult{}, err
	}
	src, ok := u.install.(LogSource)
	if !ok {
		return sandbox.LogResult{}, problem.New(problem.Unavailable, "This host cannot read plugin logs.")
	}
	return src.Logs(ctx, pluginID, cursor, stream, limit)
}
