// SPDX-License-Identifier: AGPL-3.0-only
//go:build !linux

package metrics

import "context"

func defaultStatFS(context.Context, string) (DiskUsage, error) { return DiskUsage{}, ErrUnavailable }
