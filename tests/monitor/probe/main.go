// SPDX-License-Identifier: AGPL-3.0-only

// Command probe 只读检查宿主 metrics 原始来源，不安装服务或修改系统。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/qwq-panel/qwq/internal/capability/metrics"
)

func main() {
	collector, err := metrics.New(metrics.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "metrics collector unavailable")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for index := range 3 {
		snapshot, err := collector.Collect(ctx)
		if err != nil || snapshot == nil || snapshot.Cpu == nil || snapshot.Memory == nil || snapshot.Memory.TotalBytes == 0 || len(snapshot.Nets) == 0 || len(snapshot.Disks) == 0 {
			fmt.Fprintln(os.Stderr, "metrics sources incomplete")
			os.Exit(1)
		}
		data := map[string]any{"sample": index + 1, "collected_at_unix_ms": snapshot.CollectedAtUnixMs, "cores": snapshot.Cpu.CoreCount, "memory_total_bytes": snapshot.Memory.TotalBytes, "memory_available_bytes": snapshot.Memory.AvailableBytes, "interfaces": len(snapshot.Nets), "mounts": len(snapshot.Disks), "uptime_seconds": snapshot.UptimeSeconds}
		if err := json.NewEncoder(os.Stdout).Encode(data); err != nil {
			os.Exit(1)
		}
		if index < 2 {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				os.Exit(1)
			case <-timer.C:
			}
		}
	}
}
