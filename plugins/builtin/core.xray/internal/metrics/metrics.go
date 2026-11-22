// SPDX-License-Identifier: AGPL-3.0-only

// Package metrics 将当前核心的真实只读 counter 转为有界、保留缺失语义的系列。
package metrics

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	"github.com/qwq-panel/qwq/sdk/coreapi"
)

var ErrResponse = errors.New("core metrics: counter response is invalid")

type Filter struct {
	Kind string
	IDs  []string
}

// Series 的字节字符串避免客户端浮点丢失 int64 精度；缺失值保持 nil。
type Series struct {
	Kind            string  `json:"kind"`
	ID              string  `json:"id"`
	Present         bool    `json:"present"`
	UplinkPresent   bool    `json:"uplink_present"`
	DownlinkPresent bool    `json:"downlink_present"`
	UplinkBytes     *string `json:"uplink_bytes,omitempty"`
	DownlinkBytes   *string `json:"downlink_bytes,omitempty"`
	ResetEpoch      string  `json:"reset_epoch"`
	CollectedAt     string  `json:"collected_at"`
	Source          string  `json:"source"`
}
type Result struct {
	ResetEpoch  string   `json:"reset_epoch"`
	CollectedAt string   `json:"collected_at"`
	Source      string   `json:"source"`
	Series      []Series `json:"series"`
}

// Normalize 不读取文件、不查询网络、不修改输入，也不做跨 epoch 差分或 reset。
func Normalize(summary *state.IntentSummary, counters map[string]int64, filter Filter, epoch string, collected time.Time) (Result, error) {
	if summary == nil || summary.Validate() != nil || epoch == "" || len(epoch) > 64 || len(counters) > 2*(coreapi.MaxUsers+1) {
		return Result{}, ErrResponse
	}
	if filter.Kind != "" && filter.Kind != "inbound" && filter.Kind != "user" || len(filter.IDs) > coreapi.MaxUsers {
		return Result{}, ErrResponse
	}
	selected := map[string]bool{}
	for _, id := range filter.IDs {
		if _, err := coreapi.UserEmail(id); err != nil || selected[id] {
			return Result{}, ErrResponse
		}
		selected[id] = true
	}
	users := map[string]bool{}
	for _, id := range summary.UserIDs {
		users[id] = true
	}
	for name, value := range counters {
		parts := strings.Split(name, ">>>")
		if value < 0 || len(parts) != 4 || parts[2] != "traffic" || parts[3] != "uplink" && parts[3] != "downlink" {
			return Result{}, ErrResponse
		}
		switch parts[0] {
		case "inbound":
			if parts[1] != "qwq-in-"+summary.InboundID {
				return Result{}, ErrResponse
			}
		case "user":
			if !strings.HasPrefix(parts[1], "qwq-user-") || !users[strings.TrimPrefix(parts[1], "qwq-user-")] {
				return Result{}, ErrResponse
			}
		default:
			return Result{}, ErrResponse
		}
	}
	timestamp := collected.UTC().Format(time.RFC3339Nano)
	result := Result{ResetEpoch: epoch, CollectedAt: timestamp, Source: "xray", Series: []Series{}}
	appendSeries := func(kind, id, prefix string) {
		if filter.Kind != "" && filter.Kind != kind || filter.IDs != nil && !selected[id] {
			return
		}
		series := Series{Kind: kind, ID: id, ResetEpoch: epoch, CollectedAt: timestamp, Source: "xray"}
		if value, found := counters[kind+">>>"+prefix+id+">>>traffic>>>uplink"]; found {
			encoded := strconv.FormatInt(value, 10)
			series.UplinkBytes, series.UplinkPresent = &encoded, true
		}
		if value, found := counters[kind+">>>"+prefix+id+">>>traffic>>>downlink"]; found {
			encoded := strconv.FormatInt(value, 10)
			series.DownlinkBytes, series.DownlinkPresent = &encoded, true
		}
		series.Present = series.UplinkPresent && series.DownlinkPresent
		result.Series = append(result.Series, series)
	}
	appendSeries("inbound", summary.InboundID, "qwq-in-")
	for _, id := range summary.UserIDs {
		appendSeries("user", id, "qwq-user-")
	}
	return result, nil
}
