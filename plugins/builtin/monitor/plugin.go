// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	_ "embed"
	"time"

	metricsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/metrics/v1"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

//go:embed manifest.json
var manifestJSON []byte
var buildVersion string

func Manifest() []byte {
	raw := append([]byte(nil), manifestJSON...)
	if buildVersion != "" {
		raw = bytes.Replace(raw, []byte(`"version": "0.1.0"`), []byte(`"version": "`+buildVersion+`"`), 1)
	}
	return raw
}

// Plugin 保持普通只读插件沙箱，所有指标通过宿主 UDS 能力读取。
type Plugin struct{ source Source }

func New() *Plugin { return &Plugin{} }

func (p *Plugin) NewInstance(ctx context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	cfg, err := parseConfig(info.Config)
	if err != nil {
		return nil, err
	}
	instance := &instance{InstanceBase: pluginsdk.NewInstanceBase(info)}
	source := p.source
	var hs *hostSource
	if source == nil {
		hs = &hostSource{base: instance.InstanceBase}
		source = hs
	}
	instance.samples, err = newSampler(cfg, source)
	if err != nil {
		return nil, err
	}
	if hs != nil {
		hs.mounts = instance.samples.diskMounts
	}
	instance.samples.publishAlert = func(pctx context.Context, draft pluginsdk.EventDraft) error {
		host := instance.Host()
		if host == nil || host.Conn() == nil {
			return nil
		}
		_, err := host.PublishEvent(pctx, draft)
		return err
	}
	instance.restoreCoarseHistory(ctx)
	instance.register()
	return instance, nil
}

type instance struct {
	*pluginsdk.InstanceBase
	samples *sampler
}

func (i *instance) Start(ctx context.Context) error {
	i.restoreCoarseHistory(ctx)
	return nil
}

func (i *instance) Activate(ctx context.Context) error {
	i.samples.reset()
	i.restoreCoarseHistory(ctx)
	return i.Go(i.samples.loop)
}

func (i *instance) Deactivate(ctx context.Context) error {
	i.samples.pause()
	i.persistCoarseHistory(ctx)
	return nil
}

func (i *instance) Stop(ctx context.Context) error {
	i.persistCoarseHistory(ctx)
	return nil
}

func (i *instance) persistCoarseHistory(ctx context.Context) {
	host := i.Host()
	if host == nil || host.Conn() == nil || i.samples == nil {
		return
	}
	snap := i.samples.exportCoarseSnapshot(i.samples.now())
	if len(snap.Points) == 0 {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = host.KV().PutJSON(pctx, coarseHistoryKVKey, snap, pluginsdk.PutOption{})
}

func (i *instance) restoreCoarseHistory(ctx context.Context) {
	host := i.Host()
	if host == nil || host.Conn() == nil || i.samples == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var snap coarseHistorySnapshot
	_, found, err := host.KV().GetJSON(rctx, coarseHistoryKVKey, &snap)
	if err != nil || !found {
		return
	}
	_ = i.samples.restoreCoarseSnapshot(snap, i.samples.now())
}
func (i *instance) ApplyConfig(_ context.Context, candidate pluginsdk.Config) error {
	next, err := parseConfig(candidate.JSON)
	if err != nil {
		return err
	}
	i.samples.configure(next)
	return nil
}
func (i *instance) ValidateConfig(_ context.Context, candidate pluginsdk.Config) (pluginsdk.ConfigValidation, error) {
	_, err := parseConfig(candidate.JSON)
	return pluginsdk.ConfigValidation{}, err
}
func (i *instance) Health(context.Context) pluginsdk.Health {
	i.samples.mu.Lock()
	defer i.samples.mu.Unlock()
	message := "监控采样中"
	if i.samples.previous == nil {
		message = "等待宿主首份采样"
	}
	if i.samples.lastError != "" {
		message = i.samples.lastError
	}
	return pluginsdk.Health{Message: message}
}

type hostSource struct {
	base   *pluginsdk.InstanceBase
	mounts func() []string
}

func (s *hostSource) Read(ctx context.Context) (*metricsv1.MetricsSnapshot, error) {
	host := s.base.Host()
	if host == nil || host.Conn() == nil {
		return nil, pluginsdk.Errorf("UNAVAILABLE", "宿主指标连接未建立")
	}
	meta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return nil, err
	}
	var diskMounts []string
	if s.mounts != nil {
		diskMounts = s.mounts()
	}
	response, err := metricsv1.NewMetricsServiceClient(host.Conn()).ReadMetrics(ctx, &metricsv1.ReadMetricsRequest{
		Context:    meta,
		DiskMounts: diskMounts,
	})
	if err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, pluginsdk.Errorf("UNAVAILABLE", "宿主指标读取失败")
	}
	return response.Snapshot, nil
}
