// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	_ "embed"

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

func (p *Plugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	cfg, err := parseConfig(info.Config)
	if err != nil {
		return nil, err
	}
	instance := &instance{InstanceBase: pluginsdk.NewInstanceBase(info)}
	source := p.source
	if source == nil {
		source = hostSource{base: instance.InstanceBase}
	}
	instance.samples, err = newSampler(cfg, source)
	if err != nil {
		return nil, err
	}
	instance.register()
	return instance, nil
}

type instance struct {
	*pluginsdk.InstanceBase
	samples *sampler
}

func (i *instance) Activate(context.Context) error   { i.samples.reset(); return i.Go(i.samples.loop) }
func (i *instance) Deactivate(context.Context) error { i.samples.pause(); return nil }
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

type hostSource struct{ base *pluginsdk.InstanceBase }

func (s hostSource) Read(ctx context.Context) (*metricsv1.MetricsSnapshot, error) {
	host := s.base.Host()
	if host == nil || host.Conn() == nil {
		return nil, pluginsdk.Errorf("UNAVAILABLE", "宿主指标连接未建立")
	}
	meta, err := host.CapabilityContextReadOnly(ctx)
	if err != nil {
		return nil, err
	}
	response, err := metricsv1.NewMetricsServiceClient(host.Conn()).ReadMetrics(ctx, &metricsv1.ReadMetricsRequest{Context: meta})
	if err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, pluginsdk.Errorf("UNAVAILABLE", "宿主指标读取失败")
	}
	return response.Snapshot, nil
}
