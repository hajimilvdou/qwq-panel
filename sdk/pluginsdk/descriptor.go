// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"fmt"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"github.com/qwq-panel/qwq/sdk/manifest"
)

// buildDescriptor derives PluginDescriptor from the embedded manifest. The
// descriptor is a pure function of the manifest, so GetDescriptor can never
// disagree with what the installer validated (ARCH §5.3).
func buildDescriptor(m *manifest.Manifest) (*platformv1.PluginDescriptor, error) {
	placement, err := placementProto(m.Placement)
	if err != nil {
		return nil, err
	}
	d := &platformv1.PluginDescriptor{
		PluginId:               m.ID,
		PluginVersion:          m.Version,
		AbiMajor:               uint32(m.ABI.Major),
		AbiMinor:               uint32(m.ABI.MinimumMinor),
		Placement:              placement,
		StateSchemaVersion:     m.State.SchemaVersion,
		MinimumRollbackVersion: m.State.MinimumRollbackVersion,
		ConfigSchemaRef:        m.Config.Schema,
		ConfigHotApply:         m.Config.HotApply,
	}
	for _, c := range m.Capabilities {
		d.Capabilities = append(d.Capabilities, &platformv1.Capability{Name: c.Name, Scope: c.Scope})
	}
	for _, op := range m.Operations {
		desc, err := operationDescriptor(m, op)
		if err != nil {
			return nil, err
		}
		d.Operations = append(d.Operations, desc)
	}
	return d, nil
}

func operationDescriptor(m *manifest.Manifest, op manifest.Operation) (*platformv1.OperationDescriptor, error) {
	mode, err := modeProto(op.Mode)
	if err != nil {
		return nil, fmt.Errorf("operation %s: %w", op.Name, err)
	}
	effect, err := effectProto(op.Effect)
	if err != nil {
		return nil, fmt.Errorf("operation %s: %w", op.Name, err)
	}
	risk, err := riskProto(op.Risk)
	if err != nil {
		return nil, fmt.Errorf("operation %s: %w", op.Name, err)
	}
	d := &platformv1.OperationDescriptor{
		Name:              op.Name,
		ApiVersion:        op.APIVersion,
		Permission:        op.Permission,
		Mode:              mode,
		Effect:            effect,
		Risk:              risk,
		Idempotent:        op.Idempotent,
		Plannable:         op.EffectivePlannable(),
		TimeoutMs:         int32(op.TimeoutMS),
		RequestSchemaRef:  op.RequestSchema,
		ResponseSchemaRef: op.ResponseSchema,
		Summary:           op.Summary,
		UndoOperation:     op.Undo,
		UiRoute:           op.UIRoute,
	}
	// Operation.capabilities is a subset of the plugin's; empty means "all of
	// them" (ADR-0007 #4), so an operation that declares none stays empty here.
	for _, c := range op.Capabilities {
		d.Capabilities = append(d.Capabilities, &platformv1.Capability{Name: c.Name, Scope: c.Scope})
	}
	return d, nil
}

func placementProto(s string) (platformv1.Placement, error) {
	switch s {
	case "node":
		return platformv1.Placement_PLACEMENT_NODE, nil
	case "controller":
		return platformv1.Placement_PLACEMENT_CONTROLLER, nil
	}
	return platformv1.Placement_PLACEMENT_UNSPECIFIED, fmt.Errorf("unknown manifest placement %q", s)
}

func modeProto(s string) (platformv1.OperationMode, error) {
	switch s {
	case "invoke":
		return platformv1.OperationMode_OPERATION_MODE_INVOKE, nil
	case "job":
		return platformv1.OperationMode_OPERATION_MODE_JOB, nil
	}
	return platformv1.OperationMode_OPERATION_MODE_UNSPECIFIED, fmt.Errorf("unknown manifest mode %q", s)
}

func effectProto(s string) (platformv1.OperationEffect, error) {
	switch s {
	case "read":
		return platformv1.OperationEffect_OPERATION_EFFECT_READ, nil
	case "write":
		return platformv1.OperationEffect_OPERATION_EFFECT_WRITE, nil
	case "destructive":
		return platformv1.OperationEffect_OPERATION_EFFECT_DESTRUCTIVE, nil
	}
	return platformv1.OperationEffect_OPERATION_EFFECT_UNSPECIFIED, fmt.Errorf("unknown manifest effect %q", s)
}

func riskProto(s string) (platformv1.RiskLevel, error) {
	switch s {
	case "low":
		return platformv1.RiskLevel_RISK_LEVEL_LOW, nil
	case "medium":
		return platformv1.RiskLevel_RISK_LEVEL_MEDIUM, nil
	case "high":
		return platformv1.RiskLevel_RISK_LEVEL_HIGH, nil
	}
	return platformv1.RiskLevel_RISK_LEVEL_UNSPECIFIED, fmt.Errorf("unknown manifest risk %q", s)
}
