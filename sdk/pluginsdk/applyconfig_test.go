// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"bytes"
	"testing"

	"google.golang.org/grpc/codes"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func TestApplyConfigDefaultAcceptWhenHotApply(t *testing.T) {
	env := newEnv(t, minimalPlugin{}, fixtureManifest(0, nil, nil))
	env.ready("a", []byte(`{}`))
	resp, err := env.client.ApplyConfig(testContext(t), &platformv1.ApplyConfigRequest{
		Context: lifecycleContext("a"), ConfigJson: []byte(`{"x":1}`), ProposedRevision: "2"})
	if err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if resp.GetAppliedRevision() != "2" {
		t.Fatalf("applied = %q", resp.GetAppliedRevision())
	}
	health, err := env.client.CheckHealth(testContext(t), &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if err != nil {
		t.Fatal(err)
	}
	if health.GetAppliedConfigRevision() != "2" {
		t.Fatalf("health revision = %q", health.GetAppliedConfigRevision())
	}
}

func TestApplyConfigUnimplementedWhenNotHotApply(t *testing.T) {
	m := bytes.Replace(fixtureManifest(0, nil, nil), []byte(`"hot_apply":true`), []byte(`"hot_apply":false`), 1)
	env := newEnv(t, minimalPlugin{}, m)
	env.ready("a", []byte(`{}`))
	_, err := env.client.ApplyConfig(testContext(t), &platformv1.ApplyConfigRequest{
		Context: lifecycleContext("a"), ConfigJson: []byte(`{}`), ProposedRevision: "2"})
	wantCode(t, err, codes.Unimplemented)
}
