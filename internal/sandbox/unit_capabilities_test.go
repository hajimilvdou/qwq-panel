// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"strings"
	"testing"
)

func TestDeriveSandboxRelaxations(t *testing.T) {
	cases := []struct {
		name string
		caps []CapabilityRef
		want SandboxRelaxations
	}{
		{
			name: "empty",
			want: SandboxRelaxations{},
		},
		{
			name: "network egress",
			caps: []CapabilityRef{{Name: "network.egress", Scope: "https"}},
			want: SandboxRelaxations{HostNetwork: true},
		},
		{
			name: "network listen brutal",
			caps: []CapabilityRef{{Name: "network.listen", Scope: "brutal"}},
			want: SandboxRelaxations{HostNetwork: true},
		},
		{
			name: "network listen ingress",
			caps: []CapabilityRef{{Name: "network.listen", Scope: "ingress"}},
			want: SandboxRelaxations{HostNetwork: true, BindPrivilegedPorts: true},
		},
		{
			name: "network listen custom-domain",
			caps: []CapabilityRef{{Name: "network.listen", Scope: "custom-domain"}},
			want: SandboxRelaxations{HostNetwork: true, BindPrivilegedPorts: true},
		},
		{
			name: "network proxy direct",
			caps: []CapabilityRef{{Name: "network.proxy", Scope: "direct"}},
			want: SandboxRelaxations{HostNetwork: true},
		},
		{
			name: "empty scope ignored",
			caps: []CapabilityRef{{Name: "network.egress", Scope: ""}, {Name: "network.listen", Scope: ""}},
			want: SandboxRelaxations{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveSandboxRelaxations(tc.caps); got != tc.want {
				t.Fatalf("DeriveSandboxRelaxations = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestRenderUnitRelaxationsBindPrivilegedPorts(t *testing.T) {
	spec := alphaSpec()
	spec.Relaxations = SandboxRelaxations{
		HostNetwork:         true,
		BindPrivilegedPorts: true,
	}
	files, err := RenderUnit(spec)
	if err != nil {
		t.Fatalf("RenderUnit: %v", err)
	}
	service := string(files["qwq-plugin@alpha.service"])
	for _, want := range []string{
		"PrivateNetwork=no\n",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE\n",
		"DynamicUser=yes\n",
		"NoNewPrivileges=yes\n",
	} {
		if !strings.Contains(service, want) {
			t.Errorf("service unit missing %q:\n%s", want, service)
		}
	}
}
