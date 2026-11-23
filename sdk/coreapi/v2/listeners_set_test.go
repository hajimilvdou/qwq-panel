// SPDX-License-Identifier: Apache-2.0

package coreapi

import "testing"

// ---- 外层与内部监听共用同一地址重叠规则 ------------------------------------

func TestCheckListenerConflictsReusesAddressFamilyRules(t *testing.T) {
	for _, test := range []struct {
		name    string
		other   Listener
		blocked bool
	}{
		{"same-tcp", Listener{ProfileID: "inner", Network: "tcp", Listen: "127.0.0.1", Port: 18443}, true},
		{"v4-wildcard", Listener{ProfileID: "inner", Network: "tcp", Listen: "0.0.0.0", Port: 18443}, true},
		{"v6-wildcard", Listener{ProfileID: "inner", Network: "tcp", Listen: "::", Port: 18443}, true},
		{"mapped-v4", Listener{ProfileID: "inner", Network: "tcp", Listen: "::ffff:127.0.0.1", Port: 18443}, true},
		{"udp-coexists", Listener{ProfileID: "inner", Network: "udp", Listen: "127.0.0.1", Port: 18443}, false},
		{"other-address", Listener{ProfileID: "inner", Network: "tcp", Listen: "127.0.0.2", Port: 18443}, false},
		{"other-family", Listener{ProfileID: "inner", Network: "tcp", Listen: "::1", Port: 18443}, false},
		{"other-port", Listener{ProfileID: "inner", Network: "tcp", Listen: "127.0.0.1", Port: 18444}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			listeners := []Listener{{ProfileID: "outer", Network: "tcp", Listen: "127.0.0.1", Port: 18443}, test.other}
			err := CheckListenerConflicts(listeners)
			if (err != nil) != test.blocked {
				t.Fatalf("监听冲突判断与已批准地址族规则不同: %v", err)
			}
		})
	}
}

func TestCheckListenerConflictsRejectsMalformedClaim(t *testing.T) {
	for _, change := range []func(*Listener){
		func(l *Listener) { l.ProfileID = "bad/id" },
		func(l *Listener) { l.Network = "all" },
		func(l *Listener) { l.Listen = "localhost" },
		func(l *Listener) { l.Listen = "::1%lo" },
		func(l *Listener) { l.Port = 0 },
		func(l *Listener) { l.Port = 65536 },
	} {
		listener := Listener{ProfileID: "outer", Network: "tcp", Listen: "127.0.0.1", Port: 18443}
		change(&listener)
		if err := CheckListenerConflicts([]Listener{listener}); err == nil {
			t.Fatal("畸形监听声明不能进入共用冲突校验")
		}
	}
	if err := CheckListenerConflicts([]Listener{{ProfileID: "outer", Network: "tcp", Listen: "0.0.0.0", Port: 443}}); err != nil {
		t.Fatalf("443 端口监听声明应合法: %v", err)
	}
}
