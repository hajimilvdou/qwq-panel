// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// ======================== 实测格式夹具：字段来自 137 内核库存，不从 parser 生成 ========================

const generationPerfTraceTestCommon = `field:unsigned short common_type; offset:0; size:2; signed:0;
field:unsigned char common_flags; offset:2; size:1; signed:0;
field:unsigned char common_preempt_count; offset:3; size:1; signed:0;
field:int common_pid; offset:4; size:4; signed:1;
`

const generationPerfTraceTestPopulated = `field:int root; offset:8; size:4; signed:1;
field:int level; offset:12; size:4; signed:1;
field:u64 id; offset:16; size:8; signed:0;
field:__data_loc char[] path; offset:24; size:4; signed:0;
field:int val; offset:28; size:4; signed:1;
`

const generationPerfTraceTestHotplug = `field:unsigned int cpu; offset:8; size:4; signed:0;
field:int target; offset:12; size:4; signed:1;
field:int idx; offset:16; size:4; signed:1;
field:void * fun; offset:24; size:8; signed:0;
`

func TestGenerationPerfTraceReadsDynamicIdentifiers(t *testing.T) {
	for _, test := range []struct {
		name, fields string
		schema       map[string]generationTraceField
	}{
		{"cgroup_notify_populated", generationPerfTraceTestPopulated, generationPopulatedTraceFields},
		{"cpuhp_enter", generationPerfTraceTestHotplug, generationHotplugTraceFields},
	} {
		for _, identifier := range []uint16{1, 139, 454, 65535} {
			format := fmt.Sprintf("name: %s\nID: %d\nformat:\n%s%s", test.name, identifier, generationPerfTraceTestCommon, test.fields)
			actual, err := parseGenerationTraceFormat(test.name, fmt.Sprintf("%d\n", identifier), format, test.schema)
			if err != nil || actual != identifier {
				t.Fatalf("name=%s id=%d actual=%d err=%v", test.name, identifier, actual, err)
			}
		}
	}
}

func TestGenerationPerfTraceRejectsUnsupportedABI(t *testing.T) {
	valid := "name: cgroup_notify_populated\nID: 454\nformat:\n" + generationPerfTraceTestCommon + generationPerfTraceTestPopulated
	tests := []struct{ name, id, format string }{
		{"zero_id", "0", strings.Replace(valid, "ID: 454", "ID: 0", 1)},
		{"oversized_id", "65536", valid},
		{"noncanonical_id", "0454", valid},
		{"id_mismatch", "455", valid},
		{"name_mismatch", "454", strings.Replace(valid, "cgroup_notify_populated", "cgroup_other", 1)},
		{"duplicate_name", "454", valid + "name: cgroup_notify_populated\n"},
		{"duplicate_id", "454", valid + "ID: 454\n"},
		{"missing_val", "454", strings.Replace(valid, "field:int val; offset:28; size:4; signed:1;\n", "", 1)},
		{"missing_type", "454", strings.Replace(valid, "field:u64 id;", "field:id;", 1)},
		{"short_inode", "454", strings.Replace(valid, "field:u64 id; offset:16; size:8;", "field:u64 id; offset:16; size:4;", 1)},
		{"signed_inode", "454", strings.Replace(valid, "field:u64 id; offset:16; size:8; signed:0;", "field:u64 id; offset:16; size:8; signed:1;", 1)},
		{"wrong_offset", "454", strings.Replace(valid, "field:int val; offset:28;", "field:int val; offset:32;", 1)},
		{"duplicate_field", "454", valid + "field:int val; offset:28; size:4; signed:1;\n"},
		{"unknown_field", "454", valid + "field:int extra; offset:32; size:4; signed:1;\n"},
		{"malformed_field", "454", valid + "field:garbage\n"},
		{"oversized_format", "454", valid + strings.Repeat(" ", 32<<10)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if id, err := parseGenerationTraceFormat("cgroup_notify_populated", test.id, test.format, generationPopulatedTraceFields); !errors.Is(err, ErrGenerationUnsupported) || id != 0 {
				t.Fatalf("id=%d err=%v", id, err)
			}
		})
	}
}

func TestGenerationPerfCPUInventoryIsBoundedAndExact(t *testing.T) {
	for _, test := range []struct {
		input string
		want  []int
	}{{"0\n", []int{0}}, {"3-4,1", []int{1, 3, 4}}, {"4095", []int{4095}}} {
		actual, err := parseGenerationPerfCPUs(test.input)
		if err != nil || !slices.Equal(actual, test.want) {
			t.Fatalf("input=%q actual=%v err=%v", test.input, actual, err)
		}
	}
	if actual, err := parseGenerationPerfCPUs("0-63"); err != nil || len(actual) != 64 {
		t.Fatalf("64 CPU boundary=%v err=%v", actual, err)
	}
	for _, input := range []string{"", "0,0", "0-2,2-3", "3-1", "0-64", "0-4095", "4096", "00", "0,", "-1", "+1", "0-1-2", " 0", "0\n\n"} {
		if cpus, err := parseGenerationPerfCPUs(input); !errors.Is(err, ErrGenerationUnsupported) || cpus != nil {
			t.Fatalf("bad input=%q actual=%v err=%v", input, cpus, err)
		}
	}
}
