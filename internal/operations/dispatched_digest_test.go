// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"strings"
	"testing"
)

// ======================== 授权账本与原 operation 的摘要格式一致 ========================

func TestDispatchedArgumentDigestUsesCanonicalFormat(t *testing.T) {
	expected := digestOf([]byte(`{"resource":"one"}`))
	if !ValidArgumentDigest(expected) {
		t.Fatal("真实 operation 参数摘要被拒绝")
	}
	for _, value := range []string{"", strings.Repeat("a", 64), "sha256:short", "other:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("A", 64), expected + "x", expected + "\n"} {
		if ValidArgumentDigest(value) {
			t.Fatal("无算法、未知算法、非规范或尾随摘要被接受")
		}
	}
}
