// SPDX-License-Identifier: AGPL-3.0-only

package ids

import "testing"

func TestGenerationPrefixUsesExistingTypeIDValidation(t *testing.T) {
	if Generation != "gen" {
		t.Fatalf("私有generation前缀变化：%s", Generation)
	}
	value := New(nil).New(Generation)
	if err := Check(value, Generation); err != nil || Valid(value, Operation) {
		t.Fatalf("generation未复用正确TypeID命名空间：%s %v", value, err)
	}
}
