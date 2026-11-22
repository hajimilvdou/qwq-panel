// SPDX-License-Identifier: AGPL-3.0-only

package main

import "testing"

func TestApplyInputRejectsInjectedDuplicateNullAndNoncanonicalVersions(t *testing.T) {
	for _, payload := range []string{`{}`, `null`, `[]`, `{"config_revision":null}`, `{"config_revision":"01"}`, `{"config_revision":"0"}`, `{"config_revision":"9223372036854775808"}`, `{"config_revision":"1","config_revision":"1"}`, `{"config_revision":"1","native":{}}`, `{"config_revision":"1","expected_running_revision":null}`, `{"config_revision":"1","expected_running_revision":"00"}`} {
		if _, err := decodeApplyInput([]byte(payload)); err == nil {
			t.Fatal("unsafe Apply input was accepted")
		}
	}
	input, err := decodeApplyInput([]byte(`{"config_revision":"1","expected_running_revision":""}`))
	if err != nil || input.ExpectedRunningRevision == nil || *input.ExpectedRunningRevision != "" {
		t.Fatal("explicit unconfigured running precondition was lost")
	}
}
