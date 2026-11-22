// SPDX-License-Identifier: AGPL-3.0-only

package operations

import "testing"

// TestReadInvokeCreatesNoOperation: an overview widget polls a read operation
// every few seconds. The read must not grow the operations table or the audit
// log, otherwise a 2-second card violates the OPS-05 growth bound (GAPS gap 7).
func TestReadInvokeCreatesNoOperation(t *testing.T) {
	e := newTestEnv(t)
	operationsBefore := e.countOperations()
	auditBefore := e.countAudit(actionRead)
	for i := 0; i < 3; i++ {
		resp, err := e.run(humanActor(), actionRead, nodeTarget(), nil)
		if err != nil {
			t.Fatalf("read invoke: %v", err)
		}
		if resp.Status != 200 || resp.OperationID != "" {
			t.Fatalf("read response = %d %q, want 200 with no operation id", resp.Status, resp.OperationID)
		}
	}
	if n := e.countOperations(); n != operationsBefore {
		t.Fatalf("operations = %d, want %d", n, operationsBefore)
	}
	if n := e.countAudit(actionRead); n != auditBefore {
		t.Fatalf("audit rows = %d, want %d", n, auditBefore)
	}
	if n := e.countRows("idempotency_keys"); n != 0 {
		t.Fatalf("idempotency keys = %d, want 0", n)
	}
}
