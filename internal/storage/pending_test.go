package storage_test

import (
	"os"
	"testing"
)

// pending skips a model-level test until its task removes the call.
// RUN_PENDING=1 runs marked tests.
func pending(t *testing.T) {
	t.Helper()
	if os.Getenv("RUN_PENDING") != "1" {
		t.Skip("pending: set RUN_PENDING=1 to run")
	}
}
