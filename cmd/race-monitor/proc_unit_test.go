package main

import (
	"os"
	"testing"
	"time"
)

func TestProcessStartTimeOfThisProcessIsJustBeforeTheTest(t *testing.T) {
	now := time.Now()
	got, err := processStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("processStartTime: %v", err)
	}
	if got.After(now) || now.Sub(got) > time.Minute {
		t.Errorf("process start = %v, want within a minute before %v", got, now)
	}
}

func TestProcessStartTimeOfPidZeroIsZero(t *testing.T) {
	got, err := processStartTime(0)
	if err != nil || !got.IsZero() {
		t.Errorf("processStartTime(0) = %v, %v; want zero time, nil", got, err)
	}
}
