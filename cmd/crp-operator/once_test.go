package main

import "testing"

func TestShouldExitOnce(t *testing.T) {
	if shouldExitOnce(false, false, 123) {
		t.Fatalf("once=false should never exit")
	}
	if !shouldExitOnce(true, true, 123) {
		t.Fatalf("submitOnly should exit in once mode")
	}
	if shouldExitOnce(true, false, 1) {
		t.Fatalf("pending checkpoints should not exit in once mode")
	}
	if !shouldExitOnce(true, false, 0) {
		t.Fatalf("no pending checkpoints should exit in once mode")
	}
}
