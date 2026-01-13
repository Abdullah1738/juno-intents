package main

import "testing"

func TestDefaultWorkflowFile(t *testing.T) {
	if defaultWorkflowFile != "groth16.yml" {
		t.Fatalf("defaultWorkflowFile: got %q want %q", defaultWorkflowFile, "groth16.yml")
	}
}

