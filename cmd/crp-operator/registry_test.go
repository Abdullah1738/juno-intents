package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyDeploymentRegistryDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deployments.json")
	if err := os.WriteFile(path, []byte(`{
  "schema_version": 1,
  "protocol_version": 1,
  "deployments": [
    {
      "name": "devnet-a",
      "cluster": "devnet",
      "rpc_url": "https://example.invalid",
      "deployment_id": "0x11",
      "checkpoint_registry_program_id": "CRPBASE58"
    }
  ]
}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	oldRPC := os.Getenv("SOLANA_RPC_URL")
	t.Cleanup(func() { _ = os.Setenv("SOLANA_RPC_URL", oldRPC) })
	_ = os.Unsetenv("SOLANA_RPC_URL")

	crp := ""
	deployment := ""
	if err := applyDeploymentRegistryDefaults(path, "devnet-a", &crp, &deployment); err != nil {
		t.Fatalf("applyDeploymentRegistryDefaults: %v", err)
	}
	if crp != "CRPBASE58" {
		t.Fatalf("crp: got %q, want %q", crp, "CRPBASE58")
	}
	if deployment != "0x11" {
		t.Fatalf("deployment: got %q, want %q", deployment, "0x11")
	}
	if got := os.Getenv("SOLANA_RPC_URL"); got != "https://example.invalid" {
		t.Fatalf("SOLANA_RPC_URL: got %q, want %q", got, "https://example.invalid")
	}
}

