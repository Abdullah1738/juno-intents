package deployments

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndFindByName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deployments.json")
	if err := os.WriteFile(path, []byte(`{
  "schema_version": 1,
  "protocol_version": 1,
  "deployments": [
    {
      "name": "devnet-1",
      "cluster": "devnet",
      "deployment_id": "11",
      "checkpoint_registry_program_id": "CRP"
    }
  ]
}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d, err := r.FindByName("devnet-1")
	if err != nil {
		t.Fatalf("FindByName: %v", err)
	}
	if d.Cluster != "devnet" || d.DeploymentID != "11" || d.CheckpointRegistryProgramID != "CRP" {
		t.Fatalf("unexpected deployment: %+v", d)
	}
}

