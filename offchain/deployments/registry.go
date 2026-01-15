package deployments

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

var ErrNotFound = errors.New("deployment not found")

type Registry struct {
	SchemaVersion   int          `json:"schema_version"`
	ProtocolVersion int          `json:"protocol_version"`
	Deployments     []Deployment `json:"deployments"`
}

type Deployment struct {
	Name    string `json:"name"`
	Cluster string `json:"cluster,omitempty"`
	RPCURL  string `json:"rpc_url,omitempty"`

	DeploymentID string `json:"deployment_id"`

	JunocashChain       string `json:"junocash_chain,omitempty"`
	JunocashGenesisHash string `json:"junocash_genesis_hash,omitempty"` // hex32 (no 0x prefix required)

	CheckpointRegistryProgramID string `json:"checkpoint_registry_program_id"`
	IntentEscrowProgramID       string `json:"intent_escrow_program_id,omitempty"`
	ReceiptVerifierProgramID    string `json:"receipt_verifier_program_id,omitempty"`
}

func Load(path string) (Registry, error) {
	var out Registry
	path = strings.TrimSpace(path)
	if path == "" {
		return Registry{}, errors.New("path required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Registry{}, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Registry{}, err
	}
	return out, nil
}

func (r Registry) FindByName(name string) (Deployment, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Deployment{}, errors.New("name required")
	}
	for _, d := range r.Deployments {
		if d.Name == name {
			return d, nil
		}
	}
	return Deployment{}, fmt.Errorf("%w: %s", ErrNotFound, name)
}
