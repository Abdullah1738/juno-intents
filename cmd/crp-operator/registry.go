package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Abdullah1738/juno-intents/offchain/deployments"
)

func applyDeploymentRegistryDefaults(deploymentFile, deploymentName string, crpProgramStr, deploymentHex *string) error {
	deploymentName = strings.TrimSpace(deploymentName)
	if deploymentName == "" {
		return nil
	}

	deploymentFile = strings.TrimSpace(deploymentFile)
	if deploymentFile == "" {
		deploymentFile = "deployments.json"
	}

	reg, err := deployments.Load(deploymentFile)
	if err != nil {
		return fmt.Errorf("load deployments registry %q: %w", deploymentFile, err)
	}
	d, err := reg.FindByName(deploymentName)
	if err != nil {
		return fmt.Errorf("find deployment %q in %q: %w", deploymentName, deploymentFile, err)
	}

	if crpProgramStr != nil && strings.TrimSpace(*crpProgramStr) == "" {
		*crpProgramStr = d.CheckpointRegistryProgramID
	}
	if deploymentHex != nil && strings.TrimSpace(*deploymentHex) == "" {
		*deploymentHex = d.DeploymentID
	}

	if crpProgramStr != nil && strings.TrimSpace(*crpProgramStr) == "" {
		return errors.New("deployment record is missing checkpoint_registry_program_id")
	}
	if deploymentHex != nil && strings.TrimSpace(*deploymentHex) == "" {
		return errors.New("deployment record is missing deployment_id")
	}

	if os.Getenv("SOLANA_RPC_URL") == "" && os.Getenv("HELIUS_RPC_URL") == "" && os.Getenv("HELIUS_API_KEY") == "" {
		if strings.TrimSpace(d.RPCURL) != "" {
			_ = os.Setenv("SOLANA_RPC_URL", d.RPCURL)
		}
	}

	return nil
}

