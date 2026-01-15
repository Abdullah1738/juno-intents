package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Abdullah1738/juno-intents/offchain/solana"
	"github.com/Abdullah1738/juno-intents/protocol"
)

func cmdIepPDAs(argv []string) error {
	fs := flag.NewFlagSet("iep-pdas", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentFile string
		deploymentName string

		iepProgramStr string
		deploymentHex string

		intentStr string
		printStr  string
		jsonOut   bool
	)

	fs.StringVar(&deploymentName, "deployment", "", "Deployment name from deployments.json (fills --iep-program-id/--deployment-id)")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployments registry file path")

	fs.StringVar(&iepProgramStr, "iep-program-id", "", "IEP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&intentStr, "intent", "", "Intent PDA pubkey (base58)")
	fs.StringVar(&printStr, "print", "", "If set, prints a single field: config|fill|fill-id-hex|vault|intent-vault")
	fs.BoolVar(&jsonOut, "json", true, "If set, prints JSON (default: true)")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}

	if err := applyIepDeploymentDefaults(deploymentFile, deploymentName, &iepProgramStr, &deploymentHex); err != nil {
		return err
	}
	if strings.TrimSpace(iepProgramStr) == "" || strings.TrimSpace(deploymentHex) == "" {
		return errors.New("--iep-program-id and --deployment-id are required")
	}
	if strings.TrimSpace(intentStr) == "" {
		return errors.New("--intent is required")
	}

	iepProgram, err := solana.ParsePubkey(iepProgramStr)
	if err != nil {
		return fmt.Errorf("parse --iep-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}
	intent, err := solana.ParsePubkey(intentStr)
	if err != nil {
		return fmt.Errorf("parse --intent: %w", err)
	}

	cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, solana.Pubkey(iepProgram))
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}
	fillPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("fill"), intent[:]}, solana.Pubkey(iepProgram))
	if err != nil {
		return fmt.Errorf("derive fill pda: %w", err)
	}
	vaultPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("vault"), fillPDA[:]}, solana.Pubkey(iepProgram))
	if err != nil {
		return fmt.Errorf("derive vault pda: %w", err)
	}
	intentVaultPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("intent_vault"), intent[:]}, solana.Pubkey(iepProgram))
	if err != nil {
		return fmt.Errorf("derive intent_vault pda: %w", err)
	}

	fillIDHex := hex.EncodeToString(fillPDA[:])

	if strings.TrimSpace(printStr) != "" {
		switch strings.TrimSpace(printStr) {
		case "config":
			fmt.Println(cfgPDA.Base58())
			return nil
		case "fill":
			fmt.Println(fillPDA.Base58())
			return nil
		case "fill-id-hex":
			fmt.Println(fillIDHex)
			return nil
		case "vault":
			fmt.Println(vaultPDA.Base58())
			return nil
		case "intent-vault":
			fmt.Println(intentVaultPDA.Base58())
			return nil
		default:
			return fmt.Errorf("unknown --print field: %q", printStr)
		}
	}

	if !jsonOut {
		fmt.Fprintf(os.Stdout, "config=%s\n", cfgPDA.Base58())
		fmt.Fprintf(os.Stdout, "fill=%s\n", fillPDA.Base58())
		fmt.Fprintf(os.Stdout, "fill_id_hex=%s\n", fillIDHex)
		fmt.Fprintf(os.Stdout, "vault=%s\n", vaultPDA.Base58())
		fmt.Fprintf(os.Stdout, "intent_vault=%s\n", intentVaultPDA.Base58())
		return nil
	}

	out, err := json.Marshal(struct {
		Config      string `json:"config"`
		Fill        string `json:"fill"`
		FillIDHex   string `json:"fill_id_hex"`
		Vault       string `json:"vault"`
		IntentVault string `json:"intent_vault"`
	}{
		Config:      cfgPDA.Base58(),
		Fill:        fillPDA.Base58(),
		FillIDHex:   fillIDHex,
		Vault:       vaultPDA.Base58(),
		IntentVault: intentVaultPDA.Base58(),
	})
	if err != nil {
		return err
	}
	os.Stdout.Write(out)
	os.Stdout.Write([]byte("\n"))
	return nil
}
