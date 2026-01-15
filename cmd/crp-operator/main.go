package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-intents/offchain/helius"
	"github.com/Abdullah1738/juno-intents/offchain/junocashcli"
	"github.com/Abdullah1738/juno-intents/offchain/nitro"
	"github.com/Abdullah1738/juno-intents/offchain/solana"
	"github.com/Abdullah1738/juno-intents/offchain/solanarpc"
	"github.com/Abdullah1738/juno-intents/offchain/solvernet"
	"github.com/Abdullah1738/juno-intents/protocol"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" || argv[0] == "help" {
		usage(os.Stdout)
		return nil
	}

	switch argv[0] {
	case "submit":
		return cmdSubmit(argv[1:])
	case "finalize":
		return cmdFinalize(argv[1:])
	case "finalize-auto":
		return cmdFinalizeAuto(argv[1:])
	case "finalize-pending":
		return cmdFinalizePending(argv[1:])
	case "deployments":
		return cmdDeployments(argv[1:])
	case "run":
		return cmdRun(argv[1:])
	default:
		return fmt.Errorf("unknown command: %s", argv[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "crp-operator: CheckpointRegistry operator tooling")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  crp-operator submit   [--deployment <name>] [--deployment-file <path>] --crp-program-id <base58> --deployment-id <hex32> --height <u64> --block-hash <hex32> --orchard-root <hex32> --prev-hash <hex32> [--payer-keypair <path>] [--operator-keypair <path>] [--operator-enclave-cid <u32>] [--operator-enclave-port <u32>] [--cu-limit <u32>] [--priority-level <level>] [--dry-run]")
	fmt.Fprintln(w, "  crp-operator finalize [--deployment <name>] [--deployment-file <path>] --crp-program-id <base58> --deployment-id <hex32> --height <u64> --orchard-root <hex32> --operator-keypair <path> [--operator-keypair <path>...] [--payer-keypair <path>] [--cu-limit <u32>] [--priority-level <level>] [--dry-run]")
	fmt.Fprintln(w, "  crp-operator finalize-auto [--deployment <name>] [--deployment-file <path>] --crp-program-id <base58> --deployment-id <hex32> --height <u64> --orchard-root <hex32> [--payer-keypair <path>] [--scan-limit <n>] [--cu-limit <u32>] [--priority-level <level>] [--dry-run]")
	fmt.Fprintln(w, "  crp-operator finalize-pending [--deployment <name>] [--deployment-file <path>] --crp-program-id <base58> --deployment-id <hex32> [--payer-keypair <path>] [--config-scan-limit <n>] [--scan-limit <n>] [--max-checkpoints <n>] [--cu-limit <u32>] [--priority-level <level>] [--dry-run]")
	fmt.Fprintln(w, "  crp-operator deployments [--deployment <name>] [--deployment-file <path>] --crp-program-id <base58>")
	fmt.Fprintln(w, "  crp-operator run [--deployment <name>] [--deployment-file <path>] --crp-program-id <base58> --deployment-id <hex32> --start-height <u64> --finalize-operator-keypair <path> [--junocash-cli <path>] [--junocash-cli-arg <arg>...] [--lag <u64>] [--poll-interval <duration>] [--payer-keypair <path>] [--submit-operator-keypair <path>] [--submit-operator-enclave-cid <u32>] [--submit-operator-enclave-port <u32>] [--cu-limit-submit <u32>] [--cu-limit-finalize <u32>] [--priority-level <level>] [--dry-run] [--once] [--submit-only]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Environment:")
	fmt.Fprintln(w, "  SOLANA_RPC_URL or HELIUS_RPC_URL or HELIUS_API_KEY/HELIUS_CLUSTER")
}

func cmdSubmit(argv []string) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentFile string
		deploymentName string

		crpProgramStr string
		deploymentHex string
		height        uint64
		blockHashHex  string
		orchardHex    string
		prevHashHex   string

		payerPath           string
		operatorPath        string
		operatorEnclaveCID  uint
		operatorEnclavePort uint

		cuLimit       uint
		priorityLevel string
		dryRun        bool
	)

	fs.StringVar(&deploymentName, "deployment", "", "Deployment name from deployments.json (fills --crp-program-id/--deployment-id)")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployments registry file path")
	fs.StringVar(&crpProgramStr, "crp-program-id", "", "CRP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.Uint64Var(&height, "height", 0, "JunoCash height")
	fs.StringVar(&blockHashHex, "block-hash", "", "JunoCash block hash (32-byte hex)")
	fs.StringVar(&orchardHex, "orchard-root", "", "Orchard root (32-byte hex)")
	fs.StringVar(&prevHashHex, "prev-hash", "", "JunoCash prev hash (32-byte hex)")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.StringVar(&operatorPath, "operator-keypair", solvernet.DefaultSolanaKeypairPath(), "Operator ed25519 keypair path (Solana CLI JSON format)")
	fs.UintVar(&operatorEnclaveCID, "operator-enclave-cid", 0, "If set, signs via Nitro enclave at this CID (disables --operator-keypair)")
	fs.UintVar(&operatorEnclavePort, "operator-enclave-port", 5000, "Nitro enclave AF_VSOCK port")

	fs.UintVar(&cuLimit, "cu-limit", 200_000, "Compute unit limit")
	fs.StringVar(&priorityLevel, "priority-level", string(helius.PriorityMedium), "Priority level (Min/Low/Medium/High/VeryHigh/UnsafeMax)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if err := applyDeploymentRegistryDefaults(deploymentFile, deploymentName, &crpProgramStr, &deploymentHex); err != nil {
		return err
	}
	if crpProgramStr == "" || deploymentHex == "" || blockHashHex == "" || orchardHex == "" || prevHashHex == "" {
		return errors.New("--crp-program-id, --deployment-id, --block-hash, --orchard-root, and --prev-hash are required")
	}
	if operatorEnclaveCID != 0 {
		if operatorEnclaveCID > 0xffff_ffff || operatorEnclavePort == 0 || operatorEnclavePort > 0xffff_ffff {
			return errors.New("--operator-enclave-cid and --operator-enclave-port must fit in u32 (and port must be > 0)")
		}
	}

	crpProgram, err := solana.ParsePubkey(crpProgramStr)
	if err != nil {
		return fmt.Errorf("parse --crp-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}
	blockHash, err := parseHex32(blockHashHex)
	if err != nil {
		return fmt.Errorf("parse --block-hash: %w", err)
	}
	orchardRoot, err := parseHex32(orchardHex)
	if err != nil {
		return fmt.Errorf("parse --orchard-root: %w", err)
	}
	prevHash, err := parseHex32(prevHashHex)
	if err != nil {
		return fmt.Errorf("parse --prev-hash: %w", err)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	cfg, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, solana.Pubkey(crpProgram))
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}
	checkpoint, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("checkpoint"), cfg[:], orchardRoot[:]},
		solana.Pubkey(crpProgram),
	)
	if err != nil {
		return fmt.Errorf("derive checkpoint pda: %w", err)
	}

	obs := protocol.CheckpointObservation{
		Height:      height,
		BlockHash:   protocol.JunoBlockHash(blockHash),
		OrchardRoot: protocol.OrchardRoot(orchardRoot),
		PrevHash:    protocol.JunoBlockHash(prevHash),
	}
	signingBytes := obs.SigningBytes(deploymentID)

	var operatorPub [32]byte
	var sig64 [64]byte
	if operatorEnclaveCID != 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		pk, sig, err := signObservationViaEnclave(ctx, uint32(operatorEnclaveCID), uint32(operatorEnclavePort), deploymentID, obs)
		if err != nil {
			return err
		}
		operatorPub = pk
		sig64 = sig
	} else {
		operatorPriv, opPub, err := solvernet.LoadSolanaKeypair(operatorPath)
		if err != nil {
			return fmt.Errorf("load operator keypair: %w", err)
		}
		operatorPub = opPub
		sig := ed25519.Sign(ed25519.PrivateKey(operatorPriv), signingBytes)
		copy(sig64[:], sig)
	}

	edIx := solana.Ed25519VerifyInstruction(sig64, solana.Pubkey(operatorPub), signingBytes)
	crpIx := solana.Instruction{
		ProgramID: solana.Pubkey(crpProgram),
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfg, IsSigner: false, IsWritable: false},
			{Pubkey: checkpoint, IsSigner: false, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: solana.InstructionsSysvarID, IsSigner: false, IsWritable: false},
		},
		Data: encodeCrpSubmitObservation(height, blockHash, orchardRoot, prevHash),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var microLamports uint64
	var feeKeys []string
	if hc, err := helius.ClientFromEnv(); err == nil {
		feeKeys = []string{
			solana.Pubkey(payerPub).Base58(),
			cfg.Base58(),
			checkpoint.Base58(),
			solana.SystemProgramID.Base58(),
			solana.InstructionsSysvarID.Base58(),
			solana.Ed25519ProgramID.Base58(),
			solana.Pubkey(crpProgram).Base58(),
		}
		est, err := hc.GetPriorityFeeEstimateByAccountKeys(ctx, helius.PriorityFeeEstimateByAccountKeysRequest{
			AccountKeys: feeKeys,
			Options: &helius.PriorityFeeOptions{
				PriorityLevel: helius.PriorityLevel(priorityLevel),
				Recommended:   true,
			},
		})
		if err == nil {
			microLamports = est.MicroLamports
		}
	}

	var ixs []solana.Instruction
	if cuLimit != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitLimit(uint32(cuLimit)))
	}
	if microLamports != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitPrice(microLamports))
	}
	ixs = append(ixs, edIx, crpIx)

	rpc, err := solanarpc.ClientFromEnv()
	if err != nil {
		return err
	}
	bh, err := rpc.LatestBlockhash(ctx)
	if err != nil {
		return err
	}
	tx, err := solana.BuildAndSignLegacyTransaction(
		bh,
		solana.Pubkey(payerPub),
		map[solana.Pubkey]ed25519.PrivateKey{solana.Pubkey(payerPub): payerPriv},
		ixs,
	)
	if err != nil {
		return err
	}

	if dryRun {
		if microLamports != 0 {
			fmt.Fprintf(os.Stderr, "priority_fee: cu_limit=%d microLamports=%d keys=%s\n", cuLimit, microLamports, strings.Join(feeKeys, ","))
		}
		fmt.Println(base64Std(tx))
		return nil
	}
	sigStr, err := rpc.SendTransaction(ctx, tx, false)
	if err != nil {
		return err
	}
	fmt.Println(sigStr)
	return nil
}

func cmdFinalize(argv []string) error {
	fs := flag.NewFlagSet("finalize", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentFile string
		deploymentName string

		crpProgramStr string
		deploymentHex string
		height        uint64
		orchardHex    string

		payerPath string

		operatorPaths multiString

		cuLimit       uint
		priorityLevel string
		dryRun        bool
	)

	fs.StringVar(&deploymentName, "deployment", "", "Deployment name from deployments.json (fills --crp-program-id/--deployment-id)")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployments registry file path")
	fs.StringVar(&crpProgramStr, "crp-program-id", "", "CRP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.Uint64Var(&height, "height", 0, "JunoCash height")
	fs.StringVar(&orchardHex, "orchard-root", "", "Orchard root (32-byte hex)")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.Var(&operatorPaths, "operator-keypair", "Operator keypair path (repeatable; Solana CLI JSON format)")

	fs.UintVar(&cuLimit, "cu-limit", 250_000, "Compute unit limit")
	fs.StringVar(&priorityLevel, "priority-level", string(helius.PriorityMedium), "Priority level (Min/Low/Medium/High/VeryHigh/UnsafeMax)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if err := applyDeploymentRegistryDefaults(deploymentFile, deploymentName, &crpProgramStr, &deploymentHex); err != nil {
		return err
	}
	if crpProgramStr == "" || deploymentHex == "" || orchardHex == "" || len(operatorPaths) == 0 {
		return errors.New("--crp-program-id, --deployment-id, --orchard-root, and at least one --operator-keypair are required")
	}

	crpProgram, err := solana.ParsePubkey(crpProgramStr)
	if err != nil {
		return fmt.Errorf("parse --crp-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}
	orchardRoot, err := parseHex32(orchardHex)
	if err != nil {
		return fmt.Errorf("parse --orchard-root: %w", err)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	cfg, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, solana.Pubkey(crpProgram))
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}
	checkpoint, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("checkpoint"), cfg[:], orchardRoot[:]},
		solana.Pubkey(crpProgram),
	)
	if err != nil {
		return fmt.Errorf("derive checkpoint pda: %w", err)
	}
	heightRec, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("height"), cfg[:], u64LE(height)},
		solana.Pubkey(crpProgram),
	)
	if err != nil {
		return fmt.Errorf("derive height pda: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	rpc, err := solanarpc.ClientFromEnv()
	if err != nil {
		return err
	}

	// Read the checkpoint from chain to ensure we sign exactly what will be verified.
	cpRaw, err := rpc.AccountDataBase64(ctx, checkpoint.Base58())
	if err != nil {
		return fmt.Errorf("fetch checkpoint account: %w", err)
	}
	cp, err := decodeCrpCheckpointV1(cpRaw)
	if err != nil {
		return fmt.Errorf("decode checkpoint: %w", err)
	}
	if cp.OrchardRoot != orchardRoot {
		return errors.New("checkpoint orchard_root mismatch (wrong --orchard-root?)")
	}
	if cp.Height != height {
		return errors.New("checkpoint height mismatch (wrong --height?)")
	}

	obs := protocol.CheckpointObservation{
		Height:      cp.Height,
		BlockHash:   protocol.JunoBlockHash(cp.BlockHash),
		OrchardRoot: protocol.OrchardRoot(cp.OrchardRoot),
		PrevHash:    protocol.JunoBlockHash(cp.PrevHash),
	}
	signingBytes := obs.SigningBytes(deploymentID)

	var edIxs []solana.Instruction
	for _, p := range operatorPaths {
		opPriv, opPub, err := solvernet.LoadSolanaKeypair(p)
		if err != nil {
			return fmt.Errorf("load operator keypair %q: %w", p, err)
		}
		sig := ed25519.Sign(ed25519.PrivateKey(opPriv), signingBytes)
		var sig64 [64]byte
		copy(sig64[:], sig)
		edIxs = append(edIxs, solana.Ed25519VerifyInstruction(sig64, solana.Pubkey(opPub), signingBytes))
	}

	// Optional: estimate priority fee via Helius.
	var microLamports uint64
	var feeKeys []string
	if hc, err := helius.ClientFromEnv(); err == nil {
		feeKeys = []string{
			solana.Pubkey(payerPub).Base58(),
			cfg.Base58(),
			checkpoint.Base58(),
			heightRec.Base58(),
			solana.SystemProgramID.Base58(),
			solana.InstructionsSysvarID.Base58(),
			solana.Ed25519ProgramID.Base58(),
			solana.Pubkey(crpProgram).Base58(),
		}
		est, err := hc.GetPriorityFeeEstimateByAccountKeys(ctx, helius.PriorityFeeEstimateByAccountKeysRequest{
			AccountKeys: feeKeys,
			Options: &helius.PriorityFeeOptions{
				PriorityLevel: helius.PriorityLevel(priorityLevel),
				Recommended:   true,
			},
		})
		if err == nil {
			microLamports = est.MicroLamports
		}
	}

	finalizeIx := solana.Instruction{
		ProgramID: solana.Pubkey(crpProgram),
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfg, IsSigner: false, IsWritable: true},
			{Pubkey: checkpoint, IsSigner: false, IsWritable: true},
			{Pubkey: heightRec, IsSigner: false, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: solana.InstructionsSysvarID, IsSigner: false, IsWritable: false},
		},
		Data: encodeCrpFinalize(uint8(len(edIxs))),
	}

	var ixs []solana.Instruction
	if cuLimit != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitLimit(uint32(cuLimit)))
	}
	if microLamports != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitPrice(microLamports))
	}
	ixs = append(ixs, edIxs...)
	ixs = append(ixs, finalizeIx)

	bh, err := rpc.LatestBlockhash(ctx)
	if err != nil {
		return err
	}
	tx, err := solana.BuildAndSignLegacyTransaction(
		bh,
		solana.Pubkey(payerPub),
		map[solana.Pubkey]ed25519.PrivateKey{solana.Pubkey(payerPub): payerPriv},
		ixs,
	)
	if err != nil {
		return err
	}

	if dryRun {
		if microLamports != 0 {
			fmt.Fprintf(os.Stderr, "priority_fee: cu_limit=%d microLamports=%d keys=%s\n", cuLimit, microLamports, strings.Join(feeKeys, ","))
		}
		fmt.Println(base64Std(tx))
		return nil
	}
	sigStr, err := rpc.SendTransaction(ctx, tx, false)
	if err != nil {
		return err
	}
	fmt.Println(sigStr)
	return nil
}

type operatorObservationSignature struct {
	Pubkey    solana.Pubkey
	Signature [64]byte
}

func extractObservationSignaturesFromTx(tx []byte, expectedMessage []byte, allowed map[solana.Pubkey]struct{}) ([]operatorObservationSignature, error) {
	parsed, err := solana.ParseLegacyTransaction(tx)
	if err != nil {
		return nil, err
	}

	var out []operatorObservationSignature
	for _, ix := range parsed.Instructions {
		if ix.ProgramID != solana.Ed25519ProgramID {
			continue
		}
		ed, err := solana.ParseEd25519SingleSignatureInstructionData(ix.Data)
		if err != nil {
			continue
		}
		if !bytes.Equal(ed.Message, expectedMessage) {
			continue
		}
		if _, ok := allowed[ed.Pubkey]; !ok {
			continue
		}
		out = append(out, operatorObservationSignature{
			Pubkey:    ed.Pubkey,
			Signature: ed.Signature,
		})
	}
	return out, nil
}

func cmdFinalizeAuto(argv []string) error {
	fs := flag.NewFlagSet("finalize-auto", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentFile string
		deploymentName string

		crpProgramStr string
		deploymentHex string
		height        uint64
		orchardHex    string

		payerPath string

		scanLimit     uint
		cuLimit       uint
		priorityLevel string
		dryRun        bool
	)

	fs.StringVar(&deploymentName, "deployment", "", "Deployment name from deployments.json (fills --crp-program-id/--deployment-id)")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployments registry file path")
	fs.StringVar(&crpProgramStr, "crp-program-id", "", "CRP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.Uint64Var(&height, "height", 0, "JunoCash height")
	fs.StringVar(&orchardHex, "orchard-root", "", "Orchard root (32-byte hex)")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.UintVar(&scanLimit, "scan-limit", 200, "Max tx signatures to scan for operator ed25519 signatures")
	fs.UintVar(&cuLimit, "cu-limit", 250_000, "Compute unit limit")
	fs.StringVar(&priorityLevel, "priority-level", string(helius.PriorityMedium), "Priority level (Min/Low/Medium/High/VeryHigh/UnsafeMax)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if err := applyDeploymentRegistryDefaults(deploymentFile, deploymentName, &crpProgramStr, &deploymentHex); err != nil {
		return err
	}
	if crpProgramStr == "" || deploymentHex == "" || orchardHex == "" {
		return errors.New("--crp-program-id, --deployment-id, and --orchard-root are required")
	}
	if scanLimit == 0 || scanLimit > 1000 {
		return errors.New("--scan-limit must be in [1,1000]")
	}

	crpProgram, err := solana.ParsePubkey(crpProgramStr)
	if err != nil {
		return fmt.Errorf("parse --crp-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}
	orchardRoot, err := parseHex32(orchardHex)
	if err != nil {
		return fmt.Errorf("parse --orchard-root: %w", err)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	cfg, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, solana.Pubkey(crpProgram))
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}
	checkpoint, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("checkpoint"), cfg[:], orchardRoot[:]},
		solana.Pubkey(crpProgram),
	)
	if err != nil {
		return fmt.Errorf("derive checkpoint pda: %w", err)
	}

	rpc, err := solanarpc.ClientFromEnv()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfgRaw, err := rpc.AccountDataBase64(ctx, cfg.Base58())
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}
	crpCfg, err := decodeCrpConfigV1(cfgRaw)
	if err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	if crpCfg.Paused {
		return errors.New("crp config is paused")
	}
	if crpCfg.DeploymentID != deploymentID {
		return errors.New("crp deployment_id mismatch")
	}
	if crpCfg.Threshold == 0 {
		return errors.New("crp config threshold=0")
	}

	cpRaw, err := rpc.AccountDataBase64(ctx, checkpoint.Base58())
	if err != nil {
		return fmt.Errorf("fetch checkpoint account: %w", err)
	}
	cp, err := decodeCrpCheckpointV1(cpRaw)
	if err != nil {
		return fmt.Errorf("decode checkpoint: %w", err)
	}
	if cp.OrchardRoot != orchardRoot {
		return errors.New("checkpoint orchard_root mismatch (wrong --orchard-root?)")
	}
	if height != 0 && cp.Height != height {
		return errors.New("checkpoint height mismatch (wrong --height?)")
	}
	if cp.Finalized {
		return nil
	}

	return finalizeCheckpointAuto(ctx, rpc, payerPriv, payerPub, crpProgram, deploymentID, cfg, crpCfg, checkpoint, cp, uint(scanLimit), cuLimit, priorityLevel, dryRun)
}

func cmdFinalizePending(argv []string) error {
	fs := flag.NewFlagSet("finalize-pending", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentFile string
		deploymentName string

		crpProgramStr string
		deploymentHex string

		payerPath string

		configScanLimit uint
		scanLimit       uint
		maxCheckpoints  uint

		cuLimit       uint
		priorityLevel string
		dryRun        bool
	)

	fs.StringVar(&deploymentName, "deployment", "", "Deployment name from deployments.json (fills --crp-program-id/--deployment-id)")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployments registry file path")
	fs.StringVar(&crpProgramStr, "crp-program-id", "", "CRP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.UintVar(&configScanLimit, "config-scan-limit", 200, "Max tx signatures to scan on the CRP config PDA")
	fs.UintVar(&scanLimit, "scan-limit", 200, "Max tx signatures to scan for operator ed25519 signatures per checkpoint")
	fs.UintVar(&maxCheckpoints, "max-checkpoints", 1, "Max checkpoints to finalize in one run")
	fs.UintVar(&cuLimit, "cu-limit", 250_000, "Compute unit limit")
	fs.StringVar(&priorityLevel, "priority-level", string(helius.PriorityMedium), "Priority level (Min/Low/Medium/High/VeryHigh/UnsafeMax)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx for the first candidate instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if err := applyDeploymentRegistryDefaults(deploymentFile, deploymentName, &crpProgramStr, &deploymentHex); err != nil {
		return err
	}
	if crpProgramStr == "" || deploymentHex == "" {
		return errors.New("--crp-program-id and --deployment-id are required")
	}
	if configScanLimit == 0 || configScanLimit > 1000 {
		return errors.New("--config-scan-limit must be in [1,1000]")
	}
	if scanLimit == 0 || scanLimit > 1000 {
		return errors.New("--scan-limit must be in [1,1000]")
	}
	if maxCheckpoints == 0 || maxCheckpoints > 10 {
		return errors.New("--max-checkpoints must be in [1,10]")
	}

	crpProgram, err := solana.ParsePubkey(crpProgramStr)
	if err != nil {
		return fmt.Errorf("parse --crp-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	cfg, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, solana.Pubkey(crpProgram))
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}

	rpc, err := solanarpc.ClientFromEnv()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cfgRaw, err := rpc.AccountDataBase64(ctx, cfg.Base58())
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}
	crpCfg, err := decodeCrpConfigV1(cfgRaw)
	if err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	if crpCfg.Paused {
		return errors.New("crp config is paused")
	}
	if crpCfg.DeploymentID != deploymentID {
		return errors.New("crp deployment_id mismatch")
	}
	if crpCfg.Threshold == 0 {
		return errors.New("crp config threshold=0")
	}

	sigInfos, err := rpc.SignaturesForAddress(ctx, cfg.Base58(), int(configScanLimit))
	if err != nil {
		return fmt.Errorf("getSignaturesForAddress(config): %w", err)
	}

	type candidate struct {
		Checkpoint solana.Pubkey
		Height     uint64
		Orchard    [32]byte
		CP         crpCheckpointV1
	}

	seenCheckpoints := make(map[solana.Pubkey]struct{}, int(maxCheckpoints))
	candidates := make([]candidate, 0, int(maxCheckpoints))

	for _, si := range sigInfos {
		if si.Err != nil {
			continue
		}
		txBytes, err := rpc.TransactionBytesBase64(ctx, si.Signature)
		if err != nil {
			continue
		}
		checkpoints, err := extractCheckpointsFromSubmitTx(txBytes, solana.Pubkey(crpProgram), cfg)
		if err != nil {
			continue
		}
		for _, chk := range checkpoints {
			if _, ok := seenCheckpoints[chk]; ok {
				continue
			}
			seenCheckpoints[chk] = struct{}{}

			raw, err := rpc.AccountDataBase64(ctx, chk.Base58())
			if err != nil {
				continue
			}
			cp, err := decodeCrpCheckpointV1(raw)
			if err != nil {
				continue
			}
			if cp.Version != 1 || cp.Finalized {
				continue
			}
			candidates = append(candidates, candidate{
				Checkpoint: chk,
				Height:     cp.Height,
				Orchard:    cp.OrchardRoot,
				CP:         cp,
			})
		}
	}

	if len(candidates) == 0 {
		fmt.Fprintln(os.Stderr, "no pending checkpoints found")
		return nil
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Height < candidates[j].Height })

	nowSlot, err := rpc.Slot(ctx)
	if err != nil {
		return err
	}

	var finalized uint
	for _, c := range candidates {
		if finalized >= maxCheckpoints {
			break
		}

		if nowSlot < c.CP.FirstSeenSlot+crpCfg.FinalizationDelaySlots {
			continue
		}

		// Sanity: ensure the checkpoint PDA matches (config, orchard_root).
		expectedCheckpoint, _, err := solana.FindProgramAddress(
			[][]byte{[]byte("checkpoint"), cfg[:], c.Orchard[:]},
			solana.Pubkey(crpProgram),
		)
		if err != nil || expectedCheckpoint != c.Checkpoint {
			continue
		}

		if err := finalizeCheckpointAuto(ctx, rpc, payerPriv, payerPub, crpProgram, deploymentID, cfg, crpCfg, c.Checkpoint, c.CP, scanLimit, cuLimit, priorityLevel, dryRun); err != nil {
			fmt.Fprintf(os.Stderr, "finalize %s (height=%d): %v\n", c.Checkpoint.Base58(), c.Height, err)
			continue
		}
		finalized++
		if dryRun {
			return nil
		}
	}

	if finalized == 0 {
		fmt.Fprintln(os.Stderr, "no checkpoints eligible for finalization")
	}
	return nil
}

func finalizeCheckpointAuto(
	ctx context.Context,
	rpc *solanarpc.Client,
	payerPriv ed25519.PrivateKey,
	payerPub [32]byte,
	crpProgram solana.Pubkey,
	deploymentID protocol.DeploymentID,
	cfg solana.Pubkey,
	crpCfg crpConfigV1,
	checkpoint solana.Pubkey,
	cp crpCheckpointV1,
	scanLimit uint,
	cuLimit uint,
	priorityLevel string,
	dryRun bool,
) error {
	heightRec, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("height"), cfg[:], u64LE(cp.Height)},
		solana.Pubkey(crpProgram),
	)
	if err != nil {
		return fmt.Errorf("derive height pda: %w", err)
	}

	allowed := make(map[solana.Pubkey]struct{}, int(crpCfg.OperatorCount))
	for i := 0; i < int(crpCfg.OperatorCount) && i < len(crpCfg.Operators); i++ {
		var pk solana.Pubkey
		copy(pk[:], crpCfg.Operators[i][:])
		allowed[pk] = struct{}{}
	}

	obs := protocol.CheckpointObservation{
		Height:      cp.Height,
		BlockHash:   protocol.JunoBlockHash(cp.BlockHash),
		OrchardRoot: protocol.OrchardRoot(cp.OrchardRoot),
		PrevHash:    protocol.JunoBlockHash(cp.PrevHash),
	}
	expectedMessage := obs.SigningBytes(deploymentID)

	sigInfos, err := rpc.SignaturesForAddress(ctx, checkpoint.Base58(), int(scanLimit))
	if err != nil {
		return fmt.Errorf("getSignaturesForAddress: %w", err)
	}

	collected := make([]operatorObservationSignature, 0, int(crpCfg.Threshold))
	seen := make(map[solana.Pubkey]struct{}, int(crpCfg.Threshold))
	for _, si := range sigInfos {
		if si.Err != nil {
			continue
		}
		txBytes, err := rpc.TransactionBytesBase64(ctx, si.Signature)
		if err != nil {
			continue
		}
		found, err := extractObservationSignaturesFromTx(txBytes, expectedMessage, allowed)
		if err != nil {
			continue
		}
		for _, s := range found {
			if _, ok := seen[s.Pubkey]; ok {
				continue
			}
			seen[s.Pubkey] = struct{}{}
			collected = append(collected, s)
			if len(collected) >= int(crpCfg.Threshold) {
				break
			}
		}
		if len(collected) >= int(crpCfg.Threshold) {
			break
		}
	}
	if len(collected) < int(crpCfg.Threshold) {
		return fmt.Errorf("insufficient operator signatures: got %d, need %d (try increasing --scan-limit)", len(collected), crpCfg.Threshold)
	}

	edIxs := make([]solana.Instruction, 0, int(crpCfg.Threshold))
	for _, s := range collected[:crpCfg.Threshold] {
		edIxs = append(edIxs, solana.Ed25519VerifyInstruction(s.Signature, s.Pubkey, expectedMessage))
	}

	// Optional: estimate priority fee via Helius.
	var microLamports uint64
	var feeKeys []string
	if hc, err := helius.ClientFromEnv(); err == nil {
		feeKeys = []string{
			solana.Pubkey(payerPub).Base58(),
			cfg.Base58(),
			checkpoint.Base58(),
			heightRec.Base58(),
			solana.SystemProgramID.Base58(),
			solana.InstructionsSysvarID.Base58(),
			solana.Ed25519ProgramID.Base58(),
			solana.Pubkey(crpProgram).Base58(),
		}
		est, err := hc.GetPriorityFeeEstimateByAccountKeys(ctx, helius.PriorityFeeEstimateByAccountKeysRequest{
			AccountKeys: feeKeys,
			Options: &helius.PriorityFeeOptions{
				PriorityLevel: helius.PriorityLevel(priorityLevel),
				Recommended:   true,
			},
		})
		if err == nil {
			microLamports = est.MicroLamports
		}
	}

	finalizeIx := solana.Instruction{
		ProgramID: solana.Pubkey(crpProgram),
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfg, IsSigner: false, IsWritable: true},
			{Pubkey: checkpoint, IsSigner: false, IsWritable: true},
			{Pubkey: heightRec, IsSigner: false, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: solana.InstructionsSysvarID, IsSigner: false, IsWritable: false},
		},
		Data: encodeCrpFinalize(uint8(len(edIxs))),
	}

	var ixs []solana.Instruction
	if cuLimit != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitLimit(uint32(cuLimit)))
	}
	if microLamports != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitPrice(microLamports))
	}
	ixs = append(ixs, edIxs...)
	ixs = append(ixs, finalizeIx)

	bh, err := rpc.LatestBlockhash(ctx)
	if err != nil {
		return err
	}
	tx, err := solana.BuildAndSignLegacyTransaction(
		bh,
		solana.Pubkey(payerPub),
		map[solana.Pubkey]ed25519.PrivateKey{solana.Pubkey(payerPub): payerPriv},
		ixs,
	)
	if err != nil {
		return err
	}

	if dryRun {
		if microLamports != 0 {
			fmt.Fprintf(os.Stderr, "priority_fee: cu_limit=%d microLamports=%d keys=%s\n", cuLimit, microLamports, strings.Join(feeKeys, ","))
		}
		fmt.Println(base64Std(tx))
		return nil
	}

	sigStr, err := rpc.SendTransaction(ctx, tx, false)
	if err != nil {
		return err
	}
	fmt.Println(sigStr)
	return nil
}

func extractCheckpointsFromSubmitTx(
	tx []byte,
	crpProgram solana.Pubkey,
	config solana.Pubkey,
) ([]solana.Pubkey, error) {
	msg, err := solana.ParseLegacyTransaction(tx)
	if err != nil {
		return nil, err
	}

	var out []solana.Pubkey
	for _, ix := range msg.Instructions {
		if ix.ProgramID != crpProgram {
			continue
		}
		// Borsh enum discriminant: SubmitObservation is 2.
		if len(ix.Data) == 0 || ix.Data[0] != 2 {
			continue
		}
		if len(ix.Accounts) < 3 {
			continue
		}
		cfgIdx := int(ix.Accounts[1])
		chkIdx := int(ix.Accounts[2])
		if cfgIdx < 0 || cfgIdx >= len(msg.AccountKeys) || chkIdx < 0 || chkIdx >= len(msg.AccountKeys) {
			continue
		}
		if msg.AccountKeys[cfgIdx] != config {
			continue
		}
		out = append(out, msg.AccountKeys[chkIdx])
	}
	return out, nil
}

func cmdDeployments(argv []string) error {
	fs := flag.NewFlagSet("deployments", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentFile string
		deploymentName string
		crpProgramStr  string
	)
	fs.StringVar(&deploymentName, "deployment", "", "Deployment name from deployments.json (fills --crp-program-id)")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployments registry file path")
	fs.StringVar(&crpProgramStr, "crp-program-id", "", "CRP program id (base58)")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if err := applyDeploymentRegistryDefaults(deploymentFile, deploymentName, &crpProgramStr, nil); err != nil {
		return err
	}
	if crpProgramStr == "" {
		return errors.New("--crp-program-id is required")
	}

	crpProgram, err := solana.ParsePubkey(crpProgramStr)
	if err != nil {
		return fmt.Errorf("parse --crp-program-id: %w", err)
	}

	rpc, err := solanarpc.ClientFromEnv()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	const crpConfigLenV1 = 1101
	accounts, err := rpc.ProgramAccountsByDataSizeBase64(ctx, crpProgram.Base58(), crpConfigLenV1)
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		return errors.New("no CRP config accounts found (wrong program id or no deployments?)")
	}

	for _, a := range accounts {
		cfg, err := decodeCrpConfigV1(a.Data)
		if err != nil {
			return fmt.Errorf("decode config %s: %w", a.Pubkey, err)
		}
		fmt.Printf("deployment_id=%s config=%s threshold=%d conflict_threshold=%d delay_slots=%d operators=%d paused=%v\n",
			hex.EncodeToString(cfg.DeploymentID[:]),
			a.Pubkey,
			cfg.Threshold,
			cfg.ConflictThreshold,
			cfg.FinalizationDelaySlots,
			cfg.OperatorCount,
			cfg.Paused,
		)
	}
	return nil
}

type multiString []string

func (m *multiString) String() string {
	return strings.Join(*m, ",")
}

func (m *multiString) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*m = append(*m, value)
	return nil
}

func parseHex32(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return out, errors.New("expected 32-byte hex (64 chars)")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, errors.New("invalid hex")
	}
	copy(out[:], b)
	return out, nil
}

func parseHex64(s string) ([64]byte, error) {
	var out [64]byte
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 128 {
		return out, errors.New("expected 64-byte hex (128 chars)")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 64 {
		return out, errors.New("invalid hex")
	}
	copy(out[:], b)
	return out, nil
}

type enclaveSignObservationParams struct {
	DeploymentID string `json:"deployment_id"`
	Height       uint64 `json:"height"`
	BlockHash    string `json:"block_hash"`
	OrchardRoot  string `json:"orchard_root"`
	PrevHash     string `json:"prev_hash"`
}

type enclaveSignObservationResult struct {
	SignerPubkeyHex string `json:"signer_pubkey_hex"`
	SignatureHex    string `json:"signature_hex"`
}

func signObservationViaEnclave(ctx context.Context, cid uint32, port uint32, deploymentID protocol.DeploymentID, obs protocol.CheckpointObservation) ([32]byte, [64]byte, error) {
	params := enclaveSignObservationParams{
		DeploymentID: deploymentID.Hex(),
		Height:       obs.Height,
		BlockHash:    hex.EncodeToString(obs.BlockHash[:]),
		OrchardRoot:  hex.EncodeToString(obs.OrchardRoot[:]),
		PrevHash:     hex.EncodeToString(obs.PrevHash[:]),
	}
	var resp enclaveSignObservationResult
	if err := nitro.Call(ctx, cid, port, "sign_observation", params, &resp); err != nil {
		return [32]byte{}, [64]byte{}, err
	}
	pub, err := parseHex32(resp.SignerPubkeyHex)
	if err != nil {
		return [32]byte{}, [64]byte{}, fmt.Errorf("invalid signer_pubkey_hex: %w", err)
	}
	sig, err := parseHex64(resp.SignatureHex)
	if err != nil {
		return [32]byte{}, [64]byte{}, fmt.Errorf("invalid signature_hex: %w", err)
	}
	return pub, sig, nil
}

func u64LE(v uint64) []byte {
	var out [8]byte
	out[0] = byte(v)
	out[1] = byte(v >> 8)
	out[2] = byte(v >> 16)
	out[3] = byte(v >> 24)
	out[4] = byte(v >> 32)
	out[5] = byte(v >> 40)
	out[6] = byte(v >> 48)
	out[7] = byte(v >> 56)
	return out[:]
}

func encodeCrpSubmitObservation(height uint64, blockHash [32]byte, orchardRoot [32]byte, prevHash [32]byte) []byte {
	// Borsh enum variant index (u8) for SubmitObservation is 2.
	out := make([]byte, 0, 1+8+32+32+32)
	out = append(out, 2)
	out = append(out, u64LE(height)...)
	out = append(out, blockHash[:]...)
	out = append(out, orchardRoot[:]...)
	out = append(out, prevHash[:]...)
	return out
}

func encodeCrpFinalize(sigCount uint8) []byte {
	// Borsh enum variant index (u8) for FinalizeCheckpoint is 3.
	return []byte{3, sigCount}
}

type crpCheckpointV1 struct {
	Version       uint8
	Height        uint64
	BlockHash     [32]byte
	OrchardRoot   [32]byte
	PrevHash      [32]byte
	FirstSeenSlot uint64
	Finalized     bool
}

func decodeCrpCheckpointV1(b []byte) (crpCheckpointV1, error) {
	const wantLen = 1 + 8 + 32 + 32 + 32 + 8 + 1
	if len(b) < wantLen {
		return crpCheckpointV1{}, fmt.Errorf("checkpoint too short: %d < %d", len(b), wantLen)
	}
	var out crpCheckpointV1
	out.Version = b[0]
	out.Height = uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 | uint64(b[4])<<24 |
		uint64(b[5])<<32 | uint64(b[6])<<40 | uint64(b[7])<<48 | uint64(b[8])<<56
	copy(out.BlockHash[:], b[9:41])
	copy(out.OrchardRoot[:], b[41:73])
	copy(out.PrevHash[:], b[73:105])
	out.FirstSeenSlot = uint64(b[105]) | uint64(b[106])<<8 | uint64(b[107])<<16 | uint64(b[108])<<24 |
		uint64(b[109])<<32 | uint64(b[110])<<40 | uint64(b[111])<<48 | uint64(b[112])<<56
	out.Finalized = b[113] != 0
	return out, nil
}

type crpConfigV1 struct {
	Version                uint8
	DeploymentID           [32]byte
	Admin                  [32]byte
	Threshold              uint8
	ConflictThreshold      uint8
	FinalizationDelaySlots uint64
	OperatorCount          uint8
	Operators              [32][32]byte
	Paused                 bool
}

func decodeCrpConfigV1(b []byte) (crpConfigV1, error) {
	const wantLen = 1 + 32 + 32 + 1 + 1 + 8 + 1 + (32 * 32) + 1
	if len(b) < wantLen {
		return crpConfigV1{}, fmt.Errorf("config too short: %d < %d", len(b), wantLen)
	}

	var out crpConfigV1
	out.Version = b[0]
	copy(out.DeploymentID[:], b[1:33])
	copy(out.Admin[:], b[33:65])
	out.Threshold = b[65]
	out.ConflictThreshold = b[66]
	out.FinalizationDelaySlots = binary.LittleEndian.Uint64(b[67:75])
	out.OperatorCount = b[75]
	off := 76
	for i := 0; i < 32; i++ {
		copy(out.Operators[i][:], b[off:off+32])
		off += 32
	}
	out.Paused = b[wantLen-1] != 0
	return out, nil
}

func base64Std(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	return base64Encode(enc, b)
}

func base64Encode(encoding string, src []byte) string {
	// Minimal base64 encoder to avoid pulling in extra deps.
	// This matches stdlib base64.StdEncoding.
	const pad = '='
	if len(encoding) != 64 {
		panic("invalid base64 encoding table")
	}

	dst := make([]byte, 0, ((len(src)+2)/3)*4)
	for i := 0; i < len(src); i += 3 {
		var b0, b1, b2 byte
		b0 = src[i]
		remain := len(src) - i
		if remain > 1 {
			b1 = src[i+1]
		}
		if remain > 2 {
			b2 = src[i+2]
		}

		dst = append(dst, encoding[b0>>2])
		dst = append(dst, encoding[((b0&0x03)<<4)|(b1>>4)])
		if remain > 1 {
			dst = append(dst, encoding[((b1&0x0f)<<2)|(b2>>6)])
		} else {
			dst = append(dst, pad)
		}
		if remain > 2 {
			dst = append(dst, encoding[b2&0x3f])
		} else {
			dst = append(dst, pad)
		}
	}

	return string(dst)
}

func cmdRun(argv []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentFile string
		deploymentName string

		crpProgramStr string
		deploymentHex string

		junocashPath string
		junocashArgs multiString

		startHeight  uint64
		lag          uint64
		pollInterval time.Duration

		payerPath                 string
		submitOperatorPath        string
		submitOperatorEnclaveCID  uint
		submitOperatorEnclavePort uint
		finalizeOperatorPaths     multiString

		cuLimitSubmit   uint
		cuLimitFinalize uint
		priorityLevel   string
		dryRun          bool
		once            bool
		submitOnly      bool
	)

	fs.StringVar(&deploymentName, "deployment", "", "Deployment name from deployments.json (fills --crp-program-id/--deployment-id)")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployments registry file path")
	fs.StringVar(&crpProgramStr, "crp-program-id", "", "CRP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&junocashPath, "junocash-cli", "junocash-cli", "Path to junocash-cli")
	fs.Var(&junocashArgs, "junocash-cli-arg", "Extra argument passed to junocash-cli (repeatable)")
	fs.Uint64Var(&startHeight, "start-height", 0, "First JunoCash height to observe")
	fs.Uint64Var(&lag, "lag", 10, "Only publish checkpoints at heights <= tip-lag (reorg safety)")
	fs.DurationVar(&pollInterval, "poll-interval", 10*time.Second, "Poll interval (e.g. 5s, 30s)")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.StringVar(&submitOperatorPath, "submit-operator-keypair", solvernet.DefaultSolanaKeypairPath(), "Submitter operator keypair (ed25519; Solana CLI JSON format)")
	fs.UintVar(&submitOperatorEnclaveCID, "submit-operator-enclave-cid", 0, "If set, signs SubmitObservation via Nitro enclave at this CID (disables --submit-operator-keypair)")
	fs.UintVar(&submitOperatorEnclavePort, "submit-operator-enclave-port", 5000, "Nitro enclave AF_VSOCK port")
	fs.Var(&finalizeOperatorPaths, "finalize-operator-keypair", "Finalizer operator keypair (repeatable; Solana CLI JSON format)")
	fs.UintVar(&cuLimitSubmit, "cu-limit-submit", 200_000, "Compute unit limit for SubmitObservation tx")
	fs.UintVar(&cuLimitFinalize, "cu-limit-finalize", 250_000, "Compute unit limit for FinalizeCheckpoint tx")
	fs.StringVar(&priorityLevel, "priority-level", string(helius.PriorityMedium), "Priority level (Min/Low/Medium/High/VeryHigh/UnsafeMax)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints base64 txs instead of sending them")
	fs.BoolVar(&once, "once", false, "If set, runs one poll cycle and exits")
	fs.BoolVar(&submitOnly, "submit-only", false, "If set, only submits observations (does not finalize checkpoints)")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if err := applyDeploymentRegistryDefaults(deploymentFile, deploymentName, &crpProgramStr, &deploymentHex); err != nil {
		return err
	}
	if crpProgramStr == "" || deploymentHex == "" {
		return errors.New("--crp-program-id and --deployment-id are required")
	}
	if pollInterval <= 0 {
		return errors.New("--poll-interval must be > 0")
	}
	if lag == 0 {
		return errors.New("--lag must be > 0 (reorg safety)")
	}
	if submitOperatorEnclaveCID != 0 {
		if submitOperatorEnclaveCID > 0xffff_ffff || submitOperatorEnclavePort == 0 || submitOperatorEnclavePort > 0xffff_ffff {
			return errors.New("--submit-operator-enclave-cid and --submit-operator-enclave-port must fit in u32 (and port must be > 0)")
		}
	}
	if !submitOnly && len(finalizeOperatorPaths) == 0 {
		return errors.New("at least one --finalize-operator-keypair is required (or pass --submit-only)")
	}

	crpProgram, err := solana.ParsePubkey(crpProgramStr)
	if err != nil {
		return fmt.Errorf("parse --crp-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}
	var submitterPriv ed25519.PrivateKey
	var submitterPub [32]byte
	if submitOperatorEnclaveCID == 0 {
		submitterPriv, submitterPub, err = solvernet.LoadSolanaKeypair(submitOperatorPath)
		if err != nil {
			return fmt.Errorf("load submitter keypair: %w", err)
		}
	}

	var finalizePrivs []ed25519.PrivateKey
	if !submitOnly {
		for _, p := range finalizeOperatorPaths {
			opPriv, _, err := solvernet.LoadSolanaKeypair(p)
			if err != nil {
				return fmt.Errorf("load finalizer keypair %q: %w", p, err)
			}
			finalizePrivs = append(finalizePrivs, opPriv)
		}
	}

	jc := junocashcli.New(junocashPath, []string(junocashArgs))

	rpc, err := solanarpc.ClientFromEnv()
	if err != nil {
		return err
	}

	cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, solana.Pubkey(crpProgram))
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cfgRaw, err := rpc.AccountDataBase64(ctx, cfgPDA.Base58())
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}
	cfg, err := decodeCrpConfigV1(cfgRaw)
	if err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	if cfg.Paused {
		return errors.New("crp config is paused")
	}
	if cfg.DeploymentID != deploymentID {
		return errors.New("crp deployment_id mismatch")
	}
	if cfg.Threshold == 0 {
		return errors.New("crp config threshold=0")
	}
	if !submitOnly && uint8(len(finalizePrivs)) < cfg.Threshold {
		return fmt.Errorf("need at least %d finalize keypairs, got %d", cfg.Threshold, len(finalizePrivs))
	}

	var heliusClient *helius.Client
	if hc, err := helius.ClientFromEnv(); err == nil {
		heliusClient = hc
	}

	type pendingCheckpoint struct {
		Height      uint64
		OrchardRoot [32]byte
	}
	var pending []pendingCheckpoint

	nextHeight := startHeight

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

		tip, err := jc.BlockCount(ctx)
		if err != nil {
			cancel()
			return err
		}
		if tip <= lag {
			cancel()
			if once {
				return nil
			}
			time.Sleep(pollInterval)
			continue
		}
		maxHeight := tip - lag

		for nextHeight <= maxHeight {
			bh, err := jc.BlockHash(ctx, nextHeight)
			if err != nil {
				cancel()
				return err
			}
			blk, err := jc.Block(ctx, bh)
			if err != nil {
				cancel()
				return err
			}
			if blk.Hash == "" {
				cancel()
				return errors.New("junocash getblock returned empty hash")
			}
			if blk.FinalOrchardRoot == "" {
				cancel()
				return errors.New("junocash getblock returned empty finalorchardroot (NU5 inactive?)")
			}
			if blk.PreviousBlockHash == "" && nextHeight != 0 {
				cancel()
				return errors.New("junocash getblock returned empty previousblockhash")
			}

			blockHash, err := parseHex32(blk.Hash)
			if err != nil {
				cancel()
				return fmt.Errorf("parse block hash: %w", err)
			}
			orchardRoot, err := parseHex32(blk.FinalOrchardRoot)
			if err != nil {
				cancel()
				return fmt.Errorf("parse finalorchardroot: %w", err)
			}

			var prevHash [32]byte
			if nextHeight != 0 {
				prevHash, err = parseHex32(blk.PreviousBlockHash)
				if err != nil {
					cancel()
					return fmt.Errorf("parse previousblockhash: %w", err)
				}
			}

			obs := protocol.CheckpointObservation{
				Height:      nextHeight,
				BlockHash:   protocol.JunoBlockHash(blockHash),
				OrchardRoot: protocol.OrchardRoot(orchardRoot),
				PrevHash:    protocol.JunoBlockHash(prevHash),
			}
			signingBytes := obs.SigningBytes(deploymentID)
			var sig64 [64]byte
			var opPub [32]byte
			if submitOperatorEnclaveCID != 0 {
				pk, sig, err := signObservationViaEnclave(ctx, uint32(submitOperatorEnclaveCID), uint32(submitOperatorEnclavePort), deploymentID, obs)
				if err != nil {
					cancel()
					return err
				}
				opPub = pk
				sig64 = sig
			} else {
				opPub = submitterPub
				sig := ed25519.Sign(ed25519.PrivateKey(submitterPriv), signingBytes)
				copy(sig64[:], sig)
			}

			checkpoint, _, err := solana.FindProgramAddress(
				[][]byte{[]byte("checkpoint"), cfgPDA[:], orchardRoot[:]},
				solana.Pubkey(crpProgram),
			)
			if err != nil {
				cancel()
				return fmt.Errorf("derive checkpoint pda: %w", err)
			}

			feeKeys := []string{
				solana.Pubkey(payerPub).Base58(),
				cfgPDA.Base58(),
				checkpoint.Base58(),
				solana.SystemProgramID.Base58(),
				solana.InstructionsSysvarID.Base58(),
				solana.Ed25519ProgramID.Base58(),
				solana.Pubkey(crpProgram).Base58(),
			}

			var microLamports uint64
			if heliusClient != nil {
				est, err := heliusClient.GetPriorityFeeEstimateByAccountKeys(ctx, helius.PriorityFeeEstimateByAccountKeysRequest{
					AccountKeys: feeKeys,
					Options: &helius.PriorityFeeOptions{
						PriorityLevel: helius.PriorityLevel(priorityLevel),
						Recommended:   true,
					},
				})
				if err == nil {
					microLamports = est.MicroLamports
				}
			}

			var ixs []solana.Instruction
			if cuLimitSubmit != 0 {
				ixs = append(ixs, solana.ComputeBudgetSetComputeUnitLimit(uint32(cuLimitSubmit)))
			}
			if microLamports != 0 {
				ixs = append(ixs, solana.ComputeBudgetSetComputeUnitPrice(microLamports))
			}
			ixs = append(ixs,
				solana.Ed25519VerifyInstruction(sig64, solana.Pubkey(opPub), signingBytes),
				solana.Instruction{
					ProgramID: solana.Pubkey(crpProgram),
					Accounts: []solana.AccountMeta{
						{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
						{Pubkey: cfgPDA, IsSigner: false, IsWritable: false},
						{Pubkey: checkpoint, IsSigner: false, IsWritable: true},
						{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
						{Pubkey: solana.InstructionsSysvarID, IsSigner: false, IsWritable: false},
					},
					Data: encodeCrpSubmitObservation(nextHeight, blockHash, orchardRoot, prevHash),
				},
			)

			bhSol, err := rpc.LatestBlockhash(ctx)
			if err != nil {
				cancel()
				return err
			}
			tx, err := solana.BuildAndSignLegacyTransaction(
				bhSol,
				solana.Pubkey(payerPub),
				map[solana.Pubkey]ed25519.PrivateKey{solana.Pubkey(payerPub): payerPriv},
				ixs,
			)
			if err != nil {
				cancel()
				return err
			}

			fmt.Fprintf(os.Stderr, "submit height=%d orchard_root=%x\n", nextHeight, orchardRoot)
			if dryRun {
				if microLamports != 0 {
					fmt.Fprintf(os.Stderr, "priority_fee: cu_limit=%d microLamports=%d keys=%s\n", cuLimitSubmit, microLamports, strings.Join(feeKeys, ","))
				}
				fmt.Println(base64Std(tx))
			} else {
				sigStr, err := rpc.SendTransaction(ctx, tx, false)
				if err != nil {
					cancel()
					return err
				}
				fmt.Fprintf(os.Stderr, "tx %s\n", sigStr)
			}

			if !submitOnly {
				pending = append(pending, pendingCheckpoint{Height: nextHeight, OrchardRoot: orchardRoot})
			}
			nextHeight++
		}

		curSlot, err := rpc.Slot(ctx)
		if err != nil {
			cancel()
			return err
		}

		if !submitOnly {
			for i := 0; i < len(pending); {
				p := pending[i]

				checkpoint, _, err := solana.FindProgramAddress(
					[][]byte{[]byte("checkpoint"), cfgPDA[:], p.OrchardRoot[:]},
					solana.Pubkey(crpProgram),
				)
				if err != nil {
					cancel()
					return err
				}
				cpRaw, err := rpc.AccountDataBase64(ctx, checkpoint.Base58())
				if err != nil {
					i++
					continue
				}
				cp, err := decodeCrpCheckpointV1(cpRaw)
				if err != nil {
					cancel()
					return err
				}
				if cp.Finalized {
					pending = append(pending[:i], pending[i+1:]...)
					continue
				}
				if curSlot < cp.FirstSeenSlot+cfg.FinalizationDelaySlots {
					i++
					continue
				}

				heightRec, _, err := solana.FindProgramAddress(
					[][]byte{[]byte("height"), cfgPDA[:], u64LE(cp.Height)},
					solana.Pubkey(crpProgram),
				)
				if err != nil {
					cancel()
					return err
				}

				obs := protocol.CheckpointObservation{
					Height:      cp.Height,
					BlockHash:   protocol.JunoBlockHash(cp.BlockHash),
					OrchardRoot: protocol.OrchardRoot(cp.OrchardRoot),
					PrevHash:    protocol.JunoBlockHash(cp.PrevHash),
				}
				signingBytes := obs.SigningBytes(deploymentID)

				var edIxs []solana.Instruction
				for _, priv := range finalizePrivs[:cfg.Threshold] {
					pub := priv.Public().(ed25519.PublicKey)
					var pk [32]byte
					copy(pk[:], pub)
					sig := ed25519.Sign(priv, signingBytes)
					var sig64 [64]byte
					copy(sig64[:], sig)
					edIxs = append(edIxs, solana.Ed25519VerifyInstruction(sig64, solana.Pubkey(pk), signingBytes))
				}

				feeKeys := []string{
					solana.Pubkey(payerPub).Base58(),
					cfgPDA.Base58(),
					checkpoint.Base58(),
					heightRec.Base58(),
					solana.SystemProgramID.Base58(),
					solana.InstructionsSysvarID.Base58(),
					solana.Ed25519ProgramID.Base58(),
					solana.Pubkey(crpProgram).Base58(),
				}

				var microLamports uint64
				if heliusClient != nil {
					est, err := heliusClient.GetPriorityFeeEstimateByAccountKeys(ctx, helius.PriorityFeeEstimateByAccountKeysRequest{
						AccountKeys: feeKeys,
						Options: &helius.PriorityFeeOptions{
							PriorityLevel: helius.PriorityLevel(priorityLevel),
							Recommended:   true,
						},
					})
					if err == nil {
						microLamports = est.MicroLamports
					}
				}

				var ixs []solana.Instruction
				if cuLimitFinalize != 0 {
					ixs = append(ixs, solana.ComputeBudgetSetComputeUnitLimit(uint32(cuLimitFinalize)))
				}
				if microLamports != 0 {
					ixs = append(ixs, solana.ComputeBudgetSetComputeUnitPrice(microLamports))
				}
				ixs = append(ixs, edIxs...)
				ixs = append(ixs, solana.Instruction{
					ProgramID: solana.Pubkey(crpProgram),
					Accounts: []solana.AccountMeta{
						{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
						{Pubkey: cfgPDA, IsSigner: false, IsWritable: true},
						{Pubkey: checkpoint, IsSigner: false, IsWritable: true},
						{Pubkey: heightRec, IsSigner: false, IsWritable: true},
						{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
						{Pubkey: solana.InstructionsSysvarID, IsSigner: false, IsWritable: false},
					},
					Data: encodeCrpFinalize(uint8(len(edIxs))),
				})

				bhSol, err := rpc.LatestBlockhash(ctx)
				if err != nil {
					cancel()
					return err
				}
				tx, err := solana.BuildAndSignLegacyTransaction(
					bhSol,
					solana.Pubkey(payerPub),
					map[solana.Pubkey]ed25519.PrivateKey{solana.Pubkey(payerPub): payerPriv},
					ixs,
				)
				if err != nil {
					cancel()
					return err
				}

				fmt.Fprintf(os.Stderr, "finalize height=%d orchard_root=%x\n", cp.Height, cp.OrchardRoot)
				if dryRun {
					if microLamports != 0 {
						fmt.Fprintf(os.Stderr, "priority_fee: cu_limit=%d microLamports=%d keys=%s\n", cuLimitFinalize, microLamports, strings.Join(feeKeys, ","))
					}
					fmt.Println(base64Std(tx))
				} else {
					sigStr, err := rpc.SendTransaction(ctx, tx, false)
					if err != nil {
						cancel()
						return err
					}
					fmt.Fprintf(os.Stderr, "tx %s\n", sigStr)
				}

				// Remove from pending after we attempt finalization.
				pending = append(pending[:i], pending[i+1:]...)
			}
		}

		cancel()

		if once {
			return nil
		}
		time.Sleep(pollInterval)
	}
}
