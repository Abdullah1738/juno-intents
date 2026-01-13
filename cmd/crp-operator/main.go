package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-intents/offchain/helius"
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
	default:
		return fmt.Errorf("unknown command: %s", argv[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "crp-operator: CheckpointRegistry operator tooling")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  crp-operator submit --crp-program-id <base58> --deployment-id <hex32> --height <u64> --block-hash <hex32> --orchard-root <hex32> --prev-hash <hex32> [--payer-keypair <path>] [--operator-keypair <path>] [--cu-limit <u32>] [--priority-level <level>] [--dry-run]")
	fmt.Fprintln(w, "  crp-operator finalize --crp-program-id <base58> --deployment-id <hex32> --height <u64> --orchard-root <hex32> --operator-keypair <path> [--operator-keypair <path>...] [--payer-keypair <path>] [--cu-limit <u32>] [--priority-level <level>] [--dry-run]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Environment:")
	fmt.Fprintln(w, "  SOLANA_RPC_URL or HELIUS_RPC_URL or HELIUS_API_KEY/HELIUS_CLUSTER")
}

func cmdSubmit(argv []string) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		crpProgramStr string
		deploymentHex string
		height        uint64
		blockHashHex  string
		orchardHex    string
		prevHashHex   string

		payerPath    string
		operatorPath string

		cuLimit       uint
		priorityLevel string
		dryRun        bool
	)

	fs.StringVar(&crpProgramStr, "crp-program-id", "", "CRP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.Uint64Var(&height, "height", 0, "JunoCash height")
	fs.StringVar(&blockHashHex, "block-hash", "", "JunoCash block hash (32-byte hex)")
	fs.StringVar(&orchardHex, "orchard-root", "", "Orchard root (32-byte hex)")
	fs.StringVar(&prevHashHex, "prev-hash", "", "JunoCash prev hash (32-byte hex)")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.StringVar(&operatorPath, "operator-keypair", solvernet.DefaultSolanaKeypairPath(), "Operator ed25519 keypair path (Solana CLI JSON format)")

	fs.UintVar(&cuLimit, "cu-limit", 200_000, "Compute unit limit")
	fs.StringVar(&priorityLevel, "priority-level", string(helius.PriorityMedium), "Priority level (Min/Low/Medium/High/VeryHigh/UnsafeMax)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if crpProgramStr == "" || deploymentHex == "" || blockHashHex == "" || orchardHex == "" || prevHashHex == "" {
		return errors.New("--crp-program-id, --deployment-id, --block-hash, --orchard-root, and --prev-hash are required")
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
	operatorPriv, operatorPub, err := solvernet.LoadSolanaKeypair(operatorPath)
	if err != nil {
		return fmt.Errorf("load operator keypair: %w", err)
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
	sig := ed25519.Sign(ed25519.PrivateKey(operatorPriv), signingBytes)
	var sig64 [64]byte
	copy(sig64[:], sig)

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
	if hc, err := helius.ClientFromEnv(); err == nil {
		keys := []string{
			solana.Pubkey(payerPub).Base58(),
			cfg.Base58(),
			checkpoint.Base58(),
			solana.SystemProgramID.Base58(),
			solana.InstructionsSysvarID.Base58(),
			solana.Ed25519ProgramID.Base58(),
			solana.Pubkey(crpProgram).Base58(),
		}
		est, err := hc.GetPriorityFeeEstimateByAccountKeys(ctx, helius.PriorityFeeEstimateByAccountKeysRequest{
			AccountKeys: keys,
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
	if hc, err := helius.ClientFromEnv(); err == nil {
		keys := []string{
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
			AccountKeys: keys,
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
	// Borsh enum variant index (u8) for SubmitObservation is 3.
	out := make([]byte, 0, 1+8+32+32+32)
	out = append(out, 3)
	out = append(out, u64LE(height)...)
	out = append(out, blockHash[:]...)
	out = append(out, orchardRoot[:]...)
	out = append(out, prevHash[:]...)
	return out
}

func encodeCrpFinalize(sigCount uint8) []byte {
	// Borsh enum variant index (u8) for FinalizeCheckpoint is 4.
	return []byte{4, sigCount}
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

