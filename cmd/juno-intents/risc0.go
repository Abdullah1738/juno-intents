package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-intents/offchain/solana"
	"github.com/Abdullah1738/juno-intents/offchain/solanarpc"
	"github.com/Abdullah1738/juno-intents/offchain/solvernet"
)

var bpfLoaderUpgradeableProgramID = mustParsePubkeyBase58("BPFLoaderUpgradeab1e11111111111111111111111")

func mustParsePubkeyBase58(s string) solana.Pubkey {
	pk, err := solana.ParsePubkey(s)
	if err != nil {
		panic(err)
	}
	return pk
}

func cmdRisc0PDA(argv []string) error {
	fs := flag.NewFlagSet("risc0-pda", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		routerProgramStr string
		selectorStr      string
		printField       string
	)
	fs.StringVar(&routerProgramStr, "verifier-router-program-id", "", "Verifier router program id (base58 or 32-byte hex)")
	fs.StringVar(&selectorStr, "selector", "JINT", "4-byte selector (ascii like JINT, or hex like 4a494e54 / 0x4a494e54)")
	fs.StringVar(&printField, "print", "router", "What to print: router|verifier-entry")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}
	if strings.TrimSpace(routerProgramStr) == "" {
		return errors.New("--verifier-router-program-id is required")
	}

	routerProgramBytes, err := parsePubkey(routerProgramStr)
	if err != nil {
		return fmt.Errorf("parse --verifier-router-program-id: %w", err)
	}
	selector, err := parseSelector4(selectorStr)
	if err != nil {
		return fmt.Errorf("parse --selector: %w", err)
	}

	routerPDA, _, err := findProgramAddress([][]byte{[]byte("router")}, routerProgramBytes)
	if err != nil {
		return fmt.Errorf("derive router pda: %w", err)
	}
	entryPDA, _, err := findProgramAddress(
		[][]byte{[]byte("verifier"), selector[:]},
		routerProgramBytes,
	)
	if err != nil {
		return fmt.Errorf("derive verifier entry pda: %w", err)
	}

	switch printField {
	case "router":
		fmt.Println(solana.Pubkey(routerPDA).Base58())
	case "verifier-entry":
		fmt.Println(solana.Pubkey(entryPDA).Base58())
	default:
		return fmt.Errorf("invalid --print: %s", printField)
	}
	return nil
}

func cmdInitRisc0Verifier(argv []string) error {
	fs := flag.NewFlagSet("init-risc0-verifier", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		routerProgramStr  string
		verifierProgramStr string
		selectorStr       string
		payerPath         string
		dryRun            bool
	)
	fs.StringVar(&routerProgramStr, "verifier-router-program-id", "", "Verifier router program id (base58 or 32-byte hex)")
	fs.StringVar(&verifierProgramStr, "verifier-program-id", "", "Groth16 verifier program id (base58 or 32-byte hex)")
	fs.StringVar(&selectorStr, "selector", "JINT", "4-byte selector (ascii like JINT, or hex like 4a494e54 / 0x4a494e54)")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer/owner keypair (Solana CLI JSON format)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}
	if strings.TrimSpace(routerProgramStr) == "" || strings.TrimSpace(verifierProgramStr) == "" {
		return errors.New("--verifier-router-program-id and --verifier-program-id are required")
	}

	routerProgramBytes, err := parsePubkey(routerProgramStr)
	if err != nil {
		return fmt.Errorf("parse --verifier-router-program-id: %w", err)
	}
	verifierProgramBytes, err := parsePubkey(verifierProgramStr)
	if err != nil {
		return fmt.Errorf("parse --verifier-program-id: %w", err)
	}
	selector, err := parseSelector4(selectorStr)
	if err != nil {
		return fmt.Errorf("parse --selector: %w", err)
	}

	routerPDA, _, err := findProgramAddress([][]byte{[]byte("router")}, routerProgramBytes)
	if err != nil {
		return fmt.Errorf("derive router pda: %w", err)
	}
	verifierEntryPDA, _, err := findProgramAddress(
		[][]byte{[]byte("verifier"), selector[:]},
		routerProgramBytes,
	)
	if err != nil {
		return fmt.Errorf("derive verifier entry pda: %w", err)
	}
	verifierProgramDataPDA, _, err := findProgramAddress(
		[][]byte{verifierProgramBytes[:]},
		[32]byte(bpfLoaderUpgradeableProgramID),
	)
	if err != nil {
		return fmt.Errorf("derive verifier programdata pda: %w", err)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	discInit := anchorDiscriminator("initialize")
	initIx := solana.Instruction{
		ProgramID: solana.Pubkey(routerProgramBytes),
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(routerPDA), IsSigner: false, IsWritable: true},
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
		},
		Data: discInit[:],
	}

	// verifier_router::add_verifier instruction
	discAdd := anchorDiscriminator("add_verifier")
	addData := make([]byte, 0, 8+4)
	addData = append(addData, discAdd[:]...)
	addData = append(addData, selector[:]...)

	addIx := solana.Instruction{
		ProgramID: solana.Pubkey(routerProgramBytes),
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(routerPDA), IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(verifierEntryPDA), IsSigner: false, IsWritable: true},
			{Pubkey: solana.Pubkey(verifierProgramDataPDA), IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(verifierProgramBytes), IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
		},
		Data: addData,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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
		[]solana.Instruction{initIx, addIx},
	)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "router=%s\n", solana.Pubkey(routerPDA).Base58())
	fmt.Fprintf(os.Stderr, "verifier_entry=%s\n", solana.Pubkey(verifierEntryPDA).Base58())
	fmt.Fprintf(os.Stderr, "selector=0x%s\n", hex.EncodeToString(selector[:]))
	if dryRun {
		fmt.Println(base64.StdEncoding.EncodeToString(tx))
		return nil
	}

	sig, err := rpc.SendTransaction(ctx, tx, false)
	if err != nil {
		return err
	}
	fmt.Println(sig)
	return nil
}

func anchorDiscriminator(method string) [8]byte {
	sum := sha256.Sum256([]byte("global:" + method))
	var out [8]byte
	copy(out[:], sum[:8])
	return out
}

func parseSelector4(s string) ([4]byte, error) {
	var out [4]byte
	s = strings.TrimSpace(s)
	if s == "" {
		return out, errors.New("selector required")
	}
	raw := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(raw) == 4 && raw == s {
		copy(out[:], []byte(raw))
		return out, nil
	}
	if len(raw) != 8 {
		return out, fmt.Errorf("expected 4 ascii chars or 4-byte hex (8 chars), got %q", s)
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != 4 {
		return out, fmt.Errorf("invalid selector hex: %q", s)
	}
	copy(out[:], b)
	return out, nil
}
