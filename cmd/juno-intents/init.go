package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
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
	"github.com/Abdullah1738/juno-intents/protocol"
)

func cmdInitCRP(argv []string) error {
	fs := flag.NewFlagSet("init-crp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		crpProgramStr string
		deploymentHex string
		adminStr      string
		threshold     uint
		conflict      uint
		delaySlots    uint64

		payerPath string
		operators multiString
		dryRun    bool
	)

	fs.StringVar(&crpProgramStr, "crp-program-id", "", "CRP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&adminStr, "admin", "", "Admin pubkey (base58)")
	fs.UintVar(&threshold, "threshold", 0, "t-of-n threshold (u8)")
	fs.UintVar(&conflict, "conflict-threshold", 0, "conflict threshold (u8)")
	fs.Uint64Var(&delaySlots, "finalization-delay-slots", 0, "Finalization delay in Solana slots (u64)")
	fs.Var(&operators, "operator", "Operator pubkey (base58), repeatable")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if crpProgramStr == "" || deploymentHex == "" || adminStr == "" {
		return errors.New("--crp-program-id, --deployment-id, and --admin are required")
	}
	if threshold == 0 || threshold > 255 {
		return errors.New("--threshold must be 1..255")
	}
	if conflict < 2 || conflict > 255 {
		return errors.New("--conflict-threshold must be 2..255")
	}
	if len(operators) == 0 {
		return errors.New("at least one --operator is required")
	}
	if threshold > uint(len(operators)) || conflict > uint(len(operators)) {
		return errors.New("--threshold/--conflict-threshold must be <= number of operators")
	}

	crpProgram, err := solana.ParsePubkey(crpProgramStr)
	if err != nil {
		return fmt.Errorf("parse --crp-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}
	admin, err := solana.ParsePubkey(adminStr)
	if err != nil {
		return fmt.Errorf("parse --admin: %w", err)
	}

	var operatorPubkeys []solana.Pubkey
	for _, s := range operators {
		pk, err := solana.ParsePubkey(s)
		if err != nil {
			return fmt.Errorf("parse --operator %q: %w", s, err)
		}
		operatorPubkeys = append(operatorPubkeys, pk)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, crpProgram)
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}

	ix := solana.Instruction{
		ProgramID: crpProgram,
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfgPDA, IsSigner: false, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
		},
		Data: encodeCrpInitialize([32]byte(deploymentID), admin, uint8(threshold), uint8(conflict), delaySlots, operatorPubkeys),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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
		[]solana.Instruction{ix},
	)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "crp_config=%s\n", cfgPDA.Base58())
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

func cmdInitIEP(argv []string) error {
	fs := flag.NewFlagSet("init-iep", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		iepProgramStr string
		deploymentHex string
		adminStr      string
		feeBps        uint
		feeCollector  string
		crpProgramStr string
		verifierStr   string

		payerPath string
		dryRun    bool
	)

	fs.StringVar(&iepProgramStr, "iep-program-id", "", "IEP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&adminStr, "admin", "", "Admin pubkey (base58)")
	fs.UintVar(&feeBps, "fee-bps", 0, "Protocol fee bps (u16)")
	fs.StringVar(&feeCollector, "fee-collector", "", "Fee collector pubkey (base58)")
	fs.StringVar(&crpProgramStr, "checkpoint-registry-program", "", "CRP program id (base58)")
	fs.StringVar(&verifierStr, "receipt-verifier-program", "", "Receipt verifier program id (base58)")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if iepProgramStr == "" || deploymentHex == "" || adminStr == "" || feeCollector == "" || crpProgramStr == "" || verifierStr == "" {
		return errors.New("missing required args (see --help)")
	}
	if feeBps > 65_535 {
		return errors.New("--fee-bps must fit in u16")
	}

	iepProgram, err := solana.ParsePubkey(iepProgramStr)
	if err != nil {
		return fmt.Errorf("parse --iep-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}
	admin, err := solana.ParsePubkey(adminStr)
	if err != nil {
		return fmt.Errorf("parse --admin: %w", err)
	}
	feeCollectorPK, err := solana.ParsePubkey(feeCollector)
	if err != nil {
		return fmt.Errorf("parse --fee-collector: %w", err)
	}
	crpProgram, err := solana.ParsePubkey(crpProgramStr)
	if err != nil {
		return fmt.Errorf("parse --checkpoint-registry-program: %w", err)
	}
	verifierProgram, err := solana.ParsePubkey(verifierStr)
	if err != nil {
		return fmt.Errorf("parse --receipt-verifier-program: %w", err)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, iepProgram)
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}

	ix := solana.Instruction{
		ProgramID: iepProgram,
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfgPDA, IsSigner: false, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
		},
		Data: encodeIepInitialize([32]byte(deploymentID), admin, uint16(feeBps), feeCollectorPK, crpProgram, verifierProgram),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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
		[]solana.Instruction{ix},
	)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "iep_config=%s\n", cfgPDA.Base58())
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

func encodeCrpInitialize(
	deploymentID [32]byte,
	admin solana.Pubkey,
	threshold uint8,
	conflictThreshold uint8,
	finalizationDelaySlots uint64,
	operators []solana.Pubkey,
) []byte {
	// Borsh enum variant index (u8) for Initialize is 0.
	out := make([]byte, 0, 1+32+32+1+1+8+4+(len(operators)*32))
	out = append(out, 0)
	out = append(out, deploymentID[:]...)
	out = append(out, admin[:]...)
	out = append(out, threshold)
	out = append(out, conflictThreshold)

	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], finalizationDelaySlots)
	out = append(out, tmp8[:]...)

	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], uint32(len(operators)))
	out = append(out, tmp4[:]...)
	for _, pk := range operators {
		out = append(out, pk[:]...)
	}
	return out
}

func encodeIepInitialize(
	deploymentID [32]byte,
	admin solana.Pubkey,
	feeBps uint16,
	feeCollector solana.Pubkey,
	checkpointRegistryProgram solana.Pubkey,
	receiptVerifierProgram solana.Pubkey,
) []byte {
	// Borsh enum variant index (u8) for Initialize is 0.
	out := make([]byte, 0, 1+32+32+2+32+32+32)
	out = append(out, 0)
	out = append(out, deploymentID[:]...)
	out = append(out, admin[:]...)

	var tmp2 [2]byte
	binary.LittleEndian.PutUint16(tmp2[:], feeBps)
	out = append(out, tmp2[:]...)

	out = append(out, feeCollector[:]...)
	out = append(out, checkpointRegistryProgram[:]...)
	out = append(out, receiptVerifierProgram[:]...)
	return out
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
