package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
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
	"github.com/Abdullah1738/juno-intents/protocol"
)

func cmdInitORP(argv []string) error {
	fs := flag.NewFlagSet("init-orp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		orpProgramStr       string
		deploymentHex       string
		adminStr            string
		chainID             uint
		genesisHex          string
		routerProgramStr    string
		verifierProgramStr  string
		allowedMeasurements multiString

		payerPath string
		dryRun    bool
	)

	fs.StringVar(&orpProgramStr, "orp-program-id", "", "OperatorRegistry program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&adminStr, "admin", "", "Admin pubkey (base58)")
	fs.UintVar(&chainID, "junocash-chain-id", 0, "JunoCash chain id (u8)")
	fs.StringVar(&genesisHex, "junocash-genesis-hash", "", "JunoCash genesis block hash (32-byte hex)")
	fs.StringVar(&routerProgramStr, "verifier-router-program", "", "RISC0 verifier router program id (base58)")
	fs.StringVar(&verifierProgramStr, "verifier-program-id", "", "RISC0 Groth16 verifier program id (base58)")
	fs.Var(&allowedMeasurements, "allowed-measurement", "Allowed PCR measurement digest (hex32), repeatable")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if orpProgramStr == "" || deploymentHex == "" || adminStr == "" || genesisHex == "" || routerProgramStr == "" || verifierProgramStr == "" {
		return errors.New("missing required args (see --help)")
	}
	if chainID > 255 {
		return errors.New("--junocash-chain-id must fit in u8")
	}
	if len(allowedMeasurements) == 0 {
		return errors.New("at least one --allowed-measurement is required")
	}

	orpProgram, err := solana.ParsePubkey(orpProgramStr)
	if err != nil {
		return fmt.Errorf("parse --orp-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}
	admin, err := solana.ParsePubkey(adminStr)
	if err != nil {
		return fmt.Errorf("parse --admin: %w", err)
	}
	genesisHash, err := parseHex32(genesisHex)
	if err != nil {
		return fmt.Errorf("parse --junocash-genesis-hash: %w", err)
	}
	routerProgram, err := solana.ParsePubkey(routerProgramStr)
	if err != nil {
		return fmt.Errorf("parse --verifier-router-program: %w", err)
	}
	verifierProgram, err := solana.ParsePubkey(verifierProgramStr)
	if err != nil {
		return fmt.Errorf("parse --verifier-program-id: %w", err)
	}

	var measurements [][32]byte
	for _, m := range allowedMeasurements {
		b, err := parseHex32(m)
		if err != nil {
			return fmt.Errorf("parse --allowed-measurement %q: %w", m, err)
		}
		measurements = append(measurements, b)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, orpProgram)
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}

	// ORP enforces a fixed selector ("JINT") on-chain. Compute the expected router PDAs.
	router, _, err := solana.FindProgramAddress([][]byte{[]byte("router")}, routerProgram)
	if err != nil {
		return fmt.Errorf("derive verifier router pda: %w", err)
	}
	verifierEntry, _, err := solana.FindProgramAddress([][]byte{[]byte("verifier"), []byte("JINT")}, routerProgram)
	if err != nil {
		return fmt.Errorf("derive verifier entry pda: %w", err)
	}

	ix := solana.Instruction{
		ProgramID: orpProgram,
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfgPDA, IsSigner: false, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
		},
		Data: encodeOrpInitialize([32]byte(deploymentID), admin, uint8(chainID), genesisHash, routerProgram, router, verifierEntry, verifierProgram, measurements),
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

	fmt.Fprintf(os.Stderr, "orp_config=%s\n", cfgPDA.Base58())
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

func cmdOrpRegisterOperator(argv []string) error {
	fs := flag.NewFlagSet("orp-register-operator", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		orpProgramStr string
		deploymentHex string
		bundleHex     string
		payerPath     string
		dryRun        bool
	)

	fs.StringVar(&orpProgramStr, "orp-program-id", "", "OperatorRegistry program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&bundleHex, "bundle-hex", "", "Attestation Groth16 bundle hex")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if orpProgramStr == "" || deploymentHex == "" || bundleHex == "" {
		return errors.New("missing required args (see --help)")
	}

	orpProgram, err := solana.ParsePubkey(orpProgramStr)
	if err != nil {
		return fmt.Errorf("parse --orp-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}

	bundleHex = strings.TrimSpace(strings.TrimPrefix(bundleHex, "0x"))
	bundle, err := hex.DecodeString(bundleHex)
	if err != nil {
		return fmt.Errorf("decode --bundle-hex: %w", err)
	}
	operatorPubkey, err := operatorPubkeyFromAttestationBundleV1(bundle)
	if err != nil {
		return fmt.Errorf("parse attestation bundle: %w", err)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, orpProgram)
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}
	opRec, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("operator"), deploymentID[:], operatorPubkey[:]},
		orpProgram,
	)
	if err != nil {
		return fmt.Errorf("derive operator record pda: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	rpc, err := solanarpc.ClientFromEnv()
	if err != nil {
		return err
	}

	cfgData, err := rpc.AccountDataBase64(ctx, cfgPDA.Base58())
	if err != nil {
		return fmt.Errorf("fetch ORP config: %w", err)
	}
	cfg, err := parseOrpConfigV1(cfgData)
	if err != nil {
		return fmt.Errorf("parse ORP config: %w", err)
	}
	if cfg.DeploymentID != [32]byte(deploymentID) {
		return errors.New("orp config deployment_id mismatch")
	}
	if cfg.Admin != solana.Pubkey(payerPub) {
		return errors.New("payer is not ORP admin")
	}

	ix := solana.Instruction{
		ProgramID: orpProgram,
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfgPDA, IsSigner: false, IsWritable: false},
			{Pubkey: opRec, IsSigner: false, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: cfg.VerifierRouterProgram, IsSigner: false, IsWritable: false},
			{Pubkey: cfg.Router, IsSigner: false, IsWritable: false},
			{Pubkey: cfg.VerifierEntry, IsSigner: false, IsWritable: false},
			{Pubkey: cfg.VerifierProgram, IsSigner: false, IsWritable: false},
		},
		Data: encodeOrpRegisterOperator(bundle),
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

	fmt.Fprintf(os.Stderr, "operator_record=%s\n", opRec.Base58())
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

func encodeOrpInitialize(
	deploymentID [32]byte,
	admin solana.Pubkey,
	chainID uint8,
	genesisHash [32]byte,
	verifierRouterProgram solana.Pubkey,
	router solana.Pubkey,
	verifierEntry solana.Pubkey,
	verifierProgram solana.Pubkey,
	allowedMeasurements [][32]byte,
) []byte {
	// Borsh enum variant index (u8) for Initialize is 0.
	out := make([]byte, 0, 1+32+32+1+32+(32*4)+4+len(allowedMeasurements)*32)
	out = append(out, 0)
	out = append(out, deploymentID[:]...)
	out = append(out, admin[:]...)
	out = append(out, chainID)
	out = append(out, genesisHash[:]...)
	out = append(out, verifierRouterProgram[:]...)
	out = append(out, router[:]...)
	out = append(out, verifierEntry[:]...)
	out = append(out, verifierProgram[:]...)
	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], uint32(len(allowedMeasurements)))
	out = append(out, tmp4[:]...)
	for _, m := range allowedMeasurements {
		out = append(out, m[:]...)
	}
	return out
}

func encodeOrpRegisterOperator(bundle []byte) []byte {
	// Borsh enum variant index (u8) for RegisterOperator is 1.
	out := make([]byte, 0, 1+4+len(bundle))
	out = append(out, 1)
	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], uint32(len(bundle)))
	out = append(out, tmp4[:]...)
	out = append(out, bundle...)
	return out
}

type orpConfigV1 struct {
	Version uint8

	DeploymentID [32]byte
	Admin        solana.Pubkey

	JunocashChainID     uint8
	JunocashGenesisHash [32]byte

	VerifierRouterProgram solana.Pubkey
	Router                solana.Pubkey
	VerifierEntry         solana.Pubkey
	VerifierProgram       solana.Pubkey
}

func parseOrpConfigV1(b []byte) (orpConfigV1, error) {
	const wantLen = 739
	if len(b) != wantLen {
		return orpConfigV1{}, fmt.Errorf("unexpected config len: %d (want %d)", len(b), wantLen)
	}

	var out orpConfigV1
	out.Version = b[0]
	if out.Version != 1 {
		return orpConfigV1{}, fmt.Errorf("unexpected config version: %d", out.Version)
	}
	var off int
	off = 1
	copy(out.DeploymentID[:], b[off:off+32])
	off += 32
	copy(out.Admin[:], b[off:off+32])
	off += 32
	out.JunocashChainID = b[off]
	off += 1
	copy(out.JunocashGenesisHash[:], b[off:off+32])
	off += 32

	// Skip measurement_count + fixed MAX_MEASUREMENTS array.
	off += 1 + (32 * 16)

	copy(out.VerifierRouterProgram[:], b[off:off+32])
	off += 32
	copy(out.Router[:], b[off:off+32])
	off += 32
	copy(out.VerifierEntry[:], b[off:off+32])
	off += 32
	copy(out.VerifierProgram[:], b[off:off+32])
	off += 32

	if off != wantLen {
		return orpConfigV1{}, errors.New("internal parse error")
	}
	return out, nil
}

func operatorPubkeyFromAttestationBundleV1(bundle []byte) ([32]byte, error) {
	var out [32]byte
	// Mirror on-chain parse requirements:
	// version_u16_le || proof_system_u8 || image_id_32 || journal_len_u16_le || journal_bytes || seal_len_u32_le || seal_bytes
	const journalLen = 2 + 32 + 1 + 32 + 32 + 32
	const sealLen = 260
	const minLen = 2 + 1 + 32 + 2 + journalLen + 4 + sealLen
	if len(bundle) < minLen {
		return out, errors.New("bundle too short")
	}
	if binary.LittleEndian.Uint16(bundle[0:2]) != 1 {
		return out, errors.New("unsupported bundle version")
	}
	jl := int(binary.LittleEndian.Uint16(bundle[35:37]))
	if jl != journalLen {
		return out, errors.New("unexpected journal len")
	}
	journalOff := 37
	journalEnd := journalOff + jl
	if len(bundle) < journalEnd+4 {
		return out, errors.New("bundle too short")
	}
	sl := int(binary.LittleEndian.Uint32(bundle[journalEnd : journalEnd+4]))
	if sl != sealLen {
		return out, errors.New("unexpected seal len")
	}
	if len(bundle) != journalEnd+4+sl {
		return out, errors.New("unexpected bundle len")
	}
	journal := bundle[journalOff:journalEnd]
	if binary.LittleEndian.Uint16(journal[0:2]) != 1 {
		return out, errors.New("unsupported journal version")
	}
	const operatorOff = 2 + 32 + 1 + 32
	copy(out[:], journal[operatorOff:operatorOff+32])
	return out, nil
}
