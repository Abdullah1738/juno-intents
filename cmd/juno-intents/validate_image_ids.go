package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-intents/offchain/deployments"
	"github.com/Abdullah1738/juno-intents/offchain/solana"
	"github.com/Abdullah1738/juno-intents/offchain/solanarpc"
	"github.com/Abdullah1738/juno-intents/offchain/solvernet"
)

func cmdValidateImageIDs(argv []string) error {
	fs := flag.NewFlagSet("validate-image-ids", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentName string
		deploymentFile string
		payerPath      string
	)

	fs.StringVar(&deploymentName, "deployment", "", "Deployment name in deployments.json")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployment registry JSON file path")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if strings.TrimSpace(deploymentName) == "" {
		return errors.New("--deployment is required")
	}
	if strings.TrimSpace(payerPath) == "" {
		return errors.New("--payer-keypair is required")
	}

	reg, err := deployments.Load(deploymentFile)
	if err != nil {
		return err
	}
	d, err := reg.FindByName(deploymentName)
	if err != nil {
		return err
	}

	if strings.TrimSpace(d.RPCURL) == "" {
		return errors.New("deployment missing rpc_url")
	}

	orpProgram, err := solana.ParsePubkey(d.OperatorRegistryProgramID)
	if err != nil {
		return fmt.Errorf("parse ORP program id: %w", err)
	}
	rvProgram, err := solana.ParsePubkey(d.ReceiptVerifierProgramID)
	if err != nil {
		return fmt.Errorf("parse receipt verifier program id: %w", err)
	}
	routerProgram, err := solana.ParsePubkey(d.VerifierRouterProgramID)
	if err != nil {
		return fmt.Errorf("parse verifier router program id: %w", err)
	}
	verifierProgram, err := solana.ParsePubkey(d.VerifierProgramID)
	if err != nil {
		return fmt.Errorf("parse verifier program id: %w", err)
	}

	chainID, err := junocashChainID(d.JunocashChain)
	if err != nil {
		return err
	}
	genesisHash, err := parseHex32(d.JunocashGenesisHash)
	if err != nil {
		return fmt.Errorf("parse junocash genesis hash: %w", err)
	}

	orpExpectedID, err := parseExpectedImageIDFromRust("solana/operator-registry/src/lib.rs")
	if err != nil {
		return err
	}
	rvExpectedID, err := parseExpectedImageIDFromRust("solana/receipt-verifier/src/lib.rs")
	if err != nil {
		return err
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	rpc := solanarpc.New(d.RPCURL, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := validateOrpExpectedImageID(ctx, rpc, payerPriv, payerPub, orpProgram, routerProgram, verifierProgram, chainID, genesisHash, orpExpectedID); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "orp: ok (program_id=%s)\n", orpProgram.Base58())

	if err := validateReceiptVerifierExpectedImageID(ctx, rpc, payerPriv, payerPub, rvProgram, routerProgram, verifierProgram, rvExpectedID); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "receipt-verifier: ok (program_id=%s)\n", rvProgram.Base58())

	fmt.Println("ok")
	return nil
}

func junocashChainID(chain string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "mainnet":
		return 1, nil
	case "testnet":
		return 2, nil
	case "regtest":
		return 3, nil
	default:
		return 0, fmt.Errorf("unsupported junocash_chain: %s", chain)
	}
}

var (
	expectedImageIDBlockRe = regexp.MustCompile(`const\s+EXPECTED_IMAGE_ID\s*:\s*\[u8;\s*32\]\s*=\s*\[(?s)(.*?)\];`)
	expectedImageIDByteRe  = regexp.MustCompile(`0x([0-9a-fA-F]{2})`)
)

func parseExpectedImageIDFromRust(path string) ([32]byte, error) {
	var out [32]byte
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	m := expectedImageIDBlockRe.FindSubmatch(raw)
	if m == nil {
		return out, fmt.Errorf("EXPECTED_IMAGE_ID not found in %s", path)
	}
	byteMatches := expectedImageIDByteRe.FindAllSubmatch(m[1], -1)
	if len(byteMatches) != 32 {
		return out, fmt.Errorf("EXPECTED_IMAGE_ID parse error in %s: expected 32 bytes, got %d", path, len(byteMatches))
	}
	for i, bm := range byteMatches {
		b, err := hex.DecodeString(string(bm[1]))
		if err != nil || len(b) != 1 {
			return out, fmt.Errorf("EXPECTED_IMAGE_ID parse error in %s", path)
		}
		out[i] = b[0]
	}
	return out, nil
}

func random32() ([32]byte, error) {
	var out [32]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, err
	}
	return out, nil
}

func validateOrpExpectedImageID(
	ctx context.Context,
	rpc *solanarpc.Client,
	payerPriv ed25519.PrivateKey,
	payerPub [32]byte,
	orpProgram solana.Pubkey,
	routerProgram solana.Pubkey,
	verifierProgram solana.Pubkey,
	chainID uint8,
	genesisHash [32]byte,
	expectedImageID [32]byte,
) error {
	deploymentID, err := random32()
	if err != nil {
		return err
	}
	operatorPubkey, err := random32()
	if err != nil {
		return err
	}
	measurement, err := random32()
	if err != nil {
		return err
	}

	cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, orpProgram)
	if err != nil {
		return fmt.Errorf("derive ORP config pda: %w", err)
	}
	opRec, _, err := solana.FindProgramAddress([][]byte{[]byte("operator"), deploymentID[:], operatorPubkey[:]}, orpProgram)
	if err != nil {
		return fmt.Errorf("derive ORP operator pda: %w", err)
	}
	routerPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("router")}, routerProgram)
	if err != nil {
		return fmt.Errorf("derive verifier router pda: %w", err)
	}
	verifierEntry, _, err := solana.FindProgramAddress([][]byte{[]byte("verifier"), []byte("JINT")}, routerProgram)
	if err != nil {
		return fmt.Errorf("derive verifier entry pda: %w", err)
	}

	initIx := solana.Instruction{
		ProgramID: orpProgram,
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfgPDA, IsSigner: false, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
		},
		Data: encodeOrpInitialize(deploymentID, solana.Pubkey(payerPub), chainID, genesisHash, routerProgram, routerPDA, verifierEntry, verifierProgram, [][32]byte{measurement}),
	}

	bundle := buildAttestationBundleV1(expectedImageID, deploymentID, chainID, genesisHash, operatorPubkey, measurement)
	regIx := solana.Instruction{
		ProgramID: orpProgram,
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfgPDA, IsSigner: false, IsWritable: false},
			{Pubkey: opRec, IsSigner: false, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: routerProgram, IsSigner: false, IsWritable: false},
			{Pubkey: routerPDA, IsSigner: false, IsWritable: false},
			{Pubkey: verifierEntry, IsSigner: false, IsWritable: false},
			{Pubkey: verifierProgram, IsSigner: false, IsWritable: false},
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
		[]solana.Instruction{initIx, regIx},
	)
	if err != nil {
		return err
	}

	_, err = rpc.SendTransaction(ctx, tx, false)
	if err == nil {
		return errors.New("orp validation unexpectedly succeeded")
	}

	s := strings.ToLower(err.Error())
	if !strings.Contains(s, "instruction 1") {
		return fmt.Errorf("orp validation failed unexpectedly: %w", err)
	}
	if strings.Contains(s, "custom program error: 0xe") {
		return fmt.Errorf("orp program rejected expected image_id (mismatch): %w", err)
	}
	return nil
}

func validateReceiptVerifierExpectedImageID(
	ctx context.Context,
	rpc *solanarpc.Client,
	payerPriv ed25519.PrivateKey,
	payerPub [32]byte,
	rvProgram solana.Pubkey,
	routerProgram solana.Pubkey,
	verifierProgram solana.Pubkey,
	expectedImageID [32]byte,
) error {
	routerPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("router")}, routerProgram)
	if err != nil {
		return fmt.Errorf("derive verifier router pda: %w", err)
	}
	verifierEntry, _, err := solana.FindProgramAddress([][]byte{[]byte("verifier"), []byte("JINT")}, routerProgram)
	if err != nil {
		return fmt.Errorf("derive verifier entry pda: %w", err)
	}

	bundle := buildReceiptBundleV1(expectedImageID)
	ix := solana.Instruction{
		ProgramID: rvProgram,
		Accounts: []solana.AccountMeta{
			{Pubkey: routerProgram, IsSigner: false, IsWritable: false},
			{Pubkey: routerPDA, IsSigner: false, IsWritable: false},
			{Pubkey: verifierEntry, IsSigner: false, IsWritable: false},
			{Pubkey: verifierProgram, IsSigner: false, IsWritable: false},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
		},
		Data: bundle,
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

	_, err = rpc.SendTransaction(ctx, tx, false)
	if err == nil {
		return errors.New("receipt verifier validation unexpectedly succeeded")
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "invalid instruction data") {
		return fmt.Errorf("receipt verifier rejected expected image_id (mismatch): %w", err)
	}
	if !strings.Contains(s, "instruction 0") {
		return fmt.Errorf("receipt verifier validation failed unexpectedly: %w", err)
	}
	return nil
}

func buildAttestationBundleV1(
	imageID [32]byte,
	deploymentID [32]byte,
	chainID uint8,
	genesisHash [32]byte,
	operatorPubkey [32]byte,
	measurement [32]byte,
) []byte {
	const (
		journalLen = 2 + 32 + 1 + 32 + 32 + 32
		sealLen    = 260
	)

	journal := make([]byte, 0, journalLen)
	var tmp2 [2]byte
	binary.LittleEndian.PutUint16(tmp2[:], 1)
	journal = append(journal, tmp2[:]...)
	journal = append(journal, deploymentID[:]...)
	journal = append(journal, chainID)
	journal = append(journal, genesisHash[:]...)
	journal = append(journal, operatorPubkey[:]...)
	journal = append(journal, measurement[:]...)

	seal := make([]byte, sealLen)

	out := make([]byte, 0, 2+1+32+2+len(journal)+4+len(seal))
	binary.LittleEndian.PutUint16(tmp2[:], 1)
	out = append(out, tmp2[:]...)
	out = append(out, 1) // proof_system = RISC0 Groth16
	out = append(out, imageID[:]...)
	binary.LittleEndian.PutUint16(tmp2[:], uint16(len(journal)))
	out = append(out, tmp2[:]...)
	out = append(out, journal...)

	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], uint32(len(seal)))
	out = append(out, tmp4[:]...)
	out = append(out, seal...)
	return out
}

func buildReceiptBundleV1(imageID [32]byte) []byte {
	const (
		journalLen = 2 + 32 + 32 + 32 + 8 + 32 + 32
		sealLen    = 260
	)
	journal := make([]byte, journalLen)
	seal := make([]byte, sealLen)

	out := make([]byte, 0, 2+1+32+2+journalLen+4+sealLen)
	var tmp2 [2]byte
	binary.LittleEndian.PutUint16(tmp2[:], 1)
	out = append(out, tmp2[:]...)
	out = append(out, 1) // proof_system = RISC0 Groth16
	out = append(out, imageID[:]...)
	binary.LittleEndian.PutUint16(tmp2[:], uint16(journalLen))
	out = append(out, tmp2[:]...)
	out = append(out, journal...)

	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], uint32(sealLen))
	out = append(out, tmp4[:]...)
	out = append(out, seal...)
	return out
}
