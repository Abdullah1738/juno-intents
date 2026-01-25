package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-intents/offchain/deployments"
	"github.com/Abdullah1738/juno-intents/offchain/helius"
	"github.com/Abdullah1738/juno-intents/offchain/solana"
	"github.com/Abdullah1738/juno-intents/offchain/solanarpc"
	"github.com/Abdullah1738/juno-intents/offchain/solvernet"
	"github.com/Abdullah1738/juno-intents/protocol"
	"github.com/Abdullah1738/juno-intents/zk/receipt"
)

var splTokenProgramID = mustParsePubkeyBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

func cmdIepCreateIntent(argv []string) error {
	fs := flag.NewFlagSet("iep-create-intent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentFile string
		deploymentName string

		iepProgramStr string
		deploymentHex string

		intentNonceHex     string
		directionStr       string
		mintStr            string
		solanaRecipientStr string
		netAmountStr       string
		expirySlotStr      string
		solverStr          string
		receiverTagHex     string
		junocashAmountStr  string

		creatorPath               string
		creatorSourceTokenAccount string
		cuLimit                   uint
		priorityLevel             string
		dryRun                    bool
	)

	fs.StringVar(&deploymentName, "deployment", "", "Deployment name from deployments.json (fills --iep-program-id/--deployment-id)")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployments registry file path")

	fs.StringVar(&iepProgramStr, "iep-program-id", "", "IEP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")

	fs.StringVar(&intentNonceHex, "intent-nonce", "", "Intent nonce (32-byte hex; random if omitted)")
	fs.StringVar(&directionStr, "direction", "A", "Direction: A (JunoCash->Solana) or B (Solana->JunoCash)")
	fs.StringVar(&mintStr, "mint", "", "SPL token mint pubkey (base58)")
	fs.StringVar(&solanaRecipientStr, "solana-recipient", "", "Recipient pubkey (base58)")
	fs.StringVar(&netAmountStr, "net-amount", "", "Net amount (u64)")
	fs.StringVar(&expirySlotStr, "expiry-slot", "", "Expiry slot (u64)")
	fs.StringVar(&solverStr, "solver", "", "Committed solver pubkey (base58)")
	fs.StringVar(&receiverTagHex, "receiver-tag", "", "Committed receiver tag (32-byte hex)")
	fs.StringVar(&junocashAmountStr, "junocash-amount", "", "Committed JunoCash amount required (u64, zatoshis)")

	fs.StringVar(&creatorPath, "creator-keypair", solvernet.DefaultSolanaKeypairPath(), "Creator Solana keypair path (Solana CLI JSON format)")
	fs.StringVar(&creatorSourceTokenAccount, "creator-source-token-account", "", "Creator source token account (base58; required for direction B)")
	fs.UintVar(&cuLimit, "cu-limit", 250_000, "Compute unit limit")
	fs.StringVar(&priorityLevel, "priority-level", string(helius.PriorityMedium), "Priority level (Min/Low/Medium/High/VeryHigh/UnsafeMax)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

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
	if strings.TrimSpace(mintStr) == "" || strings.TrimSpace(solanaRecipientStr) == "" || strings.TrimSpace(netAmountStr) == "" || strings.TrimSpace(expirySlotStr) == "" || strings.TrimSpace(solverStr) == "" || strings.TrimSpace(receiverTagHex) == "" || strings.TrimSpace(junocashAmountStr) == "" {
		return errors.New("--mint, --solana-recipient, --net-amount, --expiry-slot, --solver, --receiver-tag, and --junocash-amount are required")
	}

	intentNonce, err := parseOrRandomHex32(intentNonceHex)
	if err != nil {
		return fmt.Errorf("parse --intent-nonce: %w", err)
	}

	direction, err := parseDirection(directionStr)
	if err != nil {
		return err
	}
	if direction == 2 && strings.TrimSpace(creatorSourceTokenAccount) == "" {
		return errors.New("--creator-source-token-account is required for direction B")
	}

	iepProgram, err := solana.ParsePubkey(iepProgramStr)
	if err != nil {
		return fmt.Errorf("parse --iep-program-id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}
	mint, err := solana.ParsePubkey(mintStr)
	if err != nil {
		return fmt.Errorf("parse --mint: %w", err)
	}
	solanaRecipient, err := solana.ParsePubkey(solanaRecipientStr)
	if err != nil {
		return fmt.Errorf("parse --solana-recipient: %w", err)
	}
	solverPK, err := solana.ParsePubkey(solverStr)
	if err != nil {
		return fmt.Errorf("parse --solver: %w", err)
	}
	netAmount, err := strconv.ParseUint(netAmountStr, 10, 64)
	if err != nil {
		return fmt.Errorf("parse --net-amount: %w", err)
	}
	expirySlot, err := strconv.ParseUint(expirySlotStr, 10, 64)
	if err != nil {
		return fmt.Errorf("parse --expiry-slot: %w", err)
	}
	receiverTag, err := parseHex32(receiverTagHex)
	if err != nil {
		return fmt.Errorf("parse --receiver-tag: %w", err)
	}
	junocashAmountRequired, err := strconv.ParseUint(junocashAmountStr, 10, 64)
	if err != nil {
		return fmt.Errorf("parse --junocash-amount: %w", err)
	}

	creatorPriv, creatorPub, err := solvernet.LoadSolanaKeypair(creatorPath)
	if err != nil {
		return fmt.Errorf("load creator keypair: %w", err)
	}

	cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, solana.Pubkey(iepProgram))
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}
	intentPDA, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("intent"), deploymentID[:], intentNonce[:]},
		solana.Pubkey(iepProgram),
	)
	if err != nil {
		return fmt.Errorf("derive intent pda: %w", err)
	}
	intentVaultPDA, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("intent_vault"), intentPDA[:]},
		solana.Pubkey(iepProgram),
	)
	if err != nil {
		return fmt.Errorf("derive intent_vault pda: %w", err)
	}

	var creatorSourceTA solana.Pubkey
	if strings.TrimSpace(creatorSourceTokenAccount) != "" {
		pk, err := solana.ParsePubkey(creatorSourceTokenAccount)
		if err != nil {
			return fmt.Errorf("parse --creator-source-token-account: %w", err)
		}
		creatorSourceTA = pk
	} else {
		// Direction A doesn't use this account; pass creator pubkey as a placeholder.
		creatorSourceTA = solana.Pubkey(creatorPub)
	}

	ix := solana.Instruction{
		ProgramID: solana.Pubkey(iepProgram),
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(creatorPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfgPDA, IsSigner: false, IsWritable: false},
			{Pubkey: intentPDA, IsSigner: false, IsWritable: true},
			{Pubkey: intentVaultPDA, IsSigner: false, IsWritable: true},
			{Pubkey: creatorSourceTA, IsSigner: false, IsWritable: true},
			{Pubkey: solana.Pubkey(mint), IsSigner: false, IsWritable: false},
			{Pubkey: splTokenProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
		},
		Data: encodeIepCreateIntentV3(intentNonce, direction, mint, solanaRecipient, netAmount, expirySlot, solverPK, receiverTag, junocashAmountRequired),
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

	var ixs []solana.Instruction
	if cuLimit != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitLimit(uint32(cuLimit)))
	}
	if microLamports := heliusEstimateMicroLamports(ctx, []string{
		solana.Pubkey(creatorPub).Base58(),
		cfgPDA.Base58(),
		intentPDA.Base58(),
		intentVaultPDA.Base58(),
		creatorSourceTA.Base58(),
		solana.Pubkey(mint).Base58(),
		splTokenProgramID.Base58(),
		solana.SystemProgramID.Base58(),
		solana.Pubkey(iepProgram).Base58(),
	}, priorityLevel); microLamports != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitPrice(microLamports))
	}
	ixs = append(ixs, ix)

	tx, err := solana.BuildAndSignLegacyTransaction(
		bh,
		solana.Pubkey(creatorPub),
		map[solana.Pubkey]ed25519.PrivateKey{solana.Pubkey(creatorPub): creatorPriv},
		ixs,
	)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "intent=%s\n", intentPDA.Base58())
	if direction == 2 {
		fmt.Fprintf(os.Stderr, "intent_vault=%s\n", intentVaultPDA.Base58())
	}
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

func cmdIepFill(argv []string) error {
	fs := flag.NewFlagSet("iep-fill", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentFile string
		deploymentName string

		iepProgramStr string
		deploymentHex string

		intentStr         string
		receiverTagHex    string
		junocashAmountStr string
		mintStr           string

		solverPath               string
		solverSourceTokenAccount string
		solverDestTokenAccount   string
		cuLimit                  uint
		priorityLevel            string
		dryRun                   bool
	)

	fs.StringVar(&deploymentName, "deployment", "", "Deployment name from deployments.json (fills --iep-program-id/--deployment-id)")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployments registry file path")

	fs.StringVar(&iepProgramStr, "iep-program-id", "", "IEP program id (base58)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&intentStr, "intent", "", "Intent PDA pubkey (base58)")
	fs.StringVar(&receiverTagHex, "receiver-tag", "", "Receiver tag (32-byte hex; required for v2 intents)")
	fs.StringVar(&junocashAmountStr, "junocash-amount", "", "Required JunoCash amount (u64; required for v2 intents)")
	fs.StringVar(&mintStr, "mint", "", "SPL token mint pubkey (base58)")

	fs.StringVar(&solverPath, "solver-keypair", solvernet.DefaultSolanaKeypairPath(), "Solver Solana keypair path (Solana CLI JSON format)")
	fs.StringVar(&solverSourceTokenAccount, "solver-source-token-account", "", "Solver source token account (base58; required for direction A)")
	fs.StringVar(&solverDestTokenAccount, "solver-destination-token-account", "", "Solver destination token account (base58; required for direction B)")
	fs.UintVar(&cuLimit, "cu-limit", 300_000, "Compute unit limit")
	fs.StringVar(&priorityLevel, "priority-level", string(helius.PriorityMedium), "Priority level (Min/Low/Medium/High/VeryHigh/UnsafeMax)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

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
	if strings.TrimSpace(intentStr) == "" || strings.TrimSpace(mintStr) == "" {
		return errors.New("--intent and --mint are required")
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
	mint, err := solana.ParsePubkey(mintStr)
	if err != nil {
		return fmt.Errorf("parse --mint: %w", err)
	}

	var receiverTag [32]byte
	if strings.TrimSpace(receiverTagHex) != "" {
		tag, err := parseHex32(receiverTagHex)
		if err != nil {
			return fmt.Errorf("parse --receiver-tag: %w", err)
		}
		receiverTag = tag
	}
	var junocashAmount uint64
	if strings.TrimSpace(junocashAmountStr) != "" {
		amt, err := strconv.ParseUint(junocashAmountStr, 10, 64)
		if err != nil {
			return fmt.Errorf("parse --junocash-amount: %w", err)
		}
		junocashAmount = amt
	}

	cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, solana.Pubkey(iepProgram))
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}
	fillPDA, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("fill"), intent[:]},
		solana.Pubkey(iepProgram),
	)
	if err != nil {
		return fmt.Errorf("derive fill pda: %w", err)
	}
	vaultPDA, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("vault"), fillPDA[:]},
		solana.Pubkey(iepProgram),
	)
	if err != nil {
		return fmt.Errorf("derive vault pda: %w", err)
	}
	intentVaultPDA, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("intent_vault"), intent[:]},
		solana.Pubkey(iepProgram),
	)
	if err != nil {
		return fmt.Errorf("derive intent_vault pda: %w", err)
	}

	solverPriv, solverPub, err := solvernet.LoadSolanaKeypair(solverPath)
	if err != nil {
		return fmt.Errorf("load solver keypair: %w", err)
	}

	// Determine direction by reading the on-chain intent, so we pass the correct vault PDA.
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	rpc, err := solanarpc.ClientFromEnv()
	if err != nil {
		return err
	}
	intentData, err := rpc.AccountDataBase64(ctx, solana.Pubkey(intent).Base58())
	if err != nil {
		return fmt.Errorf("fetch intent account: %w", err)
	}
	intentState, err := parseIepIntentHeader(intentData)
	if err != nil {
		return fmt.Errorf("parse intent account: %w", err)
	}
	if intentState.Version == 2 {
		if receiverTag == ([32]byte{}) || junocashAmount == 0 {
			return errors.New("--receiver-tag and --junocash-amount are required for v2 intents")
		}
	}

	if intentState.Direction == 1 && strings.TrimSpace(solverSourceTokenAccount) == "" {
		return errors.New("--solver-source-token-account is required for direction A")
	}
	if intentState.Direction == 2 && strings.TrimSpace(solverDestTokenAccount) == "" {
		return errors.New("--solver-destination-token-account is required for direction B")
	}

	solverSource := solana.Pubkey(solverPub)
	if strings.TrimSpace(solverSourceTokenAccount) != "" {
		pk, err := solana.ParsePubkey(solverSourceTokenAccount)
		if err != nil {
			return fmt.Errorf("parse --solver-source-token-account: %w", err)
		}
		solverSource = pk
	}
	solverDest := solana.Pubkey(solverPub)
	if strings.TrimSpace(solverDestTokenAccount) != "" {
		pk, err := solana.ParsePubkey(solverDestTokenAccount)
		if err != nil {
			return fmt.Errorf("parse --solver-destination-token-account: %w", err)
		}
		solverDest = pk
	}
	vault := vaultPDA
	if intentState.Direction == 2 {
		vault = intentVaultPDA
	}

	ix := solana.Instruction{
		ProgramID: solana.Pubkey(iepProgram),
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(solverPub), IsSigner: true, IsWritable: true},
			{Pubkey: cfgPDA, IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(intent), IsSigner: false, IsWritable: true},
			{Pubkey: fillPDA, IsSigner: false, IsWritable: true},
			{Pubkey: vault, IsSigner: false, IsWritable: true},
			{Pubkey: solverSource, IsSigner: false, IsWritable: true},
			{Pubkey: solverDest, IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(mint), IsSigner: false, IsWritable: false},
			{Pubkey: splTokenProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
		},
		Data: encodeIepFillIntent(receiverTag, junocashAmount),
	}

	bh, err := rpc.LatestBlockhash(ctx)
	if err != nil {
		return err
	}

	var ixs []solana.Instruction
	if cuLimit != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitLimit(uint32(cuLimit)))
	}
	if microLamports := heliusEstimateMicroLamports(ctx, []string{
		solana.Pubkey(solverPub).Base58(),
		cfgPDA.Base58(),
		solana.Pubkey(intent).Base58(),
		fillPDA.Base58(),
		vault.Base58(),
		solverSource.Base58(),
		solverDest.Base58(),
		solana.Pubkey(mint).Base58(),
		splTokenProgramID.Base58(),
		solana.SystemProgramID.Base58(),
		solana.Pubkey(iepProgram).Base58(),
	}, priorityLevel); microLamports != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitPrice(microLamports))
	}
	ixs = append(ixs, ix)

	tx, err := solana.BuildAndSignLegacyTransaction(
		bh,
		solana.Pubkey(solverPub),
		map[solana.Pubkey]ed25519.PrivateKey{solana.Pubkey(solverPub): solverPriv},
		ixs,
	)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "fill=%s\n", fillPDA.Base58())
	fmt.Fprintf(os.Stderr, "vault=%s\n", vault.Base58())
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

func cmdIepSettle(argv []string) error {
	fs := flag.NewFlagSet("iep-settle", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentFile string
		deploymentName string

		deploymentHex string
		iepProgramStr string
		crpProgramStr string

		intentStr string
		mintStr   string

		recipientTokenAccountStr string
		feeTokenAccountStr       string

		bundleHex      string
		lookupTableStr string
		payerPath      string
		cuLimit        uint
		priorityLevel  string
		dryRun         bool
	)

	fs.StringVar(&deploymentName, "deployment", "", "Deployment name from deployments.json (fills program ids, configs, and verifier accounts)")
	fs.StringVar(&deploymentFile, "deployment-file", "deployments.json", "Deployments registry file path")

	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex; overrides deployments.json)")
	fs.StringVar(&iepProgramStr, "iep-program-id", "", "IEP program id (base58; overrides deployments.json)")
	fs.StringVar(&crpProgramStr, "crp-program-id", "", "CRP program id (base58; overrides deployments.json)")

	fs.StringVar(&intentStr, "intent", "", "Intent PDA pubkey (base58)")
	fs.StringVar(&mintStr, "mint", "", "SPL token mint pubkey (base58)")
	fs.StringVar(&recipientTokenAccountStr, "recipient-token-account", "", "Recipient token account (base58)")
	fs.StringVar(&feeTokenAccountStr, "fee-token-account", "", "Fee collector token account (base58)")
	fs.StringVar(&bundleHex, "bundle-hex", "", "ReceiptZKVMProofBundleV1 hex (defaults to JUNO_RECEIPT_ZKVM_BUNDLE_HEX env)")
	fs.StringVar(&lookupTableStr, "address-lookup-table", "", "Address lookup table account (base58; overrides deployments.json:address_lookup_table)")
	fs.StringVar(&payerPath, "payer-keypair", solvernet.DefaultSolanaKeypairPath(), "Payer Solana keypair path (Solana CLI JSON format)")
	fs.UintVar(&cuLimit, "cu-limit", 500_000, "Compute unit limit")
	fs.StringVar(&priorityLevel, "priority-level", string(helius.PriorityMedium), "Priority level (Min/Low/Medium/High/VeryHigh/UnsafeMax)")
	fs.BoolVar(&dryRun, "dry-run", false, "If set, prints the base64 tx instead of sending it")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}
	if strings.TrimSpace(deploymentName) == "" {
		return errors.New("--deployment is required (to source verifier program/accounts)")
	}

	var dep deployments.Deployment
	if strings.TrimSpace(deploymentName) != "" {
		reg, err := deployments.Load(deploymentFile)
		if err != nil {
			return fmt.Errorf("load deployments registry %q: %w", deploymentFile, err)
		}
		d, err := reg.FindByName(deploymentName)
		if err != nil {
			return fmt.Errorf("find deployment %q in %q: %w", deploymentName, deploymentFile, err)
		}
		dep = d
		if os.Getenv("SOLANA_RPC_URL") == "" && strings.TrimSpace(dep.RPCURL) != "" {
			_ = os.Setenv("SOLANA_RPC_URL", dep.RPCURL)
		}
	}

	if strings.TrimSpace(deploymentHex) == "" {
		deploymentHex = dep.DeploymentID
	}
	if strings.TrimSpace(iepProgramStr) == "" {
		iepProgramStr = dep.IntentEscrowProgramID
	}
	if strings.TrimSpace(crpProgramStr) == "" {
		crpProgramStr = dep.CheckpointRegistryProgramID
	}

	if strings.TrimSpace(deploymentHex) == "" || strings.TrimSpace(iepProgramStr) == "" || strings.TrimSpace(crpProgramStr) == "" {
		return errors.New("missing required deployment fields (need deployment_id, intent_escrow_program_id, checkpoint_registry_program_id)")
	}
	if strings.TrimSpace(intentStr) == "" || strings.TrimSpace(mintStr) == "" || strings.TrimSpace(recipientTokenAccountStr) == "" || strings.TrimSpace(feeTokenAccountStr) == "" {
		return errors.New("--intent, --mint, --recipient-token-account, and --fee-token-account are required")
	}
	if strings.TrimSpace(bundleHex) == "" {
		bundleHex = os.Getenv("JUNO_RECEIPT_ZKVM_BUNDLE_HEX")
	}
	if strings.TrimSpace(bundleHex) == "" {
		return errors.New("--bundle-hex or JUNO_RECEIPT_ZKVM_BUNDLE_HEX is required")
	}
	if strings.TrimSpace(lookupTableStr) == "" {
		lookupTableStr = dep.AddressLookupTable
	}

	iepProgram, err := solana.ParsePubkey(iepProgramStr)
	if err != nil {
		return fmt.Errorf("parse iep program id: %w", err)
	}
	crpProgram, err := solana.ParsePubkey(crpProgramStr)
	if err != nil {
		return fmt.Errorf("parse crp program id: %w", err)
	}
	deploymentID, err := protocol.ParseDeploymentIDHex(strings.TrimPrefix(strings.TrimSpace(deploymentHex), "0x"))
	if err != nil {
		return fmt.Errorf("parse deployment id: %w", err)
	}
	intent, err := solana.ParsePubkey(intentStr)
	if err != nil {
		return fmt.Errorf("parse intent: %w", err)
	}
	mint, err := solana.ParsePubkey(mintStr)
	if err != nil {
		return fmt.Errorf("parse mint: %w", err)
	}
	recipientTA, err := solana.ParsePubkey(recipientTokenAccountStr)
	if err != nil {
		return fmt.Errorf("parse recipient token account: %w", err)
	}
	feeTA, err := solana.ParsePubkey(feeTokenAccountStr)
	if err != nil {
		return fmt.Errorf("parse fee token account: %w", err)
	}

	iepConfig, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, solana.Pubkey(iepProgram))
	if err != nil {
		return fmt.Errorf("derive iep config pda: %w", err)
	}
	crpConfig, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, solana.Pubkey(crpProgram))
	if err != nil {
		return fmt.Errorf("derive crp config pda: %w", err)
	}

	rawBundle, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(bundleHex), "0x"))
	if err != nil {
		return fmt.Errorf("decode bundle hex: %w", err)
	}
	var bundle receipt.ReceiptZKVMProofBundleV1
	if err := bundle.UnmarshalBinary(rawBundle); err != nil {
		return fmt.Errorf("decode bundle: %w", err)
	}
	journal, err := protocol.ParseReceiptJournalV1(bundle.Journal[:])
	if err != nil {
		return fmt.Errorf("parse journal: %w", err)
	}
	if journal.DeploymentID != deploymentID {
		return errors.New("journal deployment_id does not match deployment")
	}

	// Derive fill/vault PDAs and decide which vault account to pass by reading the on-chain intent.
	fillPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("fill"), intent[:]}, solana.Pubkey(iepProgram))
	if err != nil {
		return fmt.Errorf("derive fill pda: %w", err)
	}
	if journal.FillID != protocol.FillID(fillPDA) {
		return errors.New("journal fill_id does not match derived fill PDA")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rpc, err := solanarpc.ClientFromEnv()
	if err != nil {
		return err
	}
	intentData, err := rpc.AccountDataBase64(ctx, solana.Pubkey(intent).Base58())
	if err != nil {
		return fmt.Errorf("fetch intent account: %w", err)
	}
	intentState, err := parseIepIntentHeader(intentData)
	if err != nil {
		return fmt.Errorf("parse intent account: %w", err)
	}

	vaultPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("vault"), fillPDA[:]}, solana.Pubkey(iepProgram))
	if err != nil {
		return fmt.Errorf("derive vault pda: %w", err)
	}
	vault := vaultPDA
	if intentState.Direction == 2 {
		if intentState.Vault == (solana.Pubkey{}) {
			return errors.New("intent vault is empty for direction B")
		}
		vault = intentState.Vault
	}

	// Checkpoint PDA is keyed by orchard_root.
	checkpointPDA, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("checkpoint"), crpConfig[:], journal.OrchardRoot[:]},
		solana.Pubkey(crpProgram),
	)
	if err != nil {
		return fmt.Errorf("derive checkpoint pda: %w", err)
	}

	// Spent receipt PDA is keyed by spent_receipt_id(deployment_id, cmx).
	spentID := protocol.SpentReceiptIDForCmx(journal.DeploymentID, journal.Cmx)
	spentPDA, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("spent"), spentID[:]},
		solana.Pubkey(iepProgram),
	)
	if err != nil {
		return fmt.Errorf("derive spent_receipt pda: %w", err)
	}

	// Verifier accounts come from the deployment record.
	if strings.TrimSpace(dep.ReceiptVerifierProgramID) == "" {
		return errors.New("deployment record missing receipt_verifier_program_id")
	}
	if strings.TrimSpace(dep.VerifierRouterProgramID) == "" {
		return errors.New("deployment record missing verifier_router_program_id")
	}
	if strings.TrimSpace(dep.VerifierRouter) == "" {
		return errors.New("deployment record missing verifier_router")
	}
	if strings.TrimSpace(dep.VerifierEntry) == "" {
		return errors.New("deployment record missing verifier_entry")
	}
	if strings.TrimSpace(dep.VerifierProgramID) == "" {
		return errors.New("deployment record missing verifier_program_id")
	}
	rvProgram, err := solana.ParsePubkey(dep.ReceiptVerifierProgramID)
	if err != nil {
		return fmt.Errorf("parse receipt_verifier_program_id: %w", err)
	}
	vrProgram, err := solana.ParsePubkey(dep.VerifierRouterProgramID)
	if err != nil {
		return fmt.Errorf("parse verifier_router_program_id: %w", err)
	}
	vrRouter, err := solana.ParsePubkey(dep.VerifierRouter)
	if err != nil {
		return fmt.Errorf("parse verifier_router: %w", err)
	}
	vrEntry, err := solana.ParsePubkey(dep.VerifierEntry)
	if err != nil {
		return fmt.Errorf("parse verifier_entry: %w", err)
	}
	vrVerifier, err := solana.ParsePubkey(dep.VerifierProgramID)
	if err != nil {
		return fmt.Errorf("parse verifier_program_id: %w", err)
	}

	payerPriv, payerPub, err := solvernet.LoadSolanaKeypair(payerPath)
	if err != nil {
		return fmt.Errorf("load payer keypair: %w", err)
	}

	ix := solana.Instruction{
		ProgramID: solana.Pubkey(iepProgram),
		Accounts: []solana.AccountMeta{
			{Pubkey: solana.Pubkey(payerPub), IsSigner: true, IsWritable: true},    // payer
			{Pubkey: solana.Pubkey(iepConfig), IsSigner: false, IsWritable: false}, // config
			{Pubkey: solana.Pubkey(intent), IsSigner: false, IsWritable: true},     // intent
			{Pubkey: fillPDA, IsSigner: false, IsWritable: true},                   // fill
			{Pubkey: vault, IsSigner: false, IsWritable: true},                     // vault
			{Pubkey: solana.Pubkey(recipientTA), IsSigner: false, IsWritable: true},
			{Pubkey: solana.Pubkey(feeTA), IsSigner: false, IsWritable: true},
			{Pubkey: solana.Pubkey(mint), IsSigner: false, IsWritable: false},
			{Pubkey: splTokenProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: spentPDA, IsSigner: false, IsWritable: true},
			{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(crpProgram), IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(crpConfig), IsSigner: false, IsWritable: false},
			{Pubkey: checkpointPDA, IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(rvProgram), IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(vrProgram), IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(vrRouter), IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(vrEntry), IsSigner: false, IsWritable: false},
			{Pubkey: solana.Pubkey(vrVerifier), IsSigner: false, IsWritable: false},
		},
		Data: encodeIepSettle(rawBundle),
	}

	bh, err := rpc.LatestBlockhash(ctx)
	if err != nil {
		return err
	}

	var ixs []solana.Instruction
	if cuLimit != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitLimit(uint32(cuLimit)))
	}
	if microLamports := heliusEstimateMicroLamports(ctx, []string{
		solana.Pubkey(payerPub).Base58(),
		solana.Pubkey(iepConfig).Base58(),
		solana.Pubkey(intent).Base58(),
		fillPDA.Base58(),
		vault.Base58(),
		solana.Pubkey(recipientTA).Base58(),
		solana.Pubkey(feeTA).Base58(),
		solana.Pubkey(mint).Base58(),
		splTokenProgramID.Base58(),
		spentPDA.Base58(),
		solana.SystemProgramID.Base58(),
		solana.Pubkey(crpProgram).Base58(),
		solana.Pubkey(crpConfig).Base58(),
		checkpointPDA.Base58(),
		solana.Pubkey(rvProgram).Base58(),
		solana.Pubkey(vrProgram).Base58(),
		solana.Pubkey(vrRouter).Base58(),
		solana.Pubkey(vrEntry).Base58(),
		solana.Pubkey(vrVerifier).Base58(),
		solana.Pubkey(iepProgram).Base58(),
	}, priorityLevel); microLamports != 0 {
		ixs = append(ixs, solana.ComputeBudgetSetComputeUnitPrice(microLamports))
	}
	ixs = append(ixs, ix)

	signers := map[solana.Pubkey]ed25519.PrivateKey{solana.Pubkey(payerPub): payerPriv}

	var tx []byte
	if strings.TrimSpace(lookupTableStr) != "" {
		lookupKey, err := solana.ParsePubkey(lookupTableStr)
		if err != nil {
			return fmt.Errorf("parse address lookup table: %w", err)
		}
		addrs, err := rpc.AddressLookupTableAddresses(ctx, lookupKey)
		if err != nil {
			return fmt.Errorf("fetch address lookup table %s: %w", lookupKey.Base58(), err)
		}
		tx, err = solana.BuildAndSignV0Transaction(
			bh,
			solana.Pubkey(payerPub),
			signers,
			ixs,
			[]solana.LookupTable{{AccountKey: lookupKey, Addresses: addrs}},
		)
		if err != nil {
			return err
		}
	} else {
		tx, err = solana.BuildAndSignLegacyTransaction(
			bh,
			solana.Pubkey(payerPub),
			signers,
			ixs,
		)
		if err != nil {
			return err
		}
	}

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

func applyIepDeploymentDefaults(deploymentFile, deploymentName string, iepProgramStr, deploymentHex *string) error {
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

	if iepProgramStr != nil && strings.TrimSpace(*iepProgramStr) == "" {
		*iepProgramStr = d.IntentEscrowProgramID
	}
	if deploymentHex != nil && strings.TrimSpace(*deploymentHex) == "" {
		*deploymentHex = d.DeploymentID
	}

	if iepProgramStr != nil && strings.TrimSpace(*iepProgramStr) == "" {
		return errors.New("deployment record is missing intent_escrow_program_id")
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

func parseOrRandomHex32(hex32 string) ([32]byte, error) {
	if strings.TrimSpace(hex32) == "" {
		var out [32]byte
		if _, err := rand.Read(out[:]); err != nil {
			return [32]byte{}, err
		}
		return out, nil
	}
	return parseHex32(hex32)
}

func parseDirection(s string) (uint8, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	switch s {
	case "A", "1":
		return 1, nil
	case "B", "2":
		return 2, nil
	default:
		return 0, fmt.Errorf("invalid --direction: %q (want A|B)", s)
	}
}

func heliusEstimateMicroLamports(ctx context.Context, accountKeys []string, priorityLevel string) uint64 {
	hc, err := helius.ClientFromEnv()
	if err != nil {
		return 0
	}
	est, err := hc.GetPriorityFeeEstimateByAccountKeys(ctx, helius.PriorityFeeEstimateByAccountKeysRequest{
		AccountKeys: accountKeys,
		Options: &helius.PriorityFeeOptions{
			PriorityLevel: helius.PriorityLevel(priorityLevel),
			Recommended:   true,
		},
	})
	if err != nil {
		return 0
	}
	return est.MicroLamports
}

func encodeIepCreateIntent(
	intentNonce [32]byte,
	direction uint8,
	mint solana.Pubkey,
	solanaRecipient solana.Pubkey,
	netAmount uint64,
	expirySlot uint64,
) []byte {
	// Borsh enum variant index (u8) for CreateIntent is 1.
	out := make([]byte, 0, 1+32+1+32+32+8+8)
	out = append(out, 1)
	out = append(out, intentNonce[:]...)
	out = append(out, direction)
	out = append(out, mint[:]...)
	out = append(out, solanaRecipient[:]...)

	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], netAmount)
	out = append(out, tmp8[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], expirySlot)
	out = append(out, tmp8[:]...)
	return out
}

func encodeIepCreateIntentV3(
	intentNonce [32]byte,
	direction uint8,
	mint solana.Pubkey,
	solanaRecipient solana.Pubkey,
	netAmount uint64,
	expirySlot uint64,
	solver solana.Pubkey,
	receiverTag [32]byte,
	junocashAmountRequired uint64,
) []byte {
	// Borsh enum variant index (u8) for CreateIntentV3 is 2.
	out := make([]byte, 0, 1+32+1+32+32+8+8+32+32+8)
	out = append(out, 2)
	out = append(out, intentNonce[:]...)
	out = append(out, direction)
	out = append(out, mint[:]...)
	out = append(out, solanaRecipient[:]...)

	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], netAmount)
	out = append(out, tmp8[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], expirySlot)
	out = append(out, tmp8[:]...)

	out = append(out, solver[:]...)
	out = append(out, receiverTag[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], junocashAmountRequired)
	out = append(out, tmp8[:]...)
	return out
}

func encodeIepFillIntent(receiverTag [32]byte, junocashAmountRequired uint64) []byte {
	// Borsh enum variant index (u8) for FillIntent is 4.
	out := make([]byte, 0, 1+32+8)
	out = append(out, 4)
	out = append(out, receiverTag[:]...)
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], junocashAmountRequired)
	out = append(out, tmp8[:]...)
	return out
}

func encodeIepSettle(bundle []byte) []byte {
	// Borsh enum variant index (u8) for Settle is 5.
	out := make([]byte, 0, 1+4+len(bundle))
	out = append(out, 5)
	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], uint32(len(bundle)))
	out = append(out, tmp4[:]...)
	out = append(out, bundle...)
	return out
}

type iepIntentHeader struct {
	Version   uint8
	Direction uint8
	Vault     solana.Pubkey
}

func parseIepIntentHeader(data []byte) (iepIntentHeader, error) {
	// Layout must match solana/intent-escrow IepIntentV2:
	//   version u8
	//   status u8
	//   direction u8
	//   deployment_id [32]
	//   creator Pubkey
	//   mint Pubkey
	//   solana_recipient Pubkey
	//   net_amount u64
	//   fee_bps u16
	//   protocol_fee u64
	//   expiry_slot u64
	//   intent_nonce [32]
	//   vault Pubkey
	const minLen = 1 + 1 + 1 + 32 + 32 + 32 + 32 + 8 + 2 + 8 + 8 + 32 + 32
	if len(data) < minLen {
		return iepIntentHeader{}, errors.New("intent account too short")
	}
	version := data[0]
	// direction at offset 2
	dir := data[2]
	// vault is last 32 bytes
	var vault solana.Pubkey
	copy(vault[:], data[minLen-32:minLen])
	return iepIntentHeader{Version: version, Direction: dir, Vault: vault}, nil
}
