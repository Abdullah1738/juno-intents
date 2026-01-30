package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-intents/offchain/helius"
	"github.com/Abdullah1738/juno-intents/offchain/iep"
	"github.com/Abdullah1738/juno-intents/offchain/solana"
	"github.com/Abdullah1738/juno-intents/offchain/solvernet"
	"github.com/Abdullah1738/juno-intents/offchain/solanarpc"
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
	case "announce":
		return cmdAnnounce(argv[1:])
	case "serve":
		return cmdServe(argv[1:])
	case "run":
		return cmdRun(argv[1:])
	case "rfq":
		return cmdRFQ(argv[1:])
	default:
		return fmt.Errorf("unknown command: %s", argv[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "solvernet: Juno Intents solver network tooling")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  solvernet announce --deployment-id <hex32> --quote-url <url> [--keypair <path>]")
	fmt.Fprintln(w, "  solvernet serve --listen :8080 --deployment-id <hex32> --quote-url <url> --mint <base58> --price-zat-per-token-unit <u64> --orchard-receiver-bytes-hex <hex43> [--spread-bps <u16>] [--keypair <path>]")
	fmt.Fprintln(w, "  solvernet run --listen :8080 --deployment-id <hex32> --quote-url <url> --iep-program-id <base58> --solver-token-account <base58> --mint <base58> --price-zat-per-token-unit <u64> --orchard-receiver-bytes-hex <hex43> [--spread-bps <u16>] [--poll-interval 2s] [--airdrop-sol <n>] [--keypair <path>]")
	fmt.Fprintln(w, "  solvernet rfq --deployment-id <hex32> --fill-id <hex32> --direction A|B --mint <base58> --net-amount <u64> --solana-recipient <base58> --intent-expiry-slot <u64> [--receiver-tag <hex32>] --announcement-url <url> [--announcement-url <url>...]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Environment:")
	fmt.Fprintln(w, "  HELIUS_API_KEY / HELIUS_CLUSTER or HELIUS_RPC_URL (optional; enables fee hints)")
}

func cmdAnnounce(argv []string) error {
	fs := flag.NewFlagSet("announce", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentHex string
		quoteURL      string
		keypairPath   string
	)
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&quoteURL, "quote-url", "", "Quote endpoint URL (HTTPS/WSS recommended)")
	fs.StringVar(&keypairPath, "keypair", solvernet.DefaultSolanaKeypairPath(), "Solana keypair path (Solana CLI JSON format)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if deploymentHex == "" || quoteURL == "" {
		return errors.New("--deployment-id and --quote-url are required")
	}

	deploymentID, err := protocol.ParseDeploymentIDHex(deploymentHex)
	if err != nil {
		return fmt.Errorf("parse deployment id: %w", err)
	}

	priv, pub, err := solvernet.LoadSolanaKeypair(keypairPath)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}
	ann := protocol.SolverAnnouncement{
		DeploymentID: deploymentID,
		SolverPubkey: protocol.SolanaPubkey(pub),
		QuoteURL:     quoteURL,
	}

	signed, err := solvernet.NewSignedSolverAnnouncement(ann, priv)
	if err != nil {
		return err
	}
	return printJSON(os.Stdout, signed)
}

func cmdServe(argv []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		listenAddr      string
		deploymentHex   string
		quoteURL        string
		mintStr         string
		keypairPath     string
		priceZatPerUnit uint64
		spreadBps       uint
		orchardReceiverHex string

		fillAccountKeysCSV   string
		settleAccountKeysCSV string
		fillCULimit          uint
		settleCULimit        uint
		fillSigs             uint
		settleSigs           uint
		priorityLevel        string
	)

	fs.StringVar(&listenAddr, "listen", ":8080", "Listen address")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&quoteURL, "quote-url", "", "Public quote URL (must match the server externally reachable URL)")
	fs.StringVar(&mintStr, "mint", "", "SPL token mint pubkey (base58)")
	fs.StringVar(&keypairPath, "keypair", solvernet.DefaultSolanaKeypairPath(), "Solana keypair path (Solana CLI JSON format)")
	fs.Uint64Var(&priceZatPerUnit, "price-zat-per-token-unit", 0, "Fixed price: zatoshis per Solana token base unit")
	fs.UintVar(&spreadBps, "spread-bps", 0, "Spread in bps applied to the required JunoCash amount")
	fs.StringVar(&orchardReceiverHex, "orchard-receiver-bytes-hex", "", "Orchard receiver bytes for DirectionA settlement (43-byte hex)")

	fs.StringVar(&fillAccountKeysCSV, "fill-account-keys", "", "CSV of account keys for Fill tx priority fee estimation (base58 pubkeys)")
	fs.StringVar(&settleAccountKeysCSV, "settle-account-keys", "", "CSV of account keys for Settle tx priority fee estimation (base58 pubkeys)")
	fs.UintVar(&fillCULimit, "fill-cu-limit", 200_000, "Compute unit limit assumed for Fill tx")
	fs.UintVar(&settleCULimit, "settle-cu-limit", 450_000, "Compute unit limit assumed for Settle tx")
	fs.UintVar(&fillSigs, "fill-sigs", 1, "Signature count assumed for Fill tx")
	fs.UintVar(&settleSigs, "settle-sigs", 1, "Signature count assumed for Settle tx")
	fs.StringVar(&priorityLevel, "priority-level", string(helius.PriorityMedium), "Priority level (Min/Low/Medium/High/VeryHigh/UnsafeMax)")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if deploymentHex == "" || quoteURL == "" || mintStr == "" || priceZatPerUnit == 0 || orchardReceiverHex == "" {
		return errors.New("--deployment-id, --quote-url, --mint, --price-zat-per-token-unit, and --orchard-receiver-bytes-hex are required")
	}
	if spreadBps > 10_000 {
		return errors.New("--spread-bps must be <= 10000")
	}

	deploymentID, err := protocol.ParseDeploymentIDHex(deploymentHex)
	if err != nil {
		return fmt.Errorf("parse deployment id: %w", err)
	}

	mint, err := solana.ParsePubkey(mintStr)
	if err != nil {
		return fmt.Errorf("parse --mint: %w", err)
	}

	priv, pub, err := solvernet.LoadSolanaKeypair(keypairPath)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}

	solverPub := protocol.SolanaPubkey(pub)

	orchardReceiverBytes, err := hexBytes(orchardReceiverHex, protocol.OrchardReceiverBytesLen)
	if err != nil {
		return fmt.Errorf("parse --orchard-receiver-bytes-hex: %w", err)
	}

	hc, err := helius.ClientFromEnv()
	if err != nil && !errors.Is(err, helius.ErrMissingAPIKey) {
		return fmt.Errorf("helius: %w", err)
	}
	if errors.Is(err, helius.ErrMissingAPIKey) {
		hc = nil
	}

	fillKeys := splitCSV(fillAccountKeysCSV)
	settleKeys := splitCSV(settleAccountKeysCSV)

	opts := &helius.PriorityFeeOptions{
		PriorityLevel: helius.PriorityLevel(priorityLevel),
		Recommended:   true,
	}

	solver := &solvernet.Solver{
		DeploymentID: deploymentID,
		SolverPubkey: solverPub,
		QuoteURL:     quoteURL,
		PrivKey:      priv,
		Mint:         protocol.SolanaPubkey(mint),
		OrchardReceiverBytes: orchardReceiverBytes,
		Strategy: solvernet.FixedPriceStrategy{
			ZatoshiPerTokenUnit: priceZatPerUnit,
			SpreadBps:           uint16(spreadBps),
		},
		Helius: hc,
		FillFeeProfile: solvernet.FeeProfile{
			AccountKeys:      fillKeys,
			ComputeUnitLimit: uint32(fillCULimit),
			Signatures:       uint64(fillSigs),
		},
		SettleFeeProfile: solvernet.FeeProfile{
			AccountKeys:      settleKeys,
			ComputeUnitLimit: uint32(settleCULimit),
			Signatures:       uint64(settleSigs),
		},
		PriorityOptions: *opts,
	}

	handler, err := solver.Handler()
	if err != nil {
		return err
	}

	s := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "listening on %s\n", listenAddr)
	return s.ListenAndServe()
}

func cmdRun(argv []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		listenAddr         string
		deploymentHex      string
		quoteURL           string
		mintStr            string
		iepProgramStr      string
		solverTokenAccountStr string
		keypairPath        string
		priceZatPerUnit    uint64
		spreadBps          uint
		orchardReceiverHex string
		pollInterval       time.Duration
		airdropSol         uint
	)

	fs.StringVar(&listenAddr, "listen", ":8080", "Listen address")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&quoteURL, "quote-url", "", "Public quote URL (must match the server externally reachable URL)")
	fs.StringVar(&iepProgramStr, "iep-program-id", "", "IEP program id (base58)")
	fs.StringVar(&solverTokenAccountStr, "solver-token-account", "", "Solver wJUNO token account (base58)")
	fs.StringVar(&mintStr, "mint", "", "SPL token mint pubkey (base58)")
	fs.StringVar(&keypairPath, "keypair", solvernet.DefaultSolanaKeypairPath(), "Solana keypair path (Solana CLI JSON format)")
	fs.Uint64Var(&priceZatPerUnit, "price-zat-per-token-unit", 0, "Fixed price: zatoshis per Solana token base unit")
	fs.UintVar(&spreadBps, "spread-bps", 0, "Spread in bps applied to the required JunoCash amount")
	fs.StringVar(&orchardReceiverHex, "orchard-receiver-bytes-hex", "", "Orchard receiver bytes for DirectionA settlement (43-byte hex)")
	fs.DurationVar(&pollInterval, "poll-interval", 2*time.Second, "Poll interval for scanning for bound intents")
	fs.UintVar(&airdropSol, "airdrop-sol", 0, "Request this many SOL before starting (devnet/localnet only)")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if deploymentHex == "" || quoteURL == "" || iepProgramStr == "" || solverTokenAccountStr == "" || mintStr == "" || priceZatPerUnit == 0 || orchardReceiverHex == "" {
		return errors.New("--deployment-id, --quote-url, --iep-program-id, --solver-token-account, --mint, --price-zat-per-token-unit, and --orchard-receiver-bytes-hex are required")
	}
	if spreadBps > 10_000 {
		return errors.New("--spread-bps must be <= 10000")
	}

	deploymentID, err := protocol.ParseDeploymentIDHex(deploymentHex)
	if err != nil {
		return fmt.Errorf("parse deployment id: %w", err)
	}
	iepProgram, err := solana.ParsePubkey(iepProgramStr)
	if err != nil {
		return fmt.Errorf("parse --iep-program-id: %w", err)
	}
	mint, err := solana.ParsePubkey(mintStr)
	if err != nil {
		return fmt.Errorf("parse --mint: %w", err)
	}
	solverTokenAccount, err := solana.ParsePubkey(solverTokenAccountStr)
	if err != nil {
		return fmt.Errorf("parse --solver-token-account: %w", err)
	}

	priv, pub, err := solvernet.LoadSolanaKeypair(keypairPath)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}
	solverPub := protocol.SolanaPubkey(pub)

	orchardReceiverBytes, err := hexBytes(orchardReceiverHex, protocol.OrchardReceiverBytesLen)
	if err != nil {
		return fmt.Errorf("parse --orchard-receiver-bytes-hex: %w", err)
	}

	hc, err := helius.ClientFromEnv()
	if err != nil && !errors.Is(err, helius.ErrMissingAPIKey) {
		return fmt.Errorf("helius: %w", err)
	}
	if errors.Is(err, helius.ErrMissingAPIKey) {
		hc = nil
	}

	solver := &solvernet.Solver{
		DeploymentID: deploymentID,
		SolverPubkey: solverPub,
		QuoteURL:     quoteURL,
		PrivKey:      priv,
		Mint:         protocol.SolanaPubkey(mint),
		OrchardReceiverBytes: orchardReceiverBytes,
		Strategy: solvernet.FixedPriceStrategy{
			ZatoshiPerTokenUnit: priceZatPerUnit,
			SpreadBps:           uint16(spreadBps),
		},
		Helius: hc,
	}

	handler, err := solver.Handler()
	if err != nil {
		return err
	}

	rpc, err := solanarpc.ClientFromEnv()
	if err != nil {
		return err
	}

	ctx := context.Background()
	if airdropSol != 0 {
		lamports := uint64(airdropSol) * 1_000_000_000
		sig, err := rpc.RequestAirdrop(ctx, solana.Pubkey(pub).Base58(), lamports)
		if err != nil {
			return fmt.Errorf("request airdrop: %w", err)
		}
		fmt.Fprintf(os.Stderr, "airdrop sig=%s\n", sig)
		time.Sleep(5 * time.Second)
	}
	go runAutoFillLoop(ctx, rpc, iepProgram, deploymentID, solana.Pubkey(pub), priv, mint, solverTokenAccount, pollInterval)

	s := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "listening on %s\n", listenAddr)
	return s.ListenAndServe()
}

func runAutoFillLoop(
	ctx context.Context,
	rpc *solanarpc.Client,
	iepProgram solana.Pubkey,
	deploymentID protocol.DeploymentID,
	solverPubkey solana.Pubkey,
	solverPriv ed25519.PrivateKey,
	mint solana.Pubkey,
	solverTokenAccount solana.Pubkey,
	interval time.Duration,
) {
	splTokenProgramID := mustParsePubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

	signers := map[solana.Pubkey]ed25519.PrivateKey{
		solverPubkey: solverPriv,
	}

	sleepCtx := func(d time.Duration) bool {
		if d <= 0 {
			return true
		}
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}

	baseInterval := interval
	if baseInterval <= 0 {
		baseInterval = 2 * time.Second
	}
	wait := baseInterval

	for {
		if !sleepCtx(wait) {
			return
		}

		accounts, err := rpc.ProgramAccountsByDataSizeBase64(ctx, iepProgram.Base58(), iep.IntentV3Len)
		if err != nil {
			fmt.Fprintf(os.Stderr, "autofill: getProgramAccounts: %v\n", err)
			var rpcErr *solanarpc.RPCError
			if errors.As(err, &rpcErr) && (rpcErr.Code == 403 || rpcErr.Code == 429) {
				// Public RPCs can temporarily block program account scans; back off
				// exponentially to avoid hammering the endpoint.
				wait *= 2
				if wait < 10*time.Second {
					wait = 10 * time.Second
				}
				if wait > 2*time.Minute {
					wait = 2 * time.Minute
				}
			} else {
				wait = baseInterval
			}
			continue
		}
		wait = baseInterval

		for _, pa := range accounts {
			intentPK, err := solana.ParsePubkey(pa.Pubkey)
			if err != nil {
				continue
			}

			intent, err := iep.ParseIntentV3(pa.Data)
			if err != nil {
				continue
			}
			if intent.Status != 0 {
				continue
			}
			if protocol.DeploymentID(intent.DeploymentID) != deploymentID {
				continue
			}
			if intent.Mint != mint {
				continue
			}
			if intent.Solver != solverPubkey {
				continue
			}
			if intent.Direction != 1 && intent.Direction != 2 {
				continue
			}

			cfgPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("config"), deploymentID[:]}, iepProgram)
			if err != nil {
				continue
			}
			fillPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("fill"), intentPK[:]}, iepProgram)
			if err != nil {
				continue
			}
			vaultPDA, _, err := solana.FindProgramAddress([][]byte{[]byte("vault"), fillPDA[:]}, iepProgram)
			if err != nil {
				continue
			}

			vault := vaultPDA
			if intent.Direction == 2 {
				vault = intent.Vault
			}

			ix := solana.Instruction{
				ProgramID: iepProgram,
				Accounts: []solana.AccountMeta{
					{Pubkey: solverPubkey, IsSigner: true, IsWritable: true},
					{Pubkey: cfgPDA, IsSigner: false, IsWritable: false},
					{Pubkey: intentPK, IsSigner: false, IsWritable: true},
					{Pubkey: fillPDA, IsSigner: false, IsWritable: true},
					{Pubkey: vault, IsSigner: false, IsWritable: true},
					{Pubkey: solverTokenAccount, IsSigner: false, IsWritable: true},
					{Pubkey: solverTokenAccount, IsSigner: false, IsWritable: false},
					{Pubkey: mint, IsSigner: false, IsWritable: false},
					{Pubkey: splTokenProgramID, IsSigner: false, IsWritable: false},
					{Pubkey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
				},
				Data: iep.EncodeFillIntent(intent.ReceiverTag, intent.JunocashAmountRequired),
			}

			bhCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			bh, err := rpc.LatestBlockhash(bhCtx)
			cancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "autofill: blockhash: %v\n", err)
				continue
			}

			tx, err := solana.BuildAndSignLegacyTransaction(
				bh,
				solverPubkey,
				signers,
				[]solana.Instruction{ix},
			)
			if err != nil {
				fmt.Fprintf(os.Stderr, "autofill: build tx: %v\n", err)
				continue
			}

			sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			sig, err := rpc.SendTransaction(sendCtx, tx, false)
			cancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "autofill: send tx: %v\n", err)
				continue
			}
			fmt.Fprintf(os.Stderr, "autofill: filled intent=%s sig=%s\n", intentPK.Base58(), sig)
		}
	}
}

func mustParsePubkey(s string) solana.Pubkey {
	pk, err := solana.ParsePubkey(s)
	if err != nil {
		panic(err)
	}
	return pk
}

func cmdRFQ(argv []string) error {
	fs := flag.NewFlagSet("rfq", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentHex    string
		fillIDHex        string
		direction        string
		mint             string
		netAmount        string
		solanaRecipient  string
		intentExpirySlot string
		receiverTagHex   string
		announcementURLs multiString
		rfqNonceHex      string
	)
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&fillIDHex, "fill-id", "", "FillID (32-byte hex)")
	fs.StringVar(&direction, "direction", "A", "Direction: A (JunoCash->Solana) or B (Solana->JunoCash)")
	fs.StringVar(&mint, "mint", "", "SPL token mint pubkey (base58)")
	fs.StringVar(&netAmount, "net-amount", "", "Net amount (u64)")
	fs.StringVar(&solanaRecipient, "solana-recipient", "", "Recipient pubkey (base58)")
	fs.StringVar(&intentExpirySlot, "intent-expiry-slot", "", "Intent expiry slot (u64)")
	fs.StringVar(&receiverTagHex, "receiver-tag", "", "ReceiverTag (32-byte hex; required for direction B)")
	fs.Var(&announcementURLs, "announcement-url", "Announcement URL (repeatable)")
	fs.StringVar(&rfqNonceHex, "rfq-nonce", "", "RFQ nonce hex32 (optional; random if omitted)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if deploymentHex == "" || fillIDHex == "" || mint == "" || netAmount == "" || solanaRecipient == "" || intentExpirySlot == "" || len(announcementURLs) == 0 {
		return errors.New("missing required args (see --help)")
	}

	deploymentID, err := protocol.ParseDeploymentIDHex(deploymentHex)
	if err != nil {
		return fmt.Errorf("parse deployment id: %w", err)
	}

	var dir protocol.Direction
	switch strings.ToUpper(strings.TrimSpace(direction)) {
	case "A":
		dir = protocol.DirectionA
	case "B":
		dir = protocol.DirectionB
	default:
		return fmt.Errorf("invalid --direction: %q (want A or B)", direction)
	}

	var rfqNonce [32]byte
	if rfqNonceHex != "" {
		b, err := hex32(rfqNonceHex)
		if err != nil {
			return fmt.Errorf("parse rfq nonce: %w", err)
		}
		rfqNonce = b
	} else {
		if _, err := rand.Read(rfqNonce[:]); err != nil {
			return err
		}
	}

	fillIDBytes, err := hex32(fillIDHex)
	if err != nil {
		return fmt.Errorf("parse fill id: %w", err)
	}

	var receiverTag protocol.ReceiverTag
	if receiverTagHex != "" {
		b, err := hex32(receiverTagHex)
		if err != nil {
			return fmt.Errorf("parse receiver tag: %w", err)
		}
		receiverTag = protocol.ReceiverTag(b)
	}
	if dir == protocol.DirectionB && receiverTag == (protocol.ReceiverTag{}) {
		return errors.New("--receiver-tag is required for direction B")
	}

	reqJSON := solvernet.QuoteRequestJSON{
		DeploymentID:     deploymentID.Hex(),
		RFQNonce:         hex.EncodeToString(rfqNonce[:]),
		FillID:           hex.EncodeToString(fillIDBytes[:]),
		ReceiverTag:      receiverTag.Hex(),
		Direction:        uint8(dir),
		Mint:             mint,
		NetAmount:        netAmount,
		SolanaRecipient:  solanaRecipient,
		IntentExpirySlot: intentExpirySlot,
	}

	type gotQuote struct {
		QuoteURL string                            `json:"quote_url"`
		Signed   solvernet.SignedQuoteResponseJSON `json:"signed"`
		Q        protocol.QuoteResponse            `json:"-"`
	}

	var quotes []gotQuote

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := &solvernet.Client{}

	for _, u := range announcementURLs {
		signedAnn, err := client.FetchAnnouncement(ctx, u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", u, err)
			continue
		}
		ann, _ := signedAnn.Verify()
		if ann.DeploymentID != deploymentID {
			fmt.Fprintf(os.Stderr, "skip %s: deployment mismatch\n", u)
			continue
		}

		signed, err := client.FetchQuote(ctx, ann.QuoteURL, reqJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", ann.QuoteURL, err)
			continue
		}

		q, _ := signed.Verify()
		if q.SolverPubkey != ann.SolverPubkey {
			fmt.Fprintf(os.Stderr, "skip %s: solver pubkey mismatch\n", ann.QuoteURL)
			continue
		}
		quotes = append(quotes, gotQuote{QuoteURL: ann.QuoteURL, Signed: signed, Q: q})
	}

	sort.Slice(quotes, func(i, j int) bool {
		if dir == protocol.DirectionB {
			return quotes[i].Q.JunocashAmountRequired > quotes[j].Q.JunocashAmountRequired
		}
		return quotes[i].Q.JunocashAmountRequired < quotes[j].Q.JunocashAmountRequired
	})

	return printJSON(os.Stdout, quotes)
}

type multiString []string

func (m *multiString) String() string { return strings.Join(*m, ",") }
func (m *multiString) Set(s string) error {
	*m = append(*m, s)
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func hex32(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return out, errors.New("expected 32-byte hex")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, errors.New("expected 32-byte hex")
	}
	copy(out[:], b)
	return out, nil
}

func hexBytes(s string, n int) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if len(s) != n*2 {
		return nil, fmt.Errorf("expected %d-byte hex", n)
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("expected %d-byte hex", n)
	}
	return b, nil
}
