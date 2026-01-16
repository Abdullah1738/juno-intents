package main

import (
	"context"
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
	case "announce":
		return cmdAnnounce(argv[1:])
	case "serve":
		return cmdServe(argv[1:])
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
	fmt.Fprintln(w, "  solvernet serve --listen :8080 --deployment-id <hex32> --quote-url <url> --price-zat-per-token-unit <u64> [--spread-bps <u16>] [--keypair <path>]")
	fmt.Fprintln(w, "  solvernet rfq --deployment-id <hex32> --direction A|B --mint <base58> --net-amount <u64> --solana-recipient <base58> --intent-expiry-slot <u64> --announcement-url <url> [--announcement-url <url>...]")
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
		keypairPath     string
		priceZatPerUnit uint64
		spreadBps       uint

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
	fs.StringVar(&keypairPath, "keypair", solvernet.DefaultSolanaKeypairPath(), "Solana keypair path (Solana CLI JSON format)")
	fs.Uint64Var(&priceZatPerUnit, "price-zat-per-token-unit", 0, "Fixed price: zatoshis per Solana token base unit")
	fs.UintVar(&spreadBps, "spread-bps", 0, "Spread in bps applied to the required JunoCash amount")

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
	if deploymentHex == "" || quoteURL == "" || priceZatPerUnit == 0 {
		return errors.New("--deployment-id, --quote-url, and --price-zat-per-token-unit are required")
	}
	if spreadBps > 10_000 {
		return errors.New("--spread-bps must be <= 10000")
	}

	deploymentID, err := protocol.ParseDeploymentIDHex(deploymentHex)
	if err != nil {
		return fmt.Errorf("parse deployment id: %w", err)
	}

	priv, pub, err := solvernet.LoadSolanaKeypair(keypairPath)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}

	solverPub := protocol.SolanaPubkey(pub)

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

func cmdRFQ(argv []string) error {
	fs := flag.NewFlagSet("rfq", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentHex    string
		direction        string
		mint             string
		netAmount        string
		solanaRecipient  string
		intentExpirySlot string
		announcementURLs multiString
		rfqNonceHex      string
	)
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&direction, "direction", "A", "Direction: A (JunoCash->Solana) or B (Solana->JunoCash)")
	fs.StringVar(&mint, "mint", "", "SPL token mint pubkey (base58)")
	fs.StringVar(&netAmount, "net-amount", "", "Net amount (u64)")
	fs.StringVar(&solanaRecipient, "solana-recipient", "", "Recipient pubkey (base58)")
	fs.StringVar(&intentExpirySlot, "intent-expiry-slot", "", "Intent expiry slot (u64)")
	fs.Var(&announcementURLs, "announcement-url", "Announcement URL (repeatable)")
	fs.StringVar(&rfqNonceHex, "rfq-nonce", "", "RFQ nonce hex32 (optional; random if omitted)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if deploymentHex == "" || mint == "" || netAmount == "" || solanaRecipient == "" || intentExpirySlot == "" || len(announcementURLs) == 0 {
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

	reqJSON := solvernet.QuoteRequestJSON{
		DeploymentID:     deploymentID.Hex(),
		RFQNonce:         hex.EncodeToString(rfqNonce[:]),
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
