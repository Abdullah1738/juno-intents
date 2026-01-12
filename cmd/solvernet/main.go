package main

import (
	"bytes"
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
	"github.com/Abdullah1738/juno-intents/offchain/solanafees"
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
	fmt.Fprintln(w, "  solvernet rfq --deployment-id <hex32> --mint <base58> --net-amount <u64> --solana-recipient <base58> --intent-expiry-slot <u64> --announcement-url <url> [--announcement-url <url>...]")
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
		listenAddr         string
		deploymentHex      string
		quoteURL           string
		keypairPath        string
		priceZatPerUnit    uint64
		spreadBps          uint

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
	ann := protocol.SolverAnnouncement{
		DeploymentID: deploymentID,
		SolverPubkey: solverPub,
		QuoteURL:     quoteURL,
	}
	signedAnn, err := solvernet.NewSignedSolverAnnouncement(ann, priv)
	if err != nil {
		return err
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

	strategy := solvernet.FixedPriceStrategy{
		ZatoshiPerTokenUnit: priceZatPerUnit,
		SpreadBps:           uint16(spreadBps),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/announcement", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, signedAnn)
	})
	mux.HandleFunc("/v1/quote", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		var reqJSON solvernet.QuoteRequestJSON
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&reqJSON); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		req, err := reqJSON.ToProtocol()
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if req.DeploymentID != deploymentID {
			http.Error(w, "deployment mismatch", http.StatusBadRequest)
			return
		}

		quoteID := protocol.DeriveQuoteID(deploymentID, solverPub, req.RFQNonce)
		junoRequired, err := strategy.QuoteRequiredZatoshi(req.NetAmount)
		if err != nil {
			http.Error(w, "quote error", http.StatusInternalServerError)
			return
		}

		resp := protocol.QuoteResponse{
			DeploymentID:          deploymentID,
			SolverPubkey:          solverPub,
			QuoteID:               quoteID,
			Direction:             req.Direction,
			Mint:                  req.Mint,
			NetAmount:             req.NetAmount,
			JunocashAmountRequired: protocol.Zatoshi(junoRequired),
			FillExpirySlot:        req.IntentExpirySlot,
		}

		var hint *solvernet.FeeHint
		if hc != nil {
			h := &solvernet.FeeHint{}
			if len(fillKeys) != 0 {
				est, err := solanafees.EstimateFromHeliusByAccountKeys(
					r.Context(),
					hc,
					fillKeys,
					uint32(fillCULimit),
					uint64(fillSigs),
					opts,
				)
				if err == nil {
					h.FillTx = &est
				}
			}
			if len(settleKeys) != 0 {
				est, err := solanafees.EstimateFromHeliusByAccountKeys(
					r.Context(),
					hc,
					settleKeys,
					uint32(settleCULimit),
					uint64(settleSigs),
					opts,
				)
				if err == nil {
					h.SettleTx = &est
				}
			}
			if h.FillTx != nil || h.SettleTx != nil {
				hint = h
			}
		}

		signed, err := solvernet.NewSignedQuoteResponse(resp, priv, hint)
		if err != nil {
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, signed)
	})

	s := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "listening on %s\n", listenAddr)
	return s.ListenAndServe()
}

func cmdRFQ(argv []string) error {
	fs := flag.NewFlagSet("rfq", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		deploymentHex     string
		mint             string
		netAmount        string
		solanaRecipient  string
		intentExpirySlot string
		announcementURLs multiString
		rfqNonceHex      string
	)
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
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
		Direction:        uint8(protocol.DirectionA),
		Mint:             mint,
		NetAmount:        netAmount,
		SolanaRecipient:  solanaRecipient,
		IntentExpirySlot: intentExpirySlot,
	}

	type gotQuote struct {
		Solver string
		Q      protocol.QuoteResponse
		Hint   *solvernet.FeeHint
	}

	var quotes []gotQuote

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, u := range announcementURLs {
		ann, err := fetchAnnouncement(ctx, u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", u, err)
			continue
		}
		if ann.DeploymentID != deploymentID {
			fmt.Fprintf(os.Stderr, "skip %s: deployment mismatch\n", u)
			continue
		}

		signed, err := fetchQuote(ctx, ann.QuoteURL, reqJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", ann.QuoteURL, err)
			continue
		}

		q, err := signed.Verify()
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: invalid quote signature\n", ann.QuoteURL)
			continue
		}
		if q.SolverPubkey != ann.SolverPubkey {
			fmt.Fprintf(os.Stderr, "skip %s: solver pubkey mismatch\n", ann.QuoteURL)
			continue
		}
		quotes = append(quotes, gotQuote{Solver: ann.QuoteURL, Q: q, Hint: signed.FeeHint})
	}

	sort.Slice(quotes, func(i, j int) bool {
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

func fetchAnnouncement(ctx context.Context, u string) (protocol.SolverAnnouncement, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return protocol.SolverAnnouncement{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return protocol.SolverAnnouncement{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.SolverAnnouncement{}, fmt.Errorf("http %d", resp.StatusCode)
	}

	var signed solvernet.SignedSolverAnnouncementJSON
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&signed); err != nil {
		return protocol.SolverAnnouncement{}, err
	}
	return signed.Verify()
}

func fetchQuote(ctx context.Context, quoteURL string, req solvernet.QuoteRequestJSON) (solvernet.SignedQuoteResponseJSON, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return solvernet.SignedQuoteResponseJSON{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, quoteURL, bytes.NewReader(body))
	if err != nil {
		return solvernet.SignedQuoteResponseJSON{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return solvernet.SignedQuoteResponseJSON{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return solvernet.SignedQuoteResponseJSON{}, fmt.Errorf("http %d", resp.StatusCode)
	}
	var signed solvernet.SignedQuoteResponseJSON
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&signed); err != nil {
		return solvernet.SignedQuoteResponseJSON{}, err
	}
	return signed, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
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
