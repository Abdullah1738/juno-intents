package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-intents/offchain/solana"
	"github.com/Abdullah1738/juno-intents/offchain/solvernet"
)

const (
	defaultWorkflowFile = "groth16.yml"
	defaultBranch       = "main"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" || argv[0] == "help" {
		printUsage(os.Stdout)
		return nil
	}

	switch argv[0] {
	case "witness":
		return cmdWitness(argv[1:])
	case "witness-ci":
		return cmdWitnessCI(argv[1:])
	case "set-witness-secret":
		return cmdSetWitnessSecret(argv[1:])
	case "prove-ci":
		return cmdProveCI(argv[1:])
	case "validate-image-ids":
		return cmdValidateImageIDs(argv[1:])
	case "init-orp":
		return cmdInitORP(argv[1:])
	case "orp-attestation-info":
		return cmdOrpAttestationInfo(argv[1:])
	case "orp-register-operator":
		return cmdOrpRegisterOperator(argv[1:])
	case "init-crp":
		return cmdInitCRP(argv[1:])
	case "init-iep":
		return cmdInitIEP(argv[1:])
	case "risc0-pda":
		return cmdRisc0PDA(argv[1:])
	case "init-risc0-verifier":
		return cmdInitRisc0Verifier(argv[1:])
	case "iep-create-intent":
		return cmdIepCreateIntent(argv[1:])
	case "iep-fill":
		return cmdIepFill(argv[1:])
	case "iep-settle":
		return cmdIepSettle(argv[1:])
	case "iep-pdas":
		return cmdIepPDAs(argv[1:])
	case "receipt-inputs":
		return cmdReceiptInputs(argv[1:])
	case "pda":
		return cmdPDA(argv[1:])
	case "keygen":
		return cmdKeygen(argv[1:])
	default:
		return fmt.Errorf("unknown command: %s", argv[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "juno-intents: local tooling")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  juno-intents witness [-- <wallet_witness_v1 args>]")
	fmt.Fprintln(w, "  juno-intents witness-ci [-- <wallet_witness_v1 args>]")
	fmt.Fprintln(w, "  juno-intents set-witness-secret [-- <wallet_witness_v1 args>]")
	fmt.Fprintln(w, "  juno-intents prove-ci [--witness-source regtest|secret]")
	fmt.Fprintln(w, "  juno-intents validate-image-ids --deployment <name> [--deployment-file <path>] [--payer-keypair <path>]")
	fmt.Fprintln(w, "  juno-intents init-orp --orp-program-id <pubkey> --deployment-id <hex32> --admin <pubkey> --junocash-chain-id <u8> --junocash-genesis-hash <hex32> --verifier-router-program <pubkey> --verifier-program-id <pubkey> --allowed-measurement <hex32> [--allowed-measurement <hex32>...] [--payer-keypair <path>] [--dry-run]")
	fmt.Fprintln(w, "  juno-intents orp-attestation-info --bundle-hex <hex>")
	fmt.Fprintln(w, "  juno-intents orp-register-operator --orp-program-id <pubkey> --deployment-id <hex32> --bundle-hex <hex> [--payer-keypair <path>] [--dry-run]")
	fmt.Fprintln(w, "  juno-intents init-crp --crp-program-id <pubkey> --deployment-id <hex32> --admin <pubkey> --threshold <u8> --conflict-threshold <u8> --finalization-delay-slots <u64> [--operator-registry-program <pubkey>] --operator <pubkey> [--operator <pubkey>...] [--payer-keypair <path>] [--dry-run]")
	fmt.Fprintln(w, "  juno-intents init-iep --iep-program-id <pubkey> --deployment-id <hex32> --fee-bps <u16> --fee-collector <pubkey> --checkpoint-registry-program <pubkey> --receipt-verifier-program <pubkey> --verifier-router-program <pubkey> --verifier-router <pubkey> --verifier-entry <pubkey> --verifier-program <pubkey> [--payer-keypair <path>] [--dry-run]")
	fmt.Fprintln(w, "  juno-intents risc0-pda --verifier-router-program-id <pubkey> [--selector JINT] [--print router|verifier-entry]")
	fmt.Fprintln(w, "  juno-intents init-risc0-verifier --verifier-router-program-id <pubkey> --verifier-program-id <pubkey> [--selector JINT] [--payer-keypair <path>] [--dry-run]")
	fmt.Fprintln(w, "  juno-intents iep-create-intent [--deployment <name>] --mint <pubkey> --solana-recipient <pubkey> --net-amount <u64> --expiry-slot <u64> [--direction A|B] [--intent-nonce <hex32>] [--creator-keypair <path>] [--creator-source-token-account <pubkey>] [--priority-level <level>]")
	fmt.Fprintln(w, "  juno-intents iep-fill [--deployment <name>] --intent <pubkey> --mint <pubkey> --receiver-tag <hex32> --junocash-amount <u64> [--solver-keypair <path>] [--solver-source-token-account <pubkey>] [--solver-destination-token-account <pubkey>] [--priority-level <level>]")
	fmt.Fprintln(w, "  juno-intents iep-settle --deployment <name> --intent <pubkey> --mint <pubkey> --recipient-token-account <pubkey> --fee-token-account <pubkey> [--bundle-hex <hex>] [--payer-keypair <path>] [--priority-level <level>]")
	fmt.Fprintln(w, "  juno-intents iep-pdas [--deployment <name>] --intent <pubkey> [--print <field>]")
	fmt.Fprintln(w, "  juno-intents receipt-inputs [--witness-hex <hex>] [--json]")
	fmt.Fprintln(w, "  juno-intents pda --program-id <pubkey> --deployment-id <hex32> --intent-nonce <hex32> [--print <field>]")
	fmt.Fprintln(w, "  juno-intents keygen [--out <path>] [--force]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  witness   Generate a v1 receipt witness hex from your local junocash wallet (prints hex to stdout).")
	fmt.Fprintln(w, "  witness-ci Generate a v1 receipt witness hex for the deterministic e2e Fill PDA (prints hex to stdout).")
	fmt.Fprintln(w, "  set-witness-secret Generate a v1 receipt witness hex for e2e and write it to the JUNO_RECEIPT_WITNESS_HEX GitHub Actions secret.")
	fmt.Fprintln(w, "  prove-ci  Triggers a workflow_dispatch GPU prove run and watches it.")
	fmt.Fprintln(w, "  validate-image-ids Fast v2 preflight that ensures devnet programs accept the repo's current zkVM method IDs.")
	fmt.Fprintln(w, "  init-orp  Initializes an ORP config PDA (one-time deploy step).")
	fmt.Fprintln(w, "  orp-attestation-info Prints parsed fields from an attestation Groth16 bundle.")
	fmt.Fprintln(w, "  orp-register-operator Registers a Nitro-attested operator key in ORP.")
	fmt.Fprintln(w, "  init-crp  Initializes a CRP config PDA (one-time deploy step).")
	fmt.Fprintln(w, "  init-iep  Initializes an IEP config PDA (one-time deploy step).")
	fmt.Fprintln(w, "  risc0-pda Prints Verifier Router PDAs for a selector.")
	fmt.Fprintln(w, "  init-risc0-verifier Initializes a Verifier Router PDA + adds a Groth16 verifier entry for a selector.")
	fmt.Fprintln(w, "  iep-create-intent Creates an IEP intent (devnet/mainnet RPC).")
	fmt.Fprintln(w, "  iep-fill  Fills an IEP intent (locks escrow).")
	fmt.Fprintln(w, "  iep-settle Settles a fill with a receipt bundle.")
	fmt.Fprintln(w, "  iep-pdas  Prints IEP-derived PDAs for an intent.")
	fmt.Fprintln(w, "  receipt-inputs Prints receipt public inputs for a witness.")
	fmt.Fprintln(w, "  pda       Prints the derived Intent/Fill PDAs for deterministic testing.")
	fmt.Fprintln(w, "  keygen    Generates a new Solana CLI JSON keypair file (0600).")
}

func cmdWitness(argv []string) error {
	fs := flag.NewFlagSet("witness", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var cargo string
	fs.StringVar(&cargo, "cargo", "cargo", "Path to cargo")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	pass := fs.Args()
	witnessHex, err := generateWitnessHex(cargo, pass)
	if err != nil {
		return err
	}
	fmt.Println(witnessHex)
	return nil
}

func cmdWitnessCI(argv []string) error {
	fs := flag.NewFlagSet("witness-ci", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var cargo string
	fs.StringVar(&cargo, "cargo", "cargo", "Path to cargo")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	pass := fs.Args()
	witnessArgs := append(e2eWalletWitnessArgs(), pass...)
	witnessHex, err := generateWitnessHex(cargo, witnessArgs)
	if err != nil {
		return err
	}
	fmt.Println(witnessHex)
	return nil
}

func cmdSetWitnessSecret(argv []string) error {
	fs := flag.NewFlagSet("set-witness-secret", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		gh    string
		cargo string
		repo  string
	)
	fs.StringVar(&gh, "gh", "gh", "Path to GitHub CLI")
	fs.StringVar(&cargo, "cargo", "cargo", "Path to cargo")
	fs.StringVar(&repo, "repo", "", "Override target repo for secret set (OWNER/REPO)")

	if err := fs.Parse(argv); err != nil {
		return err
	}

	pass := fs.Args()
	witnessArgs := append(e2eWalletWitnessArgs(), pass...)
	witnessHex, err := generateWitnessHex(cargo, witnessArgs)
	if err != nil {
		return err
	}

	if err := ghSecretSet(gh, repo, "JUNO_RECEIPT_WITNESS_HEX", witnessHex); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "updated secret JUNO_RECEIPT_WITNESS_HEX (len=%d)\n", len(witnessHex))
	return nil
}

func cmdProveCI(argv []string) error {
	fs := flag.NewFlagSet("prove-ci", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		gh            string
		workflow      string
		branch        string
		witnessSource string
	)
	fs.StringVar(&gh, "gh", "gh", "Path to GitHub CLI")
	fs.StringVar(&workflow, "workflow", defaultWorkflowFile, "Workflow file name (e.g. ci.yml)")
	fs.StringVar(&branch, "branch", defaultBranch, "Git ref to dispatch (e.g. main)")
	fs.StringVar(&witnessSource, "witness-source", "regtest", "Witness source input for groth16.yml: regtest or secret")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}

	if workflow == defaultWorkflowFile && witnessSource != "regtest" && witnessSource != "secret" {
		return fmt.Errorf("invalid --witness-source: %q (want regtest or secret)", witnessSource)
	}

	if err := ghWorkflowDispatch(gh, workflow, branch, witnessSource); err != nil {
		return err
	}

	runID, err := waitForLatestWorkflowDispatchRunID(gh, workflow, branch, 60*time.Second)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "dispatched run id: %d\n", runID)

	return ghRunWatch(gh, runID)
}

func cmdKeygen(argv []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		out   string
		force bool
	)
	fs.StringVar(&out, "out", solvernet.DefaultSolanaKeypairPath(), "Output keypair path (Solana CLI JSON format)")
	fs.BoolVar(&force, "force", false, "Overwrite existing file if set")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}
	if strings.TrimSpace(out) == "" {
		return errors.New("--out is required")
	}

	pub, err := solvernet.GenerateSolanaKeypairFile(out, force)
	if err != nil {
		return err
	}

	fmt.Printf("pubkey_base58=%s\n", solana.Pubkey(pub).Base58())
	fmt.Printf("keypair_file=%s\n", out)
	return nil
}

func generateWitnessHex(cargo string, walletWitnessArgs []string) (string, error) {
	args := []string{
		"run",
		"--quiet",
		"--manifest-path", "risc0/receipt/host/Cargo.toml",
		"--bin", "wallet_witness_v1",
	}
	if len(walletWitnessArgs) > 0 {
		args = append(args, "--")
		args = append(args, walletWitnessArgs...)
	}

	cmd := exec.Command(cargo, args...)
	cmd.Stdin = nil
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	witnessHex := strings.TrimSpace(string(out))
	if witnessHex == "" {
		return "", fmt.Errorf("witness generator produced empty output")
	}
	return witnessHex, nil
}

func ghWorkflowDispatch(gh, workflow, branch, witnessSource string) error {
	args := []string{"workflow", "run", workflow, "--ref", branch}
	if workflow == defaultWorkflowFile && witnessSource != "" {
		args = append(args, "-f", "witness_source="+witnessSource)
	}
	cmd := exec.Command(gh, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type ghRunListItem struct {
	DatabaseID int64  `json:"databaseId"`
	Status     string `json:"status"`
}

func waitForLatestWorkflowDispatchRunID(gh, workflow, branch string, timeout time.Duration) (int64, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		runID, err := latestWorkflowDispatchRunID(gh, workflow, branch)
		if err == nil && runID != 0 {
			return runID, nil
		}
		time.Sleep(3 * time.Second)
	}
	return 0, fmt.Errorf("timed out waiting for workflow_dispatch run to appear")
}

func latestWorkflowDispatchRunID(gh, workflow, branch string) (int64, error) {
	cmd := exec.Command(
		gh,
		"run", "list",
		"--workflow", workflow,
		"--branch", branch,
		"--event", "workflow_dispatch",
		"--limit", "1",
		"--json", "databaseId,status",
	)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return 0, err
	}

	var items []ghRunListItem
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		return 0, fmt.Errorf("parse gh run list JSON: %w", err)
	}
	if len(items) == 0 {
		return 0, fmt.Errorf("no runs returned")
	}
	if items[0].DatabaseID == 0 {
		return 0, fmt.Errorf("missing databaseId")
	}
	return items[0].DatabaseID, nil
}

func ghRunWatch(gh string, runID int64) error {
	cmd := exec.Command(gh, "run", "watch", strconv.FormatInt(runID, 10), "--interval", "30")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func repeatByte32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func e2eWalletWitnessArgs() []string {
	// Keep this in sync with:
	// - solana/intent-escrow/tests/e2e_risc0_groth16_settle.rs
	iepProgramID := repeatByte32(0xA1)
	deploymentID := repeatByte32(0x11)
	intentNonce := repeatByte32(0x33)

	_, _, err := findProgramAddress(
		[][]byte{[]byte("config"), deploymentID[:]},
		iepProgramID,
	)
	if err != nil {
		panic(err)
	}
	intent, _, err := findProgramAddress(
		[][]byte{[]byte("intent"), deploymentID[:], intentNonce[:]},
		iepProgramID,
	)
	if err != nil {
		panic(err)
	}
	fill, _, err := findProgramAddress(
		[][]byte{[]byte("fill"), intent[:]},
		iepProgramID,
	)
	if err != nil {
		panic(err)
	}

	return []string{
		"--deployment-id", fmt.Sprintf("%x", deploymentID),
		"--fill-id", fmt.Sprintf("%x", fill),
	}
}

func ghSecretSet(gh, repo, name, value string) error {
	args := []string{"secret", "set", name, "-a", "actions"}
	if repo != "" {
		args = append(args, "-R", repo)
	}

	cmd := exec.Command(gh, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Stdin = strings.NewReader(value)
	return cmd.Run()
}
