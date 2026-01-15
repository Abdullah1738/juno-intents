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
	case "init-crp":
		return cmdInitCRP(argv[1:])
	case "init-iep":
		return cmdInitIEP(argv[1:])
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
	fmt.Fprintln(w, "  juno-intents init-crp --crp-program-id <pubkey> --deployment-id <hex32> --admin <pubkey> --threshold <u8> --conflict-threshold <u8> --finalization-delay-slots <u64> --operator <pubkey> [--operator <pubkey>...] [--payer-keypair <path>] [--dry-run]")
	fmt.Fprintln(w, "  juno-intents init-iep --iep-program-id <pubkey> --deployment-id <hex32> --fee-bps <u16> --fee-collector <pubkey> --checkpoint-registry-program <pubkey> --receipt-verifier-program <pubkey> --verifier-router-program <pubkey> --verifier-router <pubkey> --verifier-entry <pubkey> --verifier-program <pubkey> [--payer-keypair <path>] [--dry-run]")
	fmt.Fprintln(w, "  juno-intents pda --program-id <pubkey> --deployment-id <hex32> --intent-nonce <hex32> [--print <field>]")
	fmt.Fprintln(w, "  juno-intents keygen [--out <path>] [--force]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  witness   Generate a v1 receipt witness hex from your local junocash wallet (prints hex to stdout).")
	fmt.Fprintln(w, "  witness-ci Generate a v1 receipt witness hex for the deterministic e2e Fill PDA (prints hex to stdout).")
	fmt.Fprintln(w, "  set-witness-secret Generate a v1 receipt witness hex for e2e and write it to the JUNO_RECEIPT_WITNESS_HEX GitHub Actions secret.")
	fmt.Fprintln(w, "  prove-ci  Triggers a workflow_dispatch GPU prove run and watches it.")
	fmt.Fprintln(w, "  init-crp  Initializes a CRP config PDA (one-time deploy step).")
	fmt.Fprintln(w, "  init-iep  Initializes an IEP config PDA (one-time deploy step).")
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
