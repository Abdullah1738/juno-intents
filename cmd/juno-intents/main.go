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
	case "prove-ci":
		return cmdProveCI(argv[1:])
	case "pda":
		return cmdPDA(argv[1:])
	default:
		return fmt.Errorf("unknown command: %s", argv[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "juno-intents: local tooling")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  juno-intents witness [-- <wallet_witness_v1 args>]")
	fmt.Fprintln(w, "  juno-intents prove-ci")
	fmt.Fprintln(w, "  juno-intents pda --program-id <pubkey> --deployment-id <hex32> --intent-nonce <hex32> [--print <field>]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  witness   Generate a v1 receipt witness hex from your local junocash wallet (prints hex to stdout).")
	fmt.Fprintln(w, "  prove-ci  Triggers a workflow_dispatch GPU prove run and watches it.")
	fmt.Fprintln(w, "  pda       Prints the derived Intent/Fill PDAs for deterministic testing.")
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

func cmdProveCI(argv []string) error {
	fs := flag.NewFlagSet("prove-ci", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		gh       string
		workflow string
		branch   string
	)
	fs.StringVar(&gh, "gh", "gh", "Path to GitHub CLI")
	fs.StringVar(&workflow, "workflow", defaultWorkflowFile, "Workflow file name (e.g. ci.yml)")
	fs.StringVar(&branch, "branch", defaultBranch, "Git ref to dispatch (e.g. main)")

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}

	if err := ghWorkflowDispatch(gh, workflow, branch); err != nil {
		return err
	}

	runID, err := waitForLatestWorkflowDispatchRunID(gh, workflow, branch, 60*time.Second)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "dispatched run id: %d\n", runID)

	return ghRunWatch(gh, runID)
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

func ghWorkflowDispatch(gh, workflow, branch string) error {
	cmd := exec.Command(gh, "workflow", "run", workflow, "--ref", branch)
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
