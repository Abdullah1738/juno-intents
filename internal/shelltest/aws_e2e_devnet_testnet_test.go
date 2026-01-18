package shelltest

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAwsE2EDevnetTestnetScriptValidatesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "aws", "e2e-devnet-testnet.sh"))

	t.Run("rejects invalid mode", func(t *testing.T) {
		cmd := exec.Command("bash", script, "--deployment", "devnet-tee-testnet-base", "--ref", "HEAD", "--crp-mode", "v2", "--mode", "nope")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected failure, got success (out=%q)", string(out))
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected ExitError, got %T (err=%v out=%q)", err, err, string(out))
		}
		if code := exitErr.ExitCode(); code != 2 {
			t.Fatalf("expected exit code 2, got %d (out=%q)", code, string(out))
		}
		if !bytes.Contains(out, []byte("--mode must be e2e or preflight")) {
			t.Fatalf("unexpected output: %q", string(out))
		}
	})

	t.Run("rejects preflight unless v2", func(t *testing.T) {
		cmd := exec.Command("bash", script, "--deployment", "devnet-tee-testnet-base", "--ref", "HEAD", "--crp-mode", "v1", "--mode", "preflight")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected failure, got success (out=%q)", string(out))
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected ExitError, got %T (err=%v out=%q)", err, err, string(out))
		}
		if code := exitErr.ExitCode(); code != 2 {
			t.Fatalf("expected exit code 2, got %d (out=%q)", code, string(out))
		}
		if !bytes.Contains(out, []byte("only supported with --crp-mode v2")) {
			t.Fatalf("unexpected output: %q", string(out))
		}
	})
}

