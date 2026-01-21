package shelltest

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTeeScriptsAttemptSolverAirdropTopupWhenUnderfunded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	for _, rel := range []string{
		filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet-tee.sh"),
		filepath.Join("..", "..", "scripts", "e2e", "tee-preflight.sh"),
	} {
		script := filepath.Clean(rel)
		src, err := os.ReadFile(script)
		if err != nil {
			t.Fatalf("read script %s: %v", script, err)
		}
		if !bytes.Contains(src, []byte("attempting solana devnet airdrop top-up")) {
			t.Fatalf("script %s missing solver airdrop top-up fallback", script)
		}
		if !bytes.Contains(src, []byte("solver still needs funding")) {
			t.Fatalf("script %s missing post-topup funding error", script)
		}
	}
}

