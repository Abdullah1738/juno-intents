package shelltest

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestE2EDevnetTestnetScriptDoesNotClobberKeypairs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	// Ensure the script doesn't overwrite pre-funded keypairs when reusing a workdir.
	if !bytes.Contains(src, []byte(`elif [[ ! -s "${SOLVER_KEYPAIR}" ]]; then`)) {
		t.Fatalf("devnet-testnet.sh should reuse existing solver keypair when present")
	}
	if !bytes.Contains(src, []byte(`elif [[ ! -s "${CREATOR_KEYPAIR}" ]]; then`)) {
		t.Fatalf("devnet-testnet.sh should reuse existing creator keypair when present")
	}
}
