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

func TestE2EDevnetTestnetScriptDoesNotLeakWitnessOnCommandLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if bytes.Contains(src, []byte("--witness-hex")) {
		t.Fatalf("devnet-testnet.sh should not pass witness hex via CLI args")
	}
	if !bytes.Contains(src, []byte("JUNO_ATTESTATION_WITNESS_HEX")) {
		t.Fatalf("devnet-testnet.sh should set JUNO_ATTESTATION_WITNESS_HEX for RISC0 proving")
	}
}

func TestAWSE2EDevnetTestnetScriptDetectsCudaArch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "aws", "e2e-devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if !bytes.Contains(src, []byte("nvidia-smi --query-gpu=compute_cap")) {
		t.Fatalf("e2e-devnet-testnet.sh should detect CUDA compute capability for NVCC flags")
	}
}
