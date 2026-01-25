package shelltest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestE2EDevnetWorkflowPassesTestnetPrefundSecretsToV1E2E(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("workflow file tests are not supported on windows")
	}

	workflow := filepath.Clean(filepath.Join("..", "..", ".github", "workflows", "e2e-devnet.yml"))
	src, err := os.ReadFile(workflow)
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}

	content := string(src)
	stepHeader := "- name: Run devnet e2e (both directions)"
	stepStart := strings.Index(content, stepHeader)
	if stepStart == -1 {
		t.Fatalf("workflow missing step: %s", stepHeader)
	}

	remaining := content[stepStart:]
	stepEnd := strings.Index(remaining, "run: |")
	if stepEnd == -1 {
		t.Fatalf("workflow missing run block for step: %s", stepHeader)
	}

	stepBlock := remaining[:stepEnd]
	for _, needle := range []string{
		"JUNO_E2E_JUNOCASH_TESTNET_TADDR_WIF: ${{ secrets.JUNO_E2E_JUNOCASH_TESTNET_TADDR_WIF }}",
		"JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64: ${{ secrets.JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64 }}",
	} {
		if !strings.Contains(stepBlock, needle) {
			t.Fatalf("workflow step missing env var: %s", needle)
		}
	}
}

