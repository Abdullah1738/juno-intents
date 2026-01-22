package shelltest

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAWSE2EDevnetTestnetScriptFetchesFailureDebugArtifacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "aws", "e2e-devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	for _, needle := range []string{
		`downloading failure debug artifacts`,
		`junocash-*.docker.inspect.json`,
		`junocash-*.docker.log`,
		`junocash-opstatus-`,
		`junocash-opresult-`,
		`db5.3-util`,
		`install-db-dump.sh`,
		`JUNO_DB_DUMP=`,
		`JUNO_E2E_REMOTE_TAIL_INTERVAL_SECONDS`,
		`e2e tail (periodic):`,
		`/debug/`,
	} {
		if !bytes.Contains(src, []byte(needle)) {
			t.Fatalf("script missing debug artifact logic: %s", needle)
		}
	}
}
