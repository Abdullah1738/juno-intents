package shelltest

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestE2EDevnetTestnetScriptWalletDatResolutionHandlesAbsolutePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if !bytes.Contains(src, []byte(`if [[ "${DATA_DIR}" != /* ]]; then`)) {
		t.Fatalf("script missing absolute-path guard for DATA_DIR")
	}
	if !bytes.Contains(src, []byte(`DATA_DIR="${ROOT}/${DATA_DIR}"`)) {
		t.Fatalf("script missing ROOT prefixing for relative DATA_DIR")
	}
	if bytes.Contains(src, []byte(`if [[ -f "${ROOT}/${p}" ]]; then`)) {
		t.Fatalf("script still prefixes ROOT onto absolute wallet candidate paths")
	}
	if !bytes.Contains(src, []byte(`if [[ -f "${p}" ]]; then`)) {
		t.Fatalf("script missing direct file check for wallet candidate paths")
	}
}

func TestE2EDevnetTestnetScriptUsesGetTransactionForConfirmations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if !bytes.Contains(src, []byte(`raw="$(jcli gettransaction "${txid}"`)) {
		t.Fatalf("script missing gettransaction confirmation path")
	}
	if !bytes.Contains(src, []byte(`raw="$(jcli getrawtransaction "${txid}" 1`)) {
		t.Fatalf("script missing getrawtransaction fallback path")
	}
	if bytes.Contains(src, []byte(`export JUNO_TESTNET_TXINDEX="${JUNO_TESTNET_TXINDEX:-0}"`)) {
		t.Fatalf("script unexpectedly forces txindex=0 for testnet")
	}
}

func TestE2EDevnetTestnetScriptWaitForOpTxidHandlesTransientNonJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if !bytes.Contains(src, []byte(`if [[ -z "${compact}" ]]; then`)) {
		t.Fatalf("script missing empty-output handling in wait_for_op_txid")
	}
	if !bytes.Contains(src, []byte(`z_getoperationresult returned non-JSON`)) {
		t.Fatalf("script missing non-JSON handling message in wait_for_op_txid")
	}
	if !bytes.Contains(src, []byte(`z_getoperationstatus`)) {
		t.Fatalf("script missing z_getoperationstatus diagnostics for wait_for_op_txid")
	}
	if !bytes.Contains(src, []byte(`junocash_save_op_debug`)) {
		t.Fatalf("script missing op debug artifact helper")
	}
	if !bytes.Contains(src, []byte(`wait_for_wallet_scan_complete`)) {
		t.Fatalf("script missing wallet scan wait helper")
	}
}

func TestE2EDevnetTestnetScriptUsesGranularStagesAndArtifacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	for _, needle := range []string{
		`set_stage "direction_a"`,
		`set_stage "direction_b"`,
		`set_stage "verify_balances"`,
		`set_stage "crp_report"`,
		`set_stage "complete"`,
	} {
		if !bytes.Contains(src, []byte(needle)) {
			t.Fatalf("script missing stage marker: %s", needle)
		}
	}

	if bytes.Contains(src, []byte(`---- docker logs (`)) {
		t.Fatalf("script still prints docker logs inline; should save to artifacts instead")
	}
	if !bytes.Contains(src, []byte(`junocash-`)) || !bytes.Contains(src, []byte(`.docker.log`)) {
		t.Fatalf("script missing docker log artifact filenames")
	}
}

func TestE2EDevnetTestnetScriptDefaultsTestnetMinConfToTen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if !bytes.Contains(src, []byte(`JUNO_E2E_JUNOCASH_SEND_MINCONF   (default: regtest=1, testnet=10)`)) {
		t.Fatalf("script usage text missing updated testnet minconf default")
	}
	if !bytes.Contains(src, []byte(`JUNOCASH_SEND_MINCONF="10"`)) {
		t.Fatalf("script missing testnet minconf default assignment")
	}
}

func TestE2EDevnetTestnetScriptWaitForTestnetSyncRequiresHeadersMatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if !bytes.Contains(src, []byte(`blocks == headers`)) {
		t.Fatalf("script missing blocks==headers sync requirement")
	}
	if !bytes.Contains(src, []byte(`fullyNotified`)) {
		t.Fatalf("script missing fullyNotified sync requirement")
	}
}
