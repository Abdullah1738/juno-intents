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

func TestE2EDevnetTestnetScriptBacksUpWalletBeforeWitnessGeneration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	for _, needle := range []string{
		`backupwallet for witness (A):`,
		`walletwitnessadat`,
		`--wallet "${WALLET_WITNESS_DAT_A}"`,
		`backupwallet for witness (B):`,
		`walletwitnessbdat`,
		`--wallet "${WALLET_WITNESS_DAT_B}"`,
	} {
		if !bytes.Contains(src, []byte(needle)) {
			t.Fatalf("script missing witness backup behavior: %s", needle)
		}
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

func TestE2EDevnetTestnetScriptWaitForTxConfirmationsHandlesBadBlockHeaders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if !bytes.Contains(src, []byte(`tx confirmed but failed to parse block height`)) {
		t.Fatalf("script missing blockheader parse failure warning")
	}
	if !bytes.Contains(src, []byte(`json.loads(raw)`)) {
		t.Fatalf("script missing safe blockheader JSON parsing")
	}
}

func TestE2EDevnetTestnetScriptWaitsForMinconfSpendableNotesWhenNeeded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	for _, needle := range []string{
		`unspent="$(jcli z_listunspent "${JUNOCASH_SEND_MINCONF}"`,
		`FUND_ACTION_B="$(jcli z_listunspent "${JUNOCASH_SEND_MINCONF}"`,
		`extra_conf_blocks="$((JUNOCASH_SEND_MINCONF - 1))"`,
	} {
		if !bytes.Contains(src, []byte(needle)) {
			t.Fatalf("script missing minconf wait logic: %s", needle)
		}
	}
}

func TestE2EDevnetTestnetScriptContainsNoTabs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if bytes.Contains(src, []byte("\t")) {
		t.Fatalf("script contains tab characters; these can break embedded python3 -c snippets")
	}
}

func TestE2EDevnetTestnetScriptFundActionPythonSnippetHasNoLeadingIndent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	needle := `FUND_ACTION_B="$(jcli z_listunspent "${JUNOCASH_SEND_MINCONF}" 9999999 false | python3 -c 'import json,sys
txid=sys.argv[1].strip().lower()`
	if !bytes.Contains(src, []byte(needle)) {
		t.Fatalf("script missing unindented FUND_ACTION_B python snippet")
	}
}

func TestE2EDevnetTestnetScriptPassesDbDumpToWitnessGenerator(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "e2e", "devnet-testnet.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	for _, needle := range []string{
		`elif command -v db5.3_dump >/dev/null; then`,
		`db_dump_flag=(--db-dump "${db_dump}")`,
		`"${db_dump_flag[@]}"`,
	} {
		if !bytes.Contains(src, []byte(needle)) {
			t.Fatalf("script missing db_dump wiring: %s", needle)
		}
	}
}
