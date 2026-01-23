package shelltest

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestJunocashTestnetUpScriptSetsExportDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "junocash", "testnet", "up.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if !bytes.Contains(src, []byte(`-exportdir=/data`)) {
		t.Fatalf("testnet up.sh missing -exportdir=/data (required for backupwallet)")
	}
}

func TestJunocashRegtestUpScriptSetsExportDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script tests are not supported on windows")
	}

	script := filepath.Clean(filepath.Join("..", "..", "scripts", "junocash", "regtest", "up.sh"))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	if !bytes.Contains(src, []byte(`-exportdir=/data`)) {
		t.Fatalf("regtest up.sh missing -exportdir=/data (required for backupwallet)")
	}
}

