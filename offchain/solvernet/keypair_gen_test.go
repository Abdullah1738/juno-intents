package solvernet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSolanaKeypairFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.json")

	pub, err := GenerateSolanaKeypairFile(path, false)
	if err != nil {
		t.Fatalf("GenerateSolanaKeypairFile: %v", err)
	}

	priv, gotPub, err := LoadSolanaKeypair(path)
	if err != nil {
		t.Fatalf("LoadSolanaKeypair: %v", err)
	}
	if len(priv) != 64 {
		t.Fatalf("private key len=%d, want 64", len(priv))
	}
	if gotPub != pub {
		t.Fatalf("pub mismatch")
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if (st.Mode() & 0o777) != 0o600 {
		t.Fatalf("mode=%#o, want 0600", st.Mode()&0o777)
	}

	if _, err := GenerateSolanaKeypairFile(path, false); err == nil {
		t.Fatalf("expected error when file exists without force")
	}

	pub2, err := GenerateSolanaKeypairFile(path, true)
	if err != nil {
		t.Fatalf("GenerateSolanaKeypairFile(force): %v", err)
	}
	if pub2 == pub {
		t.Fatalf("expected different pubkey after overwrite")
	}
}
