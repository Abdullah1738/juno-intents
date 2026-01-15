package junocashcli

import (
	"strings"
	"testing"
)

func TestParseBlockJSON_Golden(t *testing.T) {
	raw := `{
  "hash": "aa",
  "confirmations": 42,
  "height": 123,
  "previousblockhash": "bb",
  "finalorchardroot": "cc",
  "tx": ["deadbeef"]
}`
	b, err := ParseBlockJSON(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseBlockJSON: %v", err)
	}
	if b.Hash != "aa" || b.Height != 123 || b.PreviousBlockHash != "bb" || b.FinalOrchardRoot != "cc" {
		t.Fatalf("unexpected block: %+v", b)
	}
}

func TestParseBlockchainInfoJSON_Golden(t *testing.T) {
	raw := `{
  "chain": "test"
}`
	info, err := ParseBlockchainInfoJSON(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseBlockchainInfoJSON: %v", err)
	}
	if info.Chain != "test" {
		t.Fatalf("unexpected chain: %q", info.Chain)
	}
}

func TestNormalizeChain(t *testing.T) {
	cases := []struct {
		In   string
		Want string
	}{
		{"main", ChainMainnet},
		{"mainnet", ChainMainnet},
		{"test", ChainTestnet},
		{"testnet", ChainTestnet},
		{"regtest", ChainRegtest},
	}
	for _, tc := range cases {
		got, err := NormalizeChain(tc.In)
		if err != nil {
			t.Fatalf("NormalizeChain(%q): %v", tc.In, err)
		}
		if got != tc.Want {
			t.Fatalf("NormalizeChain(%q): got %q want %q", tc.In, got, tc.Want)
		}
	}
	if _, err := NormalizeChain("unknown"); err == nil {
		t.Fatalf("NormalizeChain(unknown): expected error")
	}
}
