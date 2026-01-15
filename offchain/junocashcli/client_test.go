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
