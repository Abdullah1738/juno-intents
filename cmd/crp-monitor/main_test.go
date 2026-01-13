package main

import (
	"strings"
	"testing"
)

func TestDecodeCrpHeightV1_Golden(t *testing.T) {
	var b [43]byte
	b[0] = 1 // version
	b[1] = 5 // height = 5
	for i := 0; i < 32; i++ {
		b[9+i] = 0x11
	}
	b[41] = 1 // finalized
	b[42] = 0 // conflicted

	out, err := decodeCrpHeightV1(b[:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Version != 1 || out.Height != 5 || !out.Finalized || out.Conflicted {
		t.Fatalf("unexpected decoded fields: %+v", out)
	}
	for i := 0; i < 32; i++ {
		if out.OrchardRoot[i] != 0x11 {
			t.Fatalf("orchard_root mismatch at %d", i)
		}
	}
}

func TestDecodeCrpCheckpointV1_Golden(t *testing.T) {
	var b [114]byte
	b[0] = 1 // version
	b[1] = 5 // height = 5

	for i := 0; i < 32; i++ {
		b[9+i] = 0x11  // block hash
		b[41+i] = 0x22 // orchard root
		b[73+i] = 0x33 // prev hash
	}
	b[105] = 9  // first_seen_slot = 9
	b[113] = 1  // finalized

	out, err := decodeCrpCheckpointV1(b[:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Version != 1 || out.Height != 5 || out.FirstSeenSlot != 9 || !out.Finalized {
		t.Fatalf("unexpected decoded fields: %+v", out)
	}
	for i := 0; i < 32; i++ {
		if out.BlockHash[i] != 0x11 || out.OrchardRoot[i] != 0x22 || out.PrevHash[i] != 0x33 {
			t.Fatalf("hash mismatch at %d", i)
		}
	}
}

func TestParseHex32_Trims(t *testing.T) {
	want := strings.Repeat("aa", 32)
	got, err := parseHex32("  \"0x" + want + "\"  ")
	if err != nil {
		t.Fatalf("parseHex32: %v", err)
	}
	for i := 0; i < 32; i++ {
		if got[i] != 0xaa {
			t.Fatalf("byte mismatch at %d", i)
		}
	}
}

func TestClassify(t *testing.T) {
	if st, _ := classify(true, 0, 10, nil); st != statusUnsafe {
		t.Fatalf("halted: got %s", st)
	}
	if st, _ := classify(false, 0, 10, []string{"x"}); st != statusUnsafe {
		t.Fatalf("alerted: got %s", st)
	}
	st, alerts := classify(false, 11, 10, nil)
	if st != statusDegraded || len(alerts) != 1 {
		t.Fatalf("lagged: status=%s alerts=%v", st, alerts)
	}
	st, alerts = classify(false, 10, 10, nil)
	if st != statusHealthy || len(alerts) != 0 {
		t.Fatalf("healthy: status=%s alerts=%v", st, alerts)
	}
}

