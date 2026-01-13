package main

import "testing"

func TestEncodeCrpSubmitObservation_Golden(t *testing.T) {
	var blockHash [32]byte
	var orchardRoot [32]byte
	var prevHash [32]byte
	for i := 0; i < 32; i++ {
		blockHash[i] = 0x11
		orchardRoot[i] = 0x22
		prevHash[i] = 0x33
	}

	got := encodeCrpSubmitObservation(5, blockHash, orchardRoot, prevHash)
	if len(got) != 1+8+32+32+32 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0] != 3 {
		t.Fatalf("variant=%d, want 3", got[0])
	}
}

func TestEncodeCrpFinalize_Golden(t *testing.T) {
	got := encodeCrpFinalize(7)
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0] != 4 || got[1] != 7 {
		t.Fatalf("bytes=%x, want 04 07", got)
	}
}

func TestDecodeCrpCheckpointV1_Golden(t *testing.T) {
	var b [114]byte
	b[0] = 1 // version

	// height = 5
	b[1] = 5

	for i := 0; i < 32; i++ {
		b[9+i] = 0x11       // block hash
		b[41+i] = 0x22      // orchard root
		b[73+i] = 0x33      // prev hash
	}
	// first_seen_slot = 9
	b[105] = 9
	// finalized
	b[113] = 1

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

