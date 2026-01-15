package main

import (
	"crypto/ed25519"
	"testing"

	"github.com/Abdullah1738/juno-intents/offchain/solana"
)

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
	if got[0] != 2 {
		t.Fatalf("variant=%d, want 2", got[0])
	}
}

func TestEncodeCrpFinalize_Golden(t *testing.T) {
	got := encodeCrpFinalize(7)
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0] != 3 || got[1] != 7 {
		t.Fatalf("bytes=%x, want 03 07", got)
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

func TestDecodeCrpConfigV1_Golden(t *testing.T) {
	const wantLen = 1 + 32 + 32 + 1 + 1 + 8 + 1 + (32 * 32) + 1
	b := make([]byte, wantLen)
	b[0] = 1 // version
	for i := 0; i < 32; i++ {
		b[1+i] = 0x11  // deployment id
		b[33+i] = 0x22 // admin
	}
	b[65] = 3 // threshold
	b[66] = 5 // conflict threshold
	// finalization_delay_slots = 9
	b[67] = 9
	b[75] = 2 // operator_count
	// operators start at 76
	off := 76
	for i := 0; i < 32; i++ {
		b[off+i] = 0x44
		b[off+32+i] = 0x55
	}
	// paused
	b[wantLen-1] = 0

	out, err := decodeCrpConfigV1(b)
	if err != nil {
		t.Fatalf("decodeCrpConfigV1: %v", err)
	}
	if out.Version != 1 || out.Threshold != 3 || out.ConflictThreshold != 5 || out.FinalizationDelaySlots != 9 || out.OperatorCount != 2 || out.Paused {
		t.Fatalf("unexpected decoded fields: %+v", out)
	}
	for i := 0; i < 32; i++ {
		if out.DeploymentID[i] != 0x11 || out.Admin[i] != 0x22 {
			t.Fatalf("id mismatch at %d", i)
		}
		if out.Operators[0][i] != 0x44 || out.Operators[1][i] != 0x55 {
			t.Fatalf("operator mismatch at %d", i)
		}
	}
}

func TestExtractObservationSignaturesFromTx(t *testing.T) {
	var blockhash [32]byte
	for i := range blockhash {
		blockhash[i] = 0x11
	}
	feeSeed := [32]byte{1, 2, 3}
	feePriv := ed25519.NewKeyFromSeed(feeSeed[:])
	feePub := feePriv.Public().(ed25519.PublicKey)
	var feePayer solana.Pubkey
	copy(feePayer[:], feePub)

	expectedMsg := []byte("hello")
	var sig [64]byte
	for i := range sig {
		sig[i] = byte(i)
	}
	var operator solana.Pubkey
	for i := range operator {
		operator[i] = 0xAA
	}

	ix := solana.Ed25519VerifyInstruction(sig, operator, expectedMsg)
	tx, err := solana.BuildAndSignLegacyTransaction(
		blockhash,
		feePayer,
		map[solana.Pubkey]ed25519.PrivateKey{feePayer: feePriv},
		[]solana.Instruction{ix},
	)
	if err != nil {
		t.Fatalf("BuildAndSignLegacyTransaction: %v", err)
	}

	allowed := map[solana.Pubkey]struct{}{operator: {}}
	out, err := extractObservationSignaturesFromTx(tx, expectedMsg, allowed)
	if err != nil {
		t.Fatalf("extractObservationSignaturesFromTx: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("len=%d", len(out))
	}
	if out[0].Pubkey != operator || out[0].Signature != sig {
		t.Fatalf("unexpected sig: %+v", out[0])
	}

	// Wrong message must not match.
	out2, err := extractObservationSignaturesFromTx(tx, []byte("nope"), allowed)
	if err != nil {
		t.Fatalf("extractObservationSignaturesFromTx (wrong msg): %v", err)
	}
	if len(out2) != 0 {
		t.Fatalf("len=%d, want 0", len(out2))
	}

	// Disallowed operator must not match.
	out3, err := extractObservationSignaturesFromTx(tx, expectedMsg, map[solana.Pubkey]struct{}{})
	if err != nil {
		t.Fatalf("extractObservationSignaturesFromTx (disallowed): %v", err)
	}
	if len(out3) != 0 {
		t.Fatalf("len=%d, want 0", len(out3))
	}
}
