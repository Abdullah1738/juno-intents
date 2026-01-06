package protocol

import (
	"encoding/hex"
	"testing"
)

func TestSolverAnnouncement_SigningBytes_Golden(t *testing.T) {
	var deploymentID DeploymentID
	for i := 0; i < 32; i++ {
		deploymentID[i] = byte(0x01 + i)
	}

	var solverPubkey SolanaPubkey
	for i := 0; i < 32; i++ {
		solverPubkey[i] = byte(0xA0 + i)
	}

	a := SolverAnnouncement{
		DeploymentID: deploymentID,
		SolverPubkey: solverPubkey,
		QuoteURL:     "https://solver.example/rfq",
	}

	got := hex.EncodeToString(a.SigningBytes())
	want := "4a554e4f5f494e54454e545300736f6c7665725f616e6e6f756e63656d656e740001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf1a0068747470733a2f2f736f6c7665722e6578616d706c652f726671"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestQuoteResponse_SigningBytes_Golden(t *testing.T) {
	var deploymentID DeploymentID
	for i := 0; i < 32; i++ {
		deploymentID[i] = byte(0x10 + i)
	}

	var solverPubkey SolanaPubkey
	for i := 0; i < 32; i++ {
		solverPubkey[i] = byte(0x20 + i)
	}

	var quoteID QuoteID
	for i := 0; i < 32; i++ {
		quoteID[i] = byte(0x30 + i)
	}

	var mint SolanaPubkey
	for i := 0; i < 32; i++ {
		mint[i] = byte(0x40 + i)
	}

	q := QuoteResponse{
		DeploymentID:           deploymentID,
		SolverPubkey:           solverPubkey,
		QuoteID:                quoteID,
		Direction:              DirectionA,
		Mint:                   mint,
		NetAmount:              1_000_000,
		JunocashAmountRequired: 12345,
		FillExpirySlot:         999,
	}

	b, err := q.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}

	got := hex.EncodeToString(b)
	want := "4a554e4f5f494e54454e54530071756f74655f726573706f6e7365000100101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f01404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f40420f00000000003930000000000000e703000000000000"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestDeriveQuoteID_Golden(t *testing.T) {
	var deploymentID DeploymentID
	for i := 0; i < 32; i++ {
		deploymentID[i] = byte(0xAA - i)
	}

	var solverPubkey SolanaPubkey
	for i := 0; i < 32; i++ {
		solverPubkey[i] = byte(0x10 + i)
	}

	var nonce [32]byte
	for i := 0; i < 32; i++ {
		nonce[i] = byte(i)
	}

	quoteID := DeriveQuoteID(deploymentID, solverPubkey, nonce)
	if got, want := quoteID.Hex(), "895dfe2b7bf1f317fe7935ee95a5ef51719b81bf16c23f0faf698f0453fe04b7"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
