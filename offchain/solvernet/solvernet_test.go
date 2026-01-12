package solvernet

import (
	"crypto/ed25519"
	"testing"

	"github.com/Abdullah1738/juno-intents/protocol"
)

func TestSignedSolverAnnouncementJSON_Verify(t *testing.T) {
	t.Parallel()

	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := priv.Public().(ed25519.PublicKey)

	var pub32 [32]byte
	copy(pub32[:], pub)

	ann := protocol.SolverAnnouncement{
		DeploymentID: protocol.DeploymentID([32]byte{0x11}),
		SolverPubkey: protocol.SolanaPubkey(pub32),
		QuoteURL:     "https://example.com/quote",
	}
	signed, err := NewSignedSolverAnnouncement(ann, priv)
	if err != nil {
		t.Fatalf("NewSignedSolverAnnouncement: %v", err)
	}

	got, err := signed.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != ann {
		t.Fatalf("announcement mismatch:\n got=%#v\nwant=%#v", got, ann)
	}

	signed.Announcement.QuoteURL = "https://evil.example/quote"
	if _, err := signed.Verify(); err == nil {
		t.Fatalf("expected verification failure after mutation")
	}
}

func TestSignedQuoteResponseJSON_Verify(t *testing.T) {
	t.Parallel()

	priv := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	pub := priv.Public().(ed25519.PublicKey)

	var pub32 [32]byte
	copy(pub32[:], pub)

	var rfqNonce [32]byte
	rfqNonce[0] = 9
	deployment := protocol.DeploymentID([32]byte{0x22})
	solver := protocol.SolanaPubkey(pub32)
	quoteID := protocol.DeriveQuoteID(deployment, solver, rfqNonce)

	q := protocol.QuoteResponse{
		DeploymentID:          deployment,
		SolverPubkey:          solver,
		QuoteID:               quoteID,
		Direction:             protocol.DirectionA,
		Mint:                  protocol.SolanaPubkey([32]byte{0x33}),
		NetAmount:             123,
		JunocashAmountRequired: 456,
		FillExpirySlot:        789,
	}

	signed, err := NewSignedQuoteResponse(q, priv, nil)
	if err != nil {
		t.Fatalf("NewSignedQuoteResponse: %v", err)
	}

	got, err := signed.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != q {
		t.Fatalf("quote mismatch:\n got=%#v\nwant=%#v", got, q)
	}

	signed.Quote.NetAmount = "999"
	if _, err := signed.Verify(); err == nil {
		t.Fatalf("expected verification failure after mutation")
	}
}

