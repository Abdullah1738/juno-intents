package solvernet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http/httptest"
	"testing"

	"github.com/Abdullah1738/juno-intents/protocol"
)

func TestHTTP_AnnouncementAndQuote(t *testing.T) {
	t.Parallel()

	priv := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	pub := priv.Public().(ed25519.PublicKey)
	var pub32 [32]byte
	copy(pub32[:], pub)

	s := &Solver{
		DeploymentID: protocol.DeploymentID([32]byte{0x11}),
		SolverPubkey: protocol.SolanaPubkey(pub32),
		QuoteURL:     "http://placeholder.invalid/v1/quote",
		PrivKey:      priv,
		Mint:         protocol.SolanaPubkey([32]byte{0x22}),
		OrchardReceiverBytes: bytes.Repeat([]byte{0xAB}, protocol.OrchardReceiverBytesLen),
		Strategy: FixedPriceStrategy{
			ZatoshiPerTokenUnit: 2,
			SpreadBps:           0,
		},
	}

	handler, err := s.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	s.QuoteURL = ts.URL + "/v1/quote"

	ctx := context.Background()
	c := &Client{HTTP: ts.Client()}

	signedAnn, err := c.FetchAnnouncement(ctx, ts.URL+"/v1/announcement")
	if err != nil {
		t.Fatalf("FetchAnnouncement: %v", err)
	}
	ann, err := signedAnn.Verify()
	if err != nil {
		t.Fatalf("Verify announcement: %v", err)
	}
	if ann.QuoteURL != s.QuoteURL {
		t.Fatalf("quote url mismatch: got=%q want=%q", ann.QuoteURL, s.QuoteURL)
	}

	var rfq [32]byte
	rfq[0] = 7
	fillID := [32]byte{0x44}

	req := QuoteRequestJSON{
		DeploymentID:     ann.DeploymentID.Hex(),
		RFQNonce:         hex.EncodeToString(rfq[:]),
		FillID:           hex.EncodeToString(fillID[:]),
		ReceiverTag:      hex.EncodeToString(make([]byte, 32)),
		Direction:        uint8(protocol.DirectionA),
		Mint:             encodeBase58_32([32]byte{0x22}),
		NetAmount:        "100",
		SolanaRecipient:  encodeBase58_32([32]byte{0x33}),
		IntentExpirySlot: "999",
	}
	signedQuote, err := c.FetchQuote(ctx, ann.QuoteURL, req)
	if err != nil {
		t.Fatalf("FetchQuote: %v", err)
	}
	q, err := signedQuote.Verify()
	if err != nil {
		t.Fatalf("Verify quote: %v", err)
	}
	if q.JunocashAmountRequired != 200 {
		t.Fatalf("unexpected required amount: got=%d want=200", q.JunocashAmountRequired)
	}
}
