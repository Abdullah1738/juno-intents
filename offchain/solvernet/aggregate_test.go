package solvernet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Abdullah1738/juno-intents/protocol"
)

func newTestSolverServer(t *testing.T, deployment protocol.DeploymentID, seed byte, spreadBps uint16) (*httptest.Server, string, protocol.SolanaPubkey) {
	t.Helper()

	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	pub := priv.Public().(ed25519.PublicKey)
	var pub32 [32]byte
	copy(pub32[:], pub)

	s := &Solver{
		DeploymentID: deployment,
		SolverPubkey: protocol.SolanaPubkey(pub32),
		QuoteURL:     "",
		PrivKey:      priv,
		Mint:         protocol.SolanaPubkey([32]byte{0x33}),
		OrchardReceiverBytes: bytes.Repeat([]byte{seed}, protocol.OrchardReceiverBytesLen),
		Strategy: FixedPriceStrategy{
			ZatoshiPerTokenUnit: 100,
			SpreadBps:           spreadBps,
		},
	}
	handler, err := s.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	ts := httptest.NewServer(handler)
	s.QuoteURL = ts.URL + "/v1/quote"
	return ts, ts.URL + "/v1/announcement", protocol.SolanaPubkey(pub32)
}

func TestCollectQuotes_BestQuote_DirectionA(t *testing.T) {
	t.Parallel()

	deployment := protocol.DeploymentID([32]byte{0x11})

	s1, ann1, pub1 := newTestSolverServer(t, deployment, 1, 10)
	defer s1.Close()
	s2, ann2, pub2 := newTestSolverServer(t, deployment, 2, 200)
	defer s2.Close()

	req := protocol.QuoteRequest{
		DeploymentID:      deployment,
		RFQNonce:          [32]byte{0x22},
		FillID:            protocol.FillID([32]byte{0x55}),
		Direction:         protocol.DirectionA,
		Mint:              protocol.SolanaPubkey([32]byte{0x33}),
		NetAmount:         10,
		SolanaRecipient:   protocol.SolanaPubkey([32]byte{0x44}),
		IntentExpirySlot:  123,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := CollectQuotes(ctx, &Client{HTTP: &http.Client{Timeout: 5 * time.Second}}, []string{ann1, ann2}, req)
	if err != nil {
		t.Fatalf("CollectQuotes: %v", err)
	}
	if len(got.Quotes) != 2 {
		t.Fatalf("quotes=%d want=2", len(got.Quotes))
	}
	if got.Best.Quote.SolverPubkey != pub1 {
		t.Fatalf("best solver=%x want=%x (other=%x)", got.Best.Quote.SolverPubkey, pub1, pub2)
	}
	if got.Best.Quote.JunocashAmountRequired >= got.Quotes[1].Quote.JunocashAmountRequired {
		t.Fatalf("best quote amount not smallest: best=%d other=%d", got.Best.Quote.JunocashAmountRequired, got.Quotes[1].Quote.JunocashAmountRequired)
	}
}

func TestCollectQuotes_BestQuote_DirectionB(t *testing.T) {
	t.Parallel()

	deployment := protocol.DeploymentID([32]byte{0x11})

	s1, ann1, pub1 := newTestSolverServer(t, deployment, 3, 10)
	defer s1.Close()
	s2, ann2, pub2 := newTestSolverServer(t, deployment, 4, 200)
	defer s2.Close()

	req := protocol.QuoteRequest{
		DeploymentID:      deployment,
		RFQNonce:          [32]byte{0x22},
		FillID:            protocol.FillID([32]byte{0x55}),
		ReceiverTag:       protocol.ReceiverTag([32]byte{0x66}),
		Direction:         protocol.DirectionB,
		Mint:              protocol.SolanaPubkey([32]byte{0x33}),
		NetAmount:         10,
		SolanaRecipient:   protocol.SolanaPubkey([32]byte{0x44}),
		IntentExpirySlot:  123,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := CollectQuotes(ctx, &Client{HTTP: &http.Client{Timeout: 5 * time.Second}}, []string{ann1, ann2}, req)
	if err != nil {
		t.Fatalf("CollectQuotes: %v", err)
	}
	if len(got.Quotes) != 2 {
		t.Fatalf("quotes=%d want=2", len(got.Quotes))
	}
	if got.Best.Quote.SolverPubkey != pub1 {
		t.Fatalf("best solver=%x want=%x (other=%x)", got.Best.Quote.SolverPubkey, pub1, pub2)
	}
	if got.Best.Quote.JunocashAmountRequired <= got.Quotes[1].Quote.JunocashAmountRequired {
		t.Fatalf("best quote amount not largest: best=%d other=%d", got.Best.Quote.JunocashAmountRequired, got.Quotes[1].Quote.JunocashAmountRequired)
	}
}
