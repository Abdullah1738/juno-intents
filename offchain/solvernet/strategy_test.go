package solvernet

import (
	"testing"

	"github.com/Abdullah1738/juno-intents/protocol"
)

func TestFixedPriceStrategy_QuoteRequiredZatoshi(t *testing.T) {
	t.Parallel()

	s := FixedPriceStrategy{
		ZatoshiPerTokenUnit: 2,
		SpreadBps:           0,
	}
	got, err := s.QuoteRequiredZatoshi(3)
	if err != nil {
		t.Fatalf("QuoteRequiredZatoshi: %v", err)
	}
	if got != 6 {
		t.Fatalf("got=%d want=6", got)
	}

	s = FixedPriceStrategy{
		ZatoshiPerTokenUnit: 1,
		SpreadBps:           100,
	}
	got, err = s.QuoteRequiredZatoshi(100)
	if err != nil {
		t.Fatalf("QuoteRequiredZatoshi: %v", err)
	}
	if got != 101 {
		t.Fatalf("got=%d want=101", got)
	}

	s = FixedPriceStrategy{ZatoshiPerTokenUnit: ^uint64(0)}
	if _, err := s.QuoteRequiredZatoshi(^uint64(0)); err == nil {
		t.Fatalf("expected overflow")
	}
}

func TestFixedPriceStrategy_QuoteZatoshi_DirectionB(t *testing.T) {
	t.Parallel()

	s := FixedPriceStrategy{
		ZatoshiPerTokenUnit: 100,
		SpreadBps:           100,
	}
	got, err := s.QuoteZatoshi(10, protocol.DirectionB)
	if err != nil {
		t.Fatalf("QuoteZatoshi: %v", err)
	}
	// base=1000, spread=1% => payout floor(1000*0.99)=990
	if got != 990 {
		t.Fatalf("got=%d want=990", got)
	}
}
