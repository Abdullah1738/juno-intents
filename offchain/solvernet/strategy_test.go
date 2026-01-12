package solvernet

import "testing"

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

