package solvernet

import (
	"errors"
	"math/bits"

	"github.com/Abdullah1738/juno-intents/protocol"
)

type FixedPriceStrategy struct {
	ZatoshiPerTokenUnit uint64
	SpreadBps           uint16
}

func (s FixedPriceStrategy) QuoteZatoshi(netAmount uint64, direction protocol.Direction) (uint64, error) {
	if s.ZatoshiPerTokenUnit == 0 {
		return 0, errors.New("price required")
	}
	if s.SpreadBps > 10_000 {
		return 0, errors.New("spread too large")
	}

	hi, lo := bits.Mul64(netAmount, s.ZatoshiPerTokenUnit)
	if hi != 0 {
		return 0, ErrOverflow
	}
	base := lo
	if s.SpreadBps == 0 {
		return base, nil
	}

	switch direction {
	case protocol.DirectionA:
		// User pays JunoCash, receives Solana. Solver fee increases the required JunoCash.
		mult := uint64(10_000 + s.SpreadBps)
		hi, lo = bits.Mul64(base, mult)
		if hi != 0 {
			return 0, ErrOverflow
		}
		return (lo + 10_000 - 1) / 10_000, nil
	case protocol.DirectionB:
		// User pays Solana, receives JunoCash. Solver fee decreases the JunoCash payout.
		mult := uint64(10_000 - uint64(s.SpreadBps))
		hi, lo = bits.Mul64(base, mult)
		if hi != 0 {
			return 0, ErrOverflow
		}
		return lo / 10_000, nil
	default:
		return 0, errors.New("invalid direction")
	}
}

func (s FixedPriceStrategy) QuoteRequiredZatoshi(netAmount uint64) (uint64, error) {
	return s.QuoteZatoshi(netAmount, protocol.DirectionA)
}
