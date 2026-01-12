package solvernet

import (
	"errors"
	"math/bits"
)

type FixedPriceStrategy struct {
	ZatoshiPerTokenUnit uint64
	SpreadBps           uint16
}

func (s FixedPriceStrategy) QuoteRequiredZatoshi(netAmount uint64) (uint64, error) {
	if s.ZatoshiPerTokenUnit == 0 {
		return 0, errors.New("price required")
	}

	hi, lo := bits.Mul64(netAmount, s.ZatoshiPerTokenUnit)
	if hi != 0 {
		return 0, ErrOverflow
	}
	base := lo
	if s.SpreadBps == 0 {
		return base, nil
	}

	mult := uint64(10_000 + s.SpreadBps)
	hi, lo = bits.Mul64(base, mult)
	if hi != 0 {
		return 0, ErrOverflow
	}
	return (lo + 10_000 - 1) / 10_000, nil
}

