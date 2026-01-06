package protocol

import (
	"errors"
	"math"
	"math/bits"
)

type FeeBps uint16

const FeeBpsDenominator uint64 = 10_000

var (
	errInvalidFeeBps  = errors.New("invalid fee bps")
	errAmountOverflow = errors.New("amount overflow")
)

func (bps FeeBps) IsValid() bool {
	return uint64(bps) <= FeeBpsDenominator
}

// ProtocolFeeForNetAmount returns floor(net_amount * bps / 10_000).
//
// This intentionally defines the protocol fee as a deterministic function of the
// *net* amount paid to the recipient on Solana so that:
// - users can specify exact receive amounts
// - the payer deposits net+fee into escrow
func ProtocolFeeForNetAmount(netAmount uint64, bps FeeBps) (uint64, error) {
	if !bps.IsValid() {
		return 0, errInvalidFeeBps
	}
	if bps == 0 || netAmount == 0 {
		return 0, nil
	}

	hi, lo := bits.Mul64(netAmount, uint64(bps))
	fee, _ := bits.Div64(hi, lo, FeeBpsDenominator)
	return fee, nil
}

// GrossForNetAmount returns gross = net + fee(net, bps).
func GrossForNetAmount(netAmount uint64, bps FeeBps) (gross uint64, fee uint64, err error) {
	fee, err = ProtocolFeeForNetAmount(netAmount, bps)
	if err != nil {
		return 0, 0, err
	}
	if fee > math.MaxUint64-netAmount {
		return 0, 0, errAmountOverflow
	}
	return netAmount + fee, fee, nil
}
