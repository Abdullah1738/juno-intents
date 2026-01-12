package solanafees

import (
	"context"
	"errors"
	"fmt"
	"math/bits"

	"github.com/Abdullah1738/juno-intents/offchain/helius"
)

var ErrOverflow = errors.New("overflow")

type TxFeeEstimate struct {
	LamportsPerSignature uint64 `json:"lamports_per_signature"`
	Signatures           uint64 `json:"signatures"`
	BaseFeeLamports      uint64 `json:"base_fee_lamports"`

	ComputeUnitLimit     uint32 `json:"compute_unit_limit"`
	MicroLamportsPerCU   uint64 `json:"micro_lamports_per_cu"`
	PriorityFeeLamports  uint64 `json:"priority_fee_lamports"`

	TotalLamports uint64 `json:"total_lamports"`
}

func PriorityFeeLamports(computeUnitLimit uint32, microLamportsPerCU uint64) (uint64, error) {
	if computeUnitLimit == 0 || microLamportsPerCU == 0 {
		return 0, nil
	}
	hi, lo := bits.Mul64(uint64(computeUnitLimit), microLamportsPerCU)
	if hi != 0 {
		return 0, ErrOverflow
	}
	const denom = uint64(1_000_000)
	return (lo + denom - 1) / denom, nil
}

func BaseFeeLamports(lamportsPerSignature uint64, signatures uint64) (uint64, error) {
	hi, lo := bits.Mul64(lamportsPerSignature, signatures)
	if hi != 0 {
		return 0, ErrOverflow
	}
	return lo, nil
}

func EstimateFromHeliusByAccountKeys(
	ctx context.Context,
	c *helius.Client,
	accountKeys []string,
	computeUnitLimit uint32,
	signatures uint64,
	opts *helius.PriorityFeeOptions,
) (TxFeeEstimate, error) {
	if c == nil {
		return TxFeeEstimate{}, errors.New("nil helius client")
	}
	if len(accountKeys) == 0 {
		return TxFeeEstimate{}, errors.New("accountKeys required")
	}

	feePerSig, err := c.LamportsPerSignature(ctx)
	if err != nil {
		return TxFeeEstimate{}, err
	}
	base, err := BaseFeeLamports(feePerSig, signatures)
	if err != nil {
		return TxFeeEstimate{}, err
	}

	est, err := c.GetPriorityFeeEstimateByAccountKeys(ctx, helius.PriorityFeeEstimateByAccountKeysRequest{
		AccountKeys: accountKeys,
		Options:     opts,
	})
	if err != nil {
		return TxFeeEstimate{}, err
	}
	priority, err := PriorityFeeLamports(computeUnitLimit, est.MicroLamports)
	if err != nil {
		return TxFeeEstimate{}, err
	}

	total, carry := bits.Add64(base, priority, 0)
	if carry != 0 {
		return TxFeeEstimate{}, ErrOverflow
	}

	return TxFeeEstimate{
		LamportsPerSignature: feePerSig,
		Signatures:           signatures,
		BaseFeeLamports:      base,
		ComputeUnitLimit:     computeUnitLimit,
		MicroLamportsPerCU:   est.MicroLamports,
		PriorityFeeLamports:  priority,
		TotalLamports:        total,
	}, nil
}

func (e TxFeeEstimate) String() string {
	return fmt.Sprintf("total=%d lamports (base=%d, priority=%d @ %d microLamports/CU, limit=%d)",
		e.TotalLamports,
		e.BaseFeeLamports,
		e.PriorityFeeLamports,
		e.MicroLamportsPerCU,
		e.ComputeUnitLimit,
	)
}

