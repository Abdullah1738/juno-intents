package receipt

import (
	"context"
	"errors"
)

var (
	ErrReceiptProverUnavailable = errors.New("receipt prover unavailable")
)

// Prover produces Groth16 proofs for receipt witnesses.
//
// The returned proof bytes must be encoded exactly as expected by the on-chain
// verifier for ReceiptProofBundleV1.
type Prover interface {
	ProveReceipt(ctx context.Context, witness ReceiptWitnessV1) (Groth16ProofBytesV1, error)
}

type UnimplementedProver struct{}

func (UnimplementedProver) ProveReceipt(context.Context, ReceiptWitnessV1) (Groth16ProofBytesV1, error) {
	return Groth16ProofBytesV1{}, ErrReceiptProverUnavailable
}

func ProveReceiptBundleV1(ctx context.Context, prover Prover, witness ReceiptWitnessV1) (ReceiptProofBundleV1, error) {
	if prover == nil {
		return ReceiptProofBundleV1{}, ErrReceiptProverUnavailable
	}

	publicInputs, err := witness.PublicInputs()
	if err != nil {
		return ReceiptProofBundleV1{}, err
	}

	proof, err := prover.ProveReceipt(ctx, witness)
	if err != nil {
		return ReceiptProofBundleV1{}, err
	}

	return NewReceiptProofBundleV1(proof, publicInputs)
}
