package receipt

import (
	"encoding/binary"
	"errors"

	"github.com/Abdullah1738/juno-intents/protocol"
)

const (
	ReceiptProofBundleVersionV1 uint16 = 1

	// Groth16ProofBytesLenV1 is the byte length of an uncompressed BN254 Groth16 proof.
	//
	// This is treated as an opaque blob whose internal point encoding must match the
	// on-chain verifier.
	Groth16ProofBytesLenV1 = 256

	ReceiptPublicInputCountV1 = 11

	ReceiptProofBundleBytesLenV1 = 2 + Groth16ProofBytesLenV1 + ReceiptPublicInputCountV1*32
)

var (
	ErrUnsupportedProofBundleVersion = errors.New("unsupported proof bundle version")
	ErrInvalidProofBundleLen         = errors.New("invalid proof bundle length")
	ErrInvalidReceiptPublicInputLen  = errors.New("invalid receipt public input length")
)

type Groth16ProofBytesV1 [Groth16ProofBytesLenV1]byte

// ReceiptProofBundleV1 is the prover output consumed by the Solana settlement path:
// a Groth16 proof + its exact ordered list of public inputs.
type ReceiptProofBundleV1 struct {
	Version uint16
	Proof   Groth16ProofBytesV1

	// PublicInputs are BN254 scalar field elements encoded as 32-byte big-endian.
	PublicInputs [ReceiptPublicInputCountV1][32]byte
}

func NewReceiptProofBundleV1(proof Groth16ProofBytesV1, publicInputs protocol.ReceiptPublicInputs) (ReceiptProofBundleV1, error) {
	fr := publicInputs.FrElements()
	if len(fr) != ReceiptPublicInputCountV1 {
		return ReceiptProofBundleV1{}, ErrInvalidReceiptPublicInputLen
	}

	var out ReceiptProofBundleV1
	out.Version = ReceiptProofBundleVersionV1
	out.Proof = proof
	for i := 0; i < ReceiptPublicInputCountV1; i++ {
		out.PublicInputs[i] = fr[i]
	}
	return out, nil
}

func (b ReceiptProofBundleV1) MarshalBinary() ([]byte, error) {
	if b.Version != ReceiptProofBundleVersionV1 {
		return nil, ErrUnsupportedProofBundleVersion
	}

	out := make([]byte, 0, ReceiptProofBundleBytesLenV1)

	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], b.Version)
	out = append(out, tmp[:]...)
	out = append(out, b.Proof[:]...)
	for i := 0; i < ReceiptPublicInputCountV1; i++ {
		out = append(out, b.PublicInputs[i][:]...)
	}
	return out, nil
}

func (b *ReceiptProofBundleV1) UnmarshalBinary(in []byte) error {
	if len(in) != ReceiptProofBundleBytesLenV1 {
		return ErrInvalidProofBundleLen
	}

	version := binary.LittleEndian.Uint16(in[0:2])
	if version != ReceiptProofBundleVersionV1 {
		return ErrUnsupportedProofBundleVersion
	}

	b.Version = version
	copy(b.Proof[:], in[2:2+Groth16ProofBytesLenV1])

	offset := 2 + Groth16ProofBytesLenV1
	for i := 0; i < ReceiptPublicInputCountV1; i++ {
		copy(b.PublicInputs[i][:], in[offset:offset+32])
		offset += 32
	}

	return nil
}
