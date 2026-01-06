package protocol

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	purposeIEPReceiverTag    = "iep_receiver_tag"
	purposeIEPSpentReceiptID = "iep_spent_receipt_id"
)

func ReceiverTagForReceiverBytes(deploymentID DeploymentID, receiverBytes []byte) (ReceiverTag, error) {
	if len(receiverBytes) != OrchardReceiverBytesLen {
		return ReceiverTag{}, errInvalidOrchardReceiverBytesLen
	}

	h := sha256.New()
	h.Write(prefixBytes(purposeIEPReceiverTag))
	h.Write(deploymentID[:])
	h.Write(receiverBytes)
	sum := h.Sum(nil)

	var out ReceiverTag
	copy(out[:], sum)
	return out, nil
}

func SpentReceiptIDForCmx(deploymentID DeploymentID, cmx Cmx) SpentReceiptID {
	// Replay protection is keyed solely by the note commitment (cmx) within a deployment.
	// A note appears under many later anchors, so do NOT include a checkpoint identifier.
	h := sha256.New()
	h.Write(prefixBytes(purposeIEPSpentReceiptID))
	h.Write(deploymentID[:])
	h.Write(cmx[:])
	sum := h.Sum(nil)

	var out SpentReceiptID
	copy(out[:], sum)
	return out
}

type ReceiptPublicInputs struct {
	DeploymentID DeploymentID
	OrchardRoot  OrchardRoot
	Cmx          Cmx
	Amount       Zatoshi
	ReceiverTag  ReceiverTag
}

func (in ReceiptPublicInputs) FrElements() [][32]byte {
	// Encoding for BN254 scalar field public inputs:
	// - 32-byte values are split into two 128-bit limbs: (lo, hi).
	// - Each limb is a field element encoded as 32-byte big-endian (left padded with zeros).
	// - u64 values are encoded as a single field element (32-byte big-endian).
	out := make([][32]byte, 0, 9)

	out = append(out, split32ToU128FrLimbs(in.DeploymentID[:])...)
	out = append(out, split32ToU128FrLimbs(in.OrchardRoot[:])...)
	out = append(out, split32ToU128FrLimbs(in.Cmx[:])...)

	out = append(out, frFromU64(uint64(in.Amount)))

	out = append(out, split32ToU128FrLimbs(in.ReceiverTag[:])...)
	return out
}

func split32ToU128FrLimbs(b []byte) [][32]byte {
	if len(b) != 32 {
		panic("split32ToU128FrLimbs requires 32 bytes")
	}

	// Treat b as a big-endian 256-bit integer and output limbs as (lo, hi).
	hi := b[0:16]
	lo := b[16:32]

	out := make([][32]byte, 0, 2)
	out = append(out, frFromU128BytesBE(lo))
	out = append(out, frFromU128BytesBE(hi))
	return out
}

func frFromU128BytesBE(b []byte) [32]byte {
	if len(b) != 16 {
		panic("frFromU128BytesBE requires 16 bytes")
	}
	var out [32]byte
	copy(out[16:], b)
	return out
}

func frFromU64(v uint64) [32]byte {
	var out [32]byte
	binary.BigEndian.PutUint64(out[24:], v)
	return out
}
