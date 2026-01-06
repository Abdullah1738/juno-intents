package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	ReceiptJournalVersionV1 uint16 = 1

	ReceiptJournalBytesLenV1 = 2 +
		32 + // deployment_id
		32 + // orchard_root
		32 + // cmx
		8 + // amount_u64_le
		32 + // receiver_tag
		32 // fill_id
)

var (
	ErrUnsupportedReceiptJournalVersion = errors.New("unsupported receipt journal version")
	ErrInvalidReceiptJournalLen         = errors.New("invalid receipt journal length")
)

// ReceiptJournalBytesV1 returns the canonical bytes committed by the zkVM
// receipt verifier.
//
// Encoding:
//
//	version_u16_le ||
//	deployment_id (32) ||
//	orchard_root (32) ||
//	cmx (32) ||
//	amount_u64_le ||
//	receiver_tag (32) ||
//	fill_id (32)
func (in ReceiptPublicInputs) ReceiptJournalBytesV1() []byte {
	out := make([]byte, 0, ReceiptJournalBytesLenV1)

	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], ReceiptJournalVersionV1)
	out = append(out, u16[:]...)

	out = append(out, in.DeploymentID[:]...)
	out = append(out, in.OrchardRoot[:]...)
	out = append(out, in.Cmx[:]...)

	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], uint64(in.Amount))
	out = append(out, u64[:]...)

	out = append(out, in.ReceiverTag[:]...)
	out = append(out, in.FillID[:]...)

	if len(out) != ReceiptJournalBytesLenV1 {
		panic("ReceiptJournalBytesV1 length mismatch")
	}
	return out
}

func ParseReceiptJournalV1(in []byte) (ReceiptPublicInputs, error) {
	if len(in) != ReceiptJournalBytesLenV1 {
		return ReceiptPublicInputs{}, ErrInvalidReceiptJournalLen
	}

	version := binary.LittleEndian.Uint16(in[0:2])
	if version != ReceiptJournalVersionV1 {
		return ReceiptPublicInputs{}, ErrUnsupportedReceiptJournalVersion
	}

	var out ReceiptPublicInputs
	offset := 2
	copy(out.DeploymentID[:], in[offset:offset+32])
	offset += 32
	copy(out.OrchardRoot[:], in[offset:offset+32])
	offset += 32
	copy(out.Cmx[:], in[offset:offset+32])
	offset += 32
	out.Amount = Zatoshi(binary.LittleEndian.Uint64(in[offset : offset+8]))
	offset += 8
	copy(out.ReceiverTag[:], in[offset:offset+32])
	offset += 32
	copy(out.FillID[:], in[offset:offset+32])
	offset += 32

	if offset != ReceiptJournalBytesLenV1 {
		return ReceiptPublicInputs{}, ErrInvalidReceiptJournalLen
	}

	return out, nil
}
