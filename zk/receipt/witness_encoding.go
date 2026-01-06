package receipt

import (
	"encoding/binary"
	"errors"

	"github.com/Abdullah1738/juno-intents/protocol"
)

const (
	ReceiptWitnessBytesLenV1 = 2 +
		32 + // deployment_id
		32 + // fill_id
		32 + // orchard_root
		32 + // cmx
		protocol.OrchardReceiverBytesLen +
		8 + // value_u64_le
		32 + // rho
		32 + // rseed
		4 + // merkle_index_u32_le
		OrchardMerkleDepth*32 // merkle siblings
)

var (
	ErrInvalidWitnessLen = errors.New("invalid witness length")
)

func (w ReceiptWitnessV1) MarshalBinary() ([]byte, error) {
	if err := w.Validate(); err != nil {
		return nil, err
	}

	out := make([]byte, 0, ReceiptWitnessBytesLenV1)

	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], w.Version)
	out = append(out, u16[:]...)

	out = append(out, w.DeploymentID[:]...)
	out = append(out, w.FillID[:]...)
	out = append(out, w.OrchardRoot[:]...)
	out = append(out, w.Cmx[:]...)

	out = append(out, w.Note.ReceiverBytes[:]...)

	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], uint64(w.Note.Value))
	out = append(out, u64[:]...)

	out = append(out, w.Note.Rho[:]...)
	out = append(out, w.Note.Rseed[:]...)

	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], w.Path.Index)
	out = append(out, u32[:]...)

	for i := 0; i < OrchardMerkleDepth; i++ {
		out = append(out, w.Path.Siblings[i][:]...)
	}

	if len(out) != ReceiptWitnessBytesLenV1 {
		return nil, ErrInvalidWitnessLen
	}

	return out, nil
}

func (w *ReceiptWitnessV1) UnmarshalBinary(in []byte) error {
	if len(in) != ReceiptWitnessBytesLenV1 {
		return ErrInvalidWitnessLen
	}

	version := binary.LittleEndian.Uint16(in[0:2])
	if version != ReceiptWitnessVersionV1 {
		return ErrUnsupportedWitnessVersion
	}

	w.Version = version

	offset := 2
	copy(w.DeploymentID[:], in[offset:offset+32])
	offset += 32
	copy(w.FillID[:], in[offset:offset+32])
	offset += 32
	copy(w.OrchardRoot[:], in[offset:offset+32])
	offset += 32
	copy(w.Cmx[:], in[offset:offset+32])
	offset += 32

	copy(w.Note.ReceiverBytes[:], in[offset:offset+protocol.OrchardReceiverBytesLen])
	offset += protocol.OrchardReceiverBytesLen

	w.Note.Value = protocol.Zatoshi(binary.LittleEndian.Uint64(in[offset : offset+8]))
	offset += 8

	copy(w.Note.Rho[:], in[offset:offset+32])
	offset += 32
	copy(w.Note.Rseed[:], in[offset:offset+32])
	offset += 32

	w.Path.Index = binary.LittleEndian.Uint32(in[offset : offset+4])
	offset += 4

	for i := 0; i < OrchardMerkleDepth; i++ {
		copy(w.Path.Siblings[i][:], in[offset:offset+32])
		offset += 32
	}

	if offset != ReceiptWitnessBytesLenV1 {
		return ErrInvalidWitnessLen
	}
	return nil
}
