package receipt

import (
	"encoding/binary"
	"errors"

	"github.com/Abdullah1738/juno-intents/protocol"
)

const (
	ReceiptZKVMProofBundleVersionV1 uint16 = 1
)

type ZKVMProofSystemV1 uint8

const (
	ZKVMProofSystemUnknown     ZKVMProofSystemV1 = 0
	ZKVMProofSystemRisc0Groth16 ZKVMProofSystemV1 = 1
)

var (
	ErrInvalidZKVMProofBundleVersion = errors.New("invalid zkvm proof bundle version")
	ErrInvalidZKVMProofBundleLen     = errors.New("invalid zkvm proof bundle length")
	ErrInvalidZKVMProofSystem        = errors.New("invalid zkvm proof system")
	ErrInvalidZKVMJournalLen         = errors.New("invalid zkvm journal length")
	ErrInvalidZKVMSealLen            = errors.New("invalid zkvm seal length")
)

type ReceiptZKVMProofBundleV1 struct {
	Version     uint16
	ProofSystem ZKVMProofSystemV1

	// ImageID is the zkVM program identity hash (e.g. RISC Zero MethodID).
	ImageID [32]byte

	// Journal is the canonical committed bytes (see protocol.ReceiptJournalBytesV1).
	Journal [protocol.ReceiptJournalBytesLenV1]byte

	// Seal is the proof blob consumed by the Solana verifier for ProofSystem.
	Seal []byte
}

func (b ReceiptZKVMProofBundleV1) MarshalBinary() ([]byte, error) {
	if b.Version != ReceiptZKVMProofBundleVersionV1 {
		return nil, ErrInvalidZKVMProofBundleVersion
	}
	if b.ProofSystem != ZKVMProofSystemRisc0Groth16 {
		return nil, ErrInvalidZKVMProofSystem
	}
	if len(b.Seal) == 0 {
		return nil, ErrInvalidZKVMSealLen
	}
	if len(b.Seal) > int(^uint32(0)) {
		return nil, ErrInvalidZKVMSealLen
	}

	// Canonical encoding:
	//   version_u16_le ||
	//   proof_system_u8 ||
	//   image_id (32) ||
	//   journal_len_u16_le ||
	//   journal_bytes ||
	//   seal_len_u32_le ||
	//   seal_bytes
	out := make([]byte, 0, 2+1+32+2+protocol.ReceiptJournalBytesLenV1+4+len(b.Seal))

	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], b.Version)
	out = append(out, u16[:]...)

	out = append(out, byte(b.ProofSystem))
	out = append(out, b.ImageID[:]...)

	binary.LittleEndian.PutUint16(u16[:], uint16(len(b.Journal)))
	out = append(out, u16[:]...)
	out = append(out, b.Journal[:]...)

	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(b.Seal)))
	out = append(out, u32[:]...)
	out = append(out, b.Seal...)

	return out, nil
}

func (b *ReceiptZKVMProofBundleV1) UnmarshalBinary(in []byte) error {
	const minLen = 2 + 1 + 32 + 2 + protocol.ReceiptJournalBytesLenV1 + 4
	if len(in) < minLen {
		return ErrInvalidZKVMProofBundleLen
	}

	version := binary.LittleEndian.Uint16(in[0:2])
	if version != ReceiptZKVMProofBundleVersionV1 {
		return ErrInvalidZKVMProofBundleVersion
	}
	b.Version = version

	b.ProofSystem = ZKVMProofSystemV1(in[2])
	if b.ProofSystem != ZKVMProofSystemRisc0Groth16 {
		return ErrInvalidZKVMProofSystem
	}

	offset := 3
	copy(b.ImageID[:], in[offset:offset+32])
	offset += 32

	journalLen := binary.LittleEndian.Uint16(in[offset : offset+2])
	offset += 2
	if journalLen != protocol.ReceiptJournalBytesLenV1 {
		return ErrInvalidZKVMJournalLen
	}

	copy(b.Journal[:], in[offset:offset+protocol.ReceiptJournalBytesLenV1])
	offset += protocol.ReceiptJournalBytesLenV1

	if len(in) < offset+4 {
		return ErrInvalidZKVMProofBundleLen
	}
	sealLen := binary.LittleEndian.Uint32(in[offset : offset+4])
	offset += 4

	if sealLen == 0 {
		return ErrInvalidZKVMSealLen
	}
	if len(in) != offset+int(sealLen) {
		return ErrInvalidZKVMProofBundleLen
	}

	b.Seal = make([]byte, sealLen)
	copy(b.Seal, in[offset:])
	return nil
}

