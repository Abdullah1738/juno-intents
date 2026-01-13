package solana

import (
	"encoding/binary"
)

var (
	SystemProgramID = mustParsePubkey("11111111111111111111111111111111")
	Ed25519ProgramID = mustParsePubkey("Ed25519SigVerify111111111111111111111111111")
	ComputeBudgetProgramID = mustParsePubkey("ComputeBudget111111111111111111111111111111")
	InstructionsSysvarID = mustParsePubkey("Sysvar1nstructions1111111111111111111111111")
)

func mustParsePubkey(s string) Pubkey {
	pk, err := ParsePubkey(s)
	if err != nil {
		panic(err)
	}
	return pk
}

func ComputeBudgetSetComputeUnitLimit(limit uint32) Instruction {
	var data [5]byte
	data[0] = 2
	binary.LittleEndian.PutUint32(data[1:], limit)
	return Instruction{
		ProgramID: ComputeBudgetProgramID,
		Accounts:  nil,
		Data:      data[:],
	}
}

func ComputeBudgetSetComputeUnitPrice(microLamports uint64) Instruction {
	var data [9]byte
	data[0] = 3
	binary.LittleEndian.PutUint64(data[1:], microLamports)
	return Instruction{
		ProgramID: ComputeBudgetProgramID,
		Accounts:  nil,
		Data:      data[:],
	}
}

func Ed25519VerifyInstruction(signature [64]byte, pubkey Pubkey, message []byte) Instruction {
	// Canonical 1-signature format:
	//   u8 num_signatures = 1
	//   u8 padding = 0
	//   offsets (14 bytes)
	//   pubkey (32)
	//   signature (64)
	//   message (len)
	//
	// Offsets refer to fields within this same instruction (instruction_index = u16::MAX).
	const (
		offsetsStart = 2
		offsetsLen   = 14
		dataStart    = offsetsStart + offsetsLen
		pubkeyOff    = dataStart
		sigOff       = pubkeyOff + 32
		msgOff       = sigOff + 64
	)
	out := make([]byte, 0, msgOff+len(message))
	out = append(out, 1, 0)

	writeOffsets := func(signatureOffset uint16, signatureIx uint16, pubkeyOffset uint16, pubkeyIx uint16, msgOffset uint16, msgSize uint16, msgIx uint16) {
		var tmp [14]byte
		binary.LittleEndian.PutUint16(tmp[0:2], signatureOffset)
		binary.LittleEndian.PutUint16(tmp[2:4], signatureIx)
		binary.LittleEndian.PutUint16(tmp[4:6], pubkeyOffset)
		binary.LittleEndian.PutUint16(tmp[6:8], pubkeyIx)
		binary.LittleEndian.PutUint16(tmp[8:10], msgOffset)
		binary.LittleEndian.PutUint16(tmp[10:12], msgSize)
		binary.LittleEndian.PutUint16(tmp[12:14], msgIx)
		out = append(out, tmp[:]...)
	}

	writeOffsets(
		uint16(sigOff),
		0xFFFF,
		uint16(pubkeyOff),
		0xFFFF,
		uint16(msgOff),
		uint16(len(message)),
		0xFFFF,
	)
	out = append(out, pubkey[:]...)
	out = append(out, signature[:]...)
	out = append(out, message...)

	return Instruction{
		ProgramID: Ed25519ProgramID,
		Accounts:  nil,
		Data:      out,
	}
}

