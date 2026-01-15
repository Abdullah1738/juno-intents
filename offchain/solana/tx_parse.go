package solana

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type ParsedInstruction struct {
	ProgramID Pubkey
	Accounts  []uint8
	Data      []byte
}

type ParsedLegacyMessage struct {
	AccountKeys    []Pubkey
	RecentBlockhash [32]byte
	Instructions   []ParsedInstruction
}

func ParseLegacyTransaction(tx []byte) (ParsedLegacyMessage, error) {
	var out ParsedLegacyMessage
	if len(tx) == 0 {
		return out, errors.New("empty tx")
	}

	off := 0
	sigCount, newOff, err := decodeShortVecLenAt(tx, off)
	if err != nil {
		return out, fmt.Errorf("decode signature count: %w", err)
	}
	off = newOff
	sigBytes := sigCount * 64
	if sigCount < 0 || sigBytes < 0 || off+sigBytes > len(tx) {
		return out, errors.New("invalid signature section")
	}
	off += sigBytes

	if off+3 > len(tx) {
		return out, errors.New("message header truncated")
	}
	off += 3

	nKeys, newOff, err := decodeShortVecLenAt(tx, off)
	if err != nil {
		return out, fmt.Errorf("decode account keys count: %w", err)
	}
	off = newOff
	if nKeys < 0 || off+(nKeys*32) > len(tx) {
		return out, errors.New("account keys truncated")
	}
	out.AccountKeys = make([]Pubkey, 0, nKeys)
	for i := 0; i < nKeys; i++ {
		var pk Pubkey
		copy(pk[:], tx[off:off+32])
		out.AccountKeys = append(out.AccountKeys, pk)
		off += 32
	}

	if off+32 > len(tx) {
		return out, errors.New("recent blockhash truncated")
	}
	copy(out.RecentBlockhash[:], tx[off:off+32])
	off += 32

	nIxs, newOff, err := decodeShortVecLenAt(tx, off)
	if err != nil {
		return out, fmt.Errorf("decode instruction count: %w", err)
	}
	off = newOff
	if nIxs < 0 {
		return out, errors.New("negative instruction count")
	}

	out.Instructions = make([]ParsedInstruction, 0, nIxs)
	for i := 0; i < nIxs; i++ {
		if off >= len(tx) {
			return out, errors.New("instruction truncated")
		}
		pidIndex := int(tx[off])
		off++
		if pidIndex < 0 || pidIndex >= len(out.AccountKeys) {
			return out, errors.New("invalid program id index")
		}

		acctCount, newOff, err := decodeShortVecLenAt(tx, off)
		if err != nil {
			return out, fmt.Errorf("decode instruction accounts count: %w", err)
		}
		off = newOff
		if acctCount < 0 || off+acctCount > len(tx) {
			return out, errors.New("instruction accounts truncated")
		}
		accounts := make([]uint8, acctCount)
		copy(accounts, tx[off:off+acctCount])
		off += acctCount

		dataLen, newOff, err := decodeShortVecLenAt(tx, off)
		if err != nil {
			return out, fmt.Errorf("decode instruction data len: %w", err)
		}
		off = newOff
		if dataLen < 0 || off+dataLen > len(tx) {
			return out, errors.New("instruction data truncated")
		}
		data := make([]byte, dataLen)
		copy(data, tx[off:off+dataLen])
		off += dataLen

		out.Instructions = append(out.Instructions, ParsedInstruction{
			ProgramID: out.AccountKeys[pidIndex],
			Accounts:  accounts,
			Data:      data,
		})
	}

	return out, nil
}

type ParsedEd25519Single struct {
	Pubkey    Pubkey
	Signature [64]byte
	Message   []byte
}

func ParseEd25519SingleSignatureInstructionData(data []byte) (ParsedEd25519Single, error) {
	var out ParsedEd25519Single
	if len(data) < 2+14+32+64 {
		return out, errors.New("ed25519 instruction too short")
	}
	if data[0] != 1 || data[1] != 0 {
		return out, errors.New("unsupported ed25519 signature count")
	}

	offs := data[2 : 2+14]
	sigOff := int(binary.LittleEndian.Uint16(offs[0:2]))
	sigIx := binary.LittleEndian.Uint16(offs[2:4])
	pubOff := int(binary.LittleEndian.Uint16(offs[4:6]))
	pubIx := binary.LittleEndian.Uint16(offs[6:8])
	msgOff := int(binary.LittleEndian.Uint16(offs[8:10]))
	msgLen := int(binary.LittleEndian.Uint16(offs[10:12]))
	msgIx := binary.LittleEndian.Uint16(offs[12:14])

	if sigIx != 0xFFFF || pubIx != 0xFFFF || msgIx != 0xFFFF {
		return out, errors.New("unsupported ed25519 cross-instruction offsets")
	}

	if pubOff < 0 || pubOff+32 > len(data) {
		return out, errors.New("pubkey out of bounds")
	}
	if sigOff < 0 || sigOff+64 > len(data) {
		return out, errors.New("signature out of bounds")
	}
	if msgOff < 0 || msgOff+msgLen > len(data) {
		return out, errors.New("message out of bounds")
	}

	copy(out.Pubkey[:], data[pubOff:pubOff+32])
	copy(out.Signature[:], data[sigOff:sigOff+64])
	out.Message = append([]byte{}, data[msgOff:msgOff+msgLen]...)
	return out, nil
}

func decodeShortVecLenAt(b []byte, off int) (int, int, error) {
	if off < 0 || off >= len(b) {
		return 0, off, errors.New("shortvec: out of bounds")
	}
	var out uint64
	var shift uint
	i := 0
	for {
		if off+i >= len(b) {
			return 0, off, errors.New("shortvec: truncated")
		}
		bt := b[off+i]
		out |= uint64(bt&0x7f) << shift
		i++
		if (bt & 0x80) == 0 {
			break
		}
		shift += 7
		if shift > 28 {
			return 0, off, errors.New("shortvec: too long")
		}
	}
	if out > uint64(^uint(0)>>1) {
		return 0, off, errors.New("shortvec: length overflows int")
	}
	return int(out), off + i, nil
}
