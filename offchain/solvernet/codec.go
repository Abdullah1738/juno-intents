package solvernet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mr-tron/base58"
)

var (
	ErrInvalidHex32      = errors.New("invalid 32-byte hex")
	ErrInvalidPubkey     = errors.New("invalid pubkey")
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrInvalidU64String  = errors.New("invalid u64 string")
)

func encodeHex32(b [32]byte) string {
	return hex.EncodeToString(b[:])
}

func parseHex32(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return out, ErrInvalidHex32
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, ErrInvalidHex32
	}
	copy(out[:], raw)
	return out, nil
}

func encodeBase58_32(b [32]byte) string {
	return base58.Encode(b[:])
}

func parseBase58_32(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	raw, err := base58.Decode(s)
	if err != nil || len(raw) != 32 {
		return out, ErrInvalidPubkey
	}
	copy(out[:], raw)
	return out, nil
}

func encodeBase58_64(b [64]byte) string {
	return base58.Encode(b[:])
}

func parseBase58_64(s string) ([64]byte, error) {
	var out [64]byte
	s = strings.TrimSpace(s)
	raw, err := base58.Decode(s)
	if err != nil || len(raw) != 64 {
		return out, ErrInvalidSignature
	}
	copy(out[:], raw)
	return out, nil
}

func parseU64String(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, ErrInvalidU64String
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, ErrInvalidU64String
	}
	return v, nil
}

func formatU64String(v uint64) string {
	return fmt.Sprintf("%d", v)
}

