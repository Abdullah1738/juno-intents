package protocol

import (
	"encoding/hex"
	"errors"
)

var errInvalidHex32 = errors.New("invalid 32-byte hex value")

func parseHex32(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 64 {
		return out, errInvalidHex32
	}

	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, errInvalidHex32
	}

	copy(out[:], b)
	return out, nil
}

func hex32(b [32]byte) string {
	return hex.EncodeToString(b[:])
}
