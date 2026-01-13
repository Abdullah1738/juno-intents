package solana

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/mr-tron/base58"
)

type Pubkey [32]byte

var (
	ErrInvalidPubkey = errors.New("invalid pubkey")
)

func ParsePubkey(s string) (Pubkey, error) {
	var out Pubkey
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return out, ErrInvalidPubkey
	}

	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			return out, ErrInvalidPubkey
		}
		copy(out[:], b)
		return out, nil
	}

	b, err := base58.Decode(s)
	if err != nil || len(b) != 32 {
		return out, ErrInvalidPubkey
	}
	copy(out[:], b)
	return out, nil
}

func (k Pubkey) Base58() string {
	return base58.Encode(k[:])
}

