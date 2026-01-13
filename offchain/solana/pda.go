package solana

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

var (
	ErrInvalidSeeds = errors.New("invalid seeds")
	ErrOnCurve      = errors.New("derived address is on-curve")
)

func FindProgramAddress(seeds [][]byte, programID Pubkey) (Pubkey, uint8, error) {
	for bump := uint8(255); ; bump-- {
		pda, err := CreateProgramAddress(append(seeds, []byte{bump}), programID)
		if err == nil {
			return pda, bump, nil
		}
		if bump == 0 {
			return Pubkey{}, 0, fmt.Errorf("no viable program address found")
		}
	}
}

func CreateProgramAddress(seeds [][]byte, programID Pubkey) (Pubkey, error) {
	if len(seeds) > 16 {
		return Pubkey{}, ErrInvalidSeeds
	}

	h := sha256.New()
	for _, seed := range seeds {
		if len(seed) > 32 {
			return Pubkey{}, ErrInvalidSeeds
		}
		h.Write(seed)
	}
	h.Write(programID[:])
	h.Write([]byte("ProgramDerivedAddress"))

	var out Pubkey
	copy(out[:], h.Sum(nil))
	if isOnCurve(out) {
		return Pubkey{}, ErrOnCurve
	}
	return out, nil
}

func isOnCurve(pk Pubkey) bool {
	_, err := new(edwards25519.Point).SetBytes(pk[:])
	return err == nil
}

