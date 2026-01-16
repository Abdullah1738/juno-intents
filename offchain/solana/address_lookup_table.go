package solana

import (
	"encoding/binary"
	"errors"
)

var ErrInvalidAddressLookupTable = errors.New("invalid address lookup table")

// ParseAddressLookupTableAddresses parses the address list from an Address Lookup Table account's raw data.
//
// Format:
//
//	u32  discriminator (1)
//	u64  deactivation_slot
//	u64  last_extended_slot
//	u8   last_extended_slot_start_index
//	u8   has_authority (0|1)
//	[32] authority pubkey (present even when has_authority=0; all-zero pubkey means none)
//	[2]  padding (0)
//	[32]* addresses (rest of the account data)
//
// This matches the on-chain layout used by the address lookup table program.
func ParseAddressLookupTableAddresses(data []byte) ([]Pubkey, error) {
	if len(data) < 56 {
		return nil, ErrInvalidAddressLookupTable
	}
	if binary.LittleEndian.Uint32(data[0:4]) != 1 {
		return nil, ErrInvalidAddressLookupTable
	}
	if (len(data)-56)%32 != 0 {
		return nil, ErrInvalidAddressLookupTable
	}
	n := (len(data) - 56) / 32
	out := make([]Pubkey, 0, n)
	off := 56
	for i := 0; i < n; i++ {
		var pk Pubkey
		copy(pk[:], data[off:off+32])
		out = append(out, pk)
		off += 32
	}
	return out, nil
}
