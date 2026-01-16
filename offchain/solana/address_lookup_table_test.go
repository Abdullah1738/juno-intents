package solana

import (
	"encoding/binary"
	"testing"
)

func TestParseAddressLookupTableAddresses(t *testing.T) {
	var a Pubkey
	for i := range a {
		a[i] = 0x11
	}
	var b Pubkey
	for i := range b {
		b[i] = 0x22
	}

	data := make([]byte, 0, 56+64)
	var discr [4]byte
	binary.LittleEndian.PutUint32(discr[:], 1)
	data = append(data, discr[:]...)

	// deactivation_slot + last_extended_slot
	data = append(data, make([]byte, 8+8)...)
	// last_extended_slot_start_index + has_authority
	data = append(data, 0, 0)
	// authority pubkey (all zero for none)
	data = append(data, make([]byte, 32)...)
	// padding
	data = append(data, 0, 0)
	// addresses
	data = append(data, a[:]...)
	data = append(data, b[:]...)

	addrs, err := ParseAddressLookupTableAddresses(data)
	if err != nil {
		t.Fatalf("ParseAddressLookupTableAddresses: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("len(addrs)=%d, want 2", len(addrs))
	}
	if addrs[0] != a || addrs[1] != b {
		t.Fatalf("unexpected addresses")
	}
}

func TestParseAddressLookupTableAddresses_Invalid(t *testing.T) {
	if _, err := ParseAddressLookupTableAddresses(nil); err == nil {
		t.Fatalf("expected error for empty data")
	}
	tooShort := make([]byte, 55)
	if _, err := ParseAddressLookupTableAddresses(tooShort); err == nil {
		t.Fatalf("expected error for short data")
	}
}
