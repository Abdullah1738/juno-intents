package protocol

import "encoding/binary"

const ProtocolVersion uint16 = 1

const domainSeparator = "JUNO_INTENTS"

func prefixBytes(purpose string) []byte {
	// Format (no ambiguity, stable across languages):
	//   ASCII(domainSeparator) || 0x00 ||
	//   ASCII(purpose) || 0x00 ||
	//   u16_le(protocolVersion)
	//
	// All purpose strings are constants in this package.
	prefix := make([]byte, 0, len(domainSeparator)+1+len(purpose)+1+2)
	prefix = append(prefix, domainSeparator...)
	prefix = append(prefix, 0)
	prefix = append(prefix, purpose...)
	prefix = append(prefix, 0)

	var version [2]byte
	binary.LittleEndian.PutUint16(version[:], ProtocolVersion)
	prefix = append(prefix, version[:]...)

	return prefix
}
