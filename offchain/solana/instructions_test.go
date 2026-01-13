package solana

import (
	"encoding/binary"
	"testing"
)

func TestEd25519VerifyInstruction_CanonicalLayout(t *testing.T) {
	var sig [64]byte
	for i := range sig {
		sig[i] = 0xAA
	}
	var pub Pubkey
	for i := range pub {
		pub[i] = 0xBB
	}
	msg := []byte("hello")

	ix := Ed25519VerifyInstruction(sig, pub, msg)
	if ix.ProgramID != Ed25519ProgramID {
		t.Fatalf("ProgramID mismatch")
	}
	if ix.Accounts != nil {
		t.Fatalf("Accounts must be nil")
	}
	wantLen := 2 + 14 + 32 + 64 + len(msg)
	if len(ix.Data) != wantLen {
		t.Fatalf("data len=%d, want %d", len(ix.Data), wantLen)
	}
	if ix.Data[0] != 1 || ix.Data[1] != 0 {
		t.Fatalf("header bytes=%x, want 01 00", ix.Data[:2])
	}

	offs := ix.Data[2 : 2+14]
	sigOff := binary.LittleEndian.Uint16(offs[0:2])
	sigIx := binary.LittleEndian.Uint16(offs[2:4])
	pubOff := binary.LittleEndian.Uint16(offs[4:6])
	pubIx := binary.LittleEndian.Uint16(offs[6:8])
	msgOff := binary.LittleEndian.Uint16(offs[8:10])
	msgLen := binary.LittleEndian.Uint16(offs[10:12])
	msgIx := binary.LittleEndian.Uint16(offs[12:14])

	if sigOff != 48 || sigIx != 0xFFFF {
		t.Fatalf("sig offset=%d ix=%x, want 48 ffff", sigOff, sigIx)
	}
	if pubOff != 16 || pubIx != 0xFFFF {
		t.Fatalf("pub offset=%d ix=%x, want 16 ffff", pubOff, pubIx)
	}
	if msgOff != 112 || msgLen != uint16(len(msg)) || msgIx != 0xFFFF {
		t.Fatalf("msg offset=%d len=%d ix=%x, want 112 %d ffff", msgOff, msgLen, msgIx, len(msg))
	}

	gotPub := ix.Data[16:48]
	if string(gotPub) != string(pub[:]) {
		t.Fatalf("pubkey bytes mismatch")
	}
	gotSig := ix.Data[48:112]
	if string(gotSig) != string(sig[:]) {
		t.Fatalf("signature bytes mismatch")
	}
	gotMsg := ix.Data[112:]
	if string(gotMsg) != string(msg) {
		t.Fatalf("message bytes mismatch")
	}
}

