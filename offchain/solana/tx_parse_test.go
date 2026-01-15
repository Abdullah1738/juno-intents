package solana

import (
	"crypto/ed25519"
	"testing"
)

func TestParseEd25519SingleSignatureInstructionData_RoundTrip(t *testing.T) {
	var sig [64]byte
	for i := range sig {
		sig[i] = byte(i)
	}
	var pub Pubkey
	for i := range pub {
		pub[i] = 0xAA
	}
	msg := []byte("hello world")

	ix := Ed25519VerifyInstruction(sig, pub, msg)
	got, err := ParseEd25519SingleSignatureInstructionData(ix.Data)
	if err != nil {
		t.Fatalf("ParseEd25519SingleSignatureInstructionData: %v", err)
	}
	if got.Pubkey != pub {
		t.Fatalf("pubkey mismatch")
	}
	if got.Signature != sig {
		t.Fatalf("signature mismatch")
	}
	if string(got.Message) != string(msg) {
		t.Fatalf("message mismatch")
	}
}

func TestParseLegacyTransaction(t *testing.T) {
	var blockhash [32]byte
	for i := range blockhash {
		blockhash[i] = 0x11
	}

	feeSeed := [32]byte{1, 2, 3}
	feePriv := ed25519.NewKeyFromSeed(feeSeed[:])
	feePub := feePriv.Public().(ed25519.PublicKey)
	var feePayer Pubkey
	copy(feePayer[:], feePub)

	var sig [64]byte
	for i := range sig {
		sig[i] = 0xBB
	}
	var pub Pubkey
	for i := range pub {
		pub[i] = 0xCC
	}
	msg := []byte("msg")

	ix0 := Ed25519VerifyInstruction(sig, pub, msg)
	ix1 := Instruction{ProgramID: SystemProgramID, Accounts: nil, Data: []byte{1, 2, 3}}

	tx, err := BuildAndSignLegacyTransaction(blockhash, feePayer, map[Pubkey]ed25519.PrivateKey{feePayer: feePriv}, []Instruction{ix0, ix1})
	if err != nil {
		t.Fatalf("BuildAndSignLegacyTransaction: %v", err)
	}

	parsed, err := ParseLegacyTransaction(tx)
	if err != nil {
		t.Fatalf("ParseLegacyTransaction: %v", err)
	}
	if len(parsed.Instructions) != 2 {
		t.Fatalf("instructions=%d", len(parsed.Instructions))
	}

	foundEd := false
	foundSys := false
	for _, ix := range parsed.Instructions {
		switch ix.ProgramID {
		case Ed25519ProgramID:
			foundEd = true
			ed, err := ParseEd25519SingleSignatureInstructionData(ix.Data)
			if err != nil {
				t.Fatalf("ParseEd25519SingleSignatureInstructionData: %v", err)
			}
			if ed.Pubkey != pub || ed.Signature != sig || string(ed.Message) != string(msg) {
				t.Fatalf("ed mismatch: pub=%x sig=%x msg=%q", ed.Pubkey, ed.Signature, string(ed.Message))
			}
		case SystemProgramID:
			foundSys = true
			if string(ix.Data) != string([]byte{1, 2, 3}) {
				t.Fatalf("system data=%x", ix.Data)
			}
		}
	}
	if !foundEd {
		t.Fatalf("missing ed25519 instruction")
	}
	if !foundSys {
		t.Fatalf("missing system instruction")
	}
}

