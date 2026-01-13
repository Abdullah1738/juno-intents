package solana

import (
	"crypto/ed25519"
	"testing"
)

func decodeShortVecLen(b []byte) (n int, consumed int, ok bool) {
	var v uint64
	var shift uint
	for i := 0; i < len(b); i++ {
		v |= uint64(b[i]&0x7f) << shift
		if (b[i] & 0x80) == 0 {
			return int(v), i + 1, true
		}
		shift += 7
		if shift > 63 {
			return 0, 0, false
		}
	}
	return 0, 0, false
}

func TestBuildAndSignLegacyTransaction_SignatureVerifies(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 1
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	var feePayer Pubkey
	copy(feePayer[:], pub)

	var recipient Pubkey
	for i := range recipient {
		recipient[i] = 0x44
	}

	var blockhash [32]byte
	for i := range blockhash {
		blockhash[i] = 0x42
	}

	tx, err := BuildAndSignLegacyTransaction(
		blockhash,
		feePayer,
		map[Pubkey]ed25519.PrivateKey{feePayer: priv},
		[]Instruction{
			{
				ProgramID: SystemProgramID,
				Accounts: []AccountMeta{
					{Pubkey: feePayer, IsSigner: true, IsWritable: true},
					{Pubkey: recipient, IsSigner: false, IsWritable: true},
				},
				Data: []byte{1, 2, 3},
			},
		},
	)
	if err != nil {
		t.Fatalf("BuildAndSignLegacyTransaction: %v", err)
	}

	sigCount, off, ok := decodeShortVecLen(tx)
	if !ok {
		t.Fatalf("decode sigCount failed")
	}
	if sigCount != 1 {
		t.Fatalf("sigCount=%d, want 1", sigCount)
	}
	if len(tx) < off+64 {
		t.Fatalf("tx too short for signatures")
	}
	sig := tx[off : off+64]
	msg := tx[off+64:]
	if len(msg) == 0 {
		t.Fatalf("empty message")
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatalf("signature did not verify")
	}
}

