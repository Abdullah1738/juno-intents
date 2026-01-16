package solana

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func parseV0StaticKeys(tx []byte) ([]Pubkey, error) {
	sigCount, off, ok := decodeShortVecLen(tx)
	if !ok {
		return nil, errors.New("invalid tx: signature shortvec")
	}
	sigBytes := sigCount * 64
	if sigCount < 0 || sigBytes < 0 || off+sigBytes > len(tx) {
		return nil, errors.New("invalid tx: signature section")
	}
	msg := tx[off+sigBytes:]
	if len(msg) < 4 {
		return nil, errors.New("invalid tx: message too short")
	}
	if msg[0] != 0x80 {
		return nil, errors.New("invalid tx: missing v0 prefix")
	}

	msgOff := 1 + 3
	nKeys, consumed, ok := decodeShortVecLen(msg[msgOff:])
	if !ok {
		return nil, errors.New("invalid tx: keys shortvec")
	}
	msgOff += consumed
	if nKeys < 0 || msgOff+(nKeys*32) > len(msg) {
		return nil, errors.New("invalid tx: keys section")
	}
	keys := make([]Pubkey, 0, nKeys)
	for i := 0; i < nKeys; i++ {
		var pk Pubkey
		copy(pk[:], msg[msgOff:msgOff+32])
		msgOff += 32
		keys = append(keys, pk)
	}
	return keys, nil
}

func TestBuildAndSignV0Transaction_SignatureVerifies(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 2
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	var feePayer Pubkey
	copy(feePayer[:], pub)

	var recipient Pubkey
	for i := range recipient {
		recipient[i] = 0x55
	}

	var blockhash [32]byte
	for i := range blockhash {
		blockhash[i] = 0x43
	}

	tx, err := BuildAndSignV0Transaction(
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
		nil,
	)
	if err != nil {
		t.Fatalf("BuildAndSignV0Transaction: %v", err)
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
	if msg[0] != 0x80 {
		t.Fatalf("expected v0 message prefix 0x80, got 0x%02x", msg[0])
	}
}

func TestBuildAndSignV0Transaction_UsesLookupTable(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 3
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	var feePayer Pubkey
	copy(feePayer[:], pub)

	var blockhash [32]byte
	for i := range blockhash {
		blockhash[i] = 0x44
	}

	var lookupKey Pubkey
	for i := range lookupKey {
		lookupKey[i] = 0x99
	}

	others := make([]Pubkey, 0, 10)
	for n := 0; n < 10; n++ {
		var pk Pubkey
		for i := range pk {
			pk[i] = byte(0x10 + n)
		}
		others = append(others, pk)
	}

	ixAccounts := make([]AccountMeta, 0, 1+len(others))
	ixAccounts = append(ixAccounts, AccountMeta{Pubkey: feePayer, IsSigner: true, IsWritable: true})
	for _, pk := range others {
		ixAccounts = append(ixAccounts, AccountMeta{Pubkey: pk, IsSigner: false, IsWritable: true})
	}
	ix := Instruction{
		ProgramID: SystemProgramID,
		Accounts:  ixAccounts,
		Data:      []byte{9, 9, 9},
	}

	legacy, err := BuildAndSignLegacyTransaction(
		blockhash,
		feePayer,
		map[Pubkey]ed25519.PrivateKey{feePayer: priv},
		[]Instruction{ix},
	)
	if err != nil {
		t.Fatalf("BuildAndSignLegacyTransaction: %v", err)
	}

	lt := LookupTable{
		AccountKey: lookupKey,
		Addresses:  append([]Pubkey{}, others...),
	}
	v0, err := BuildAndSignV0Transaction(
		blockhash,
		feePayer,
		map[Pubkey]ed25519.PrivateKey{feePayer: priv},
		[]Instruction{ix},
		[]LookupTable{lt},
	)
	if err != nil {
		t.Fatalf("BuildAndSignV0Transaction: %v", err)
	}

	if len(v0) >= len(legacy) {
		t.Fatalf("expected v0 tx smaller than legacy (v0=%d legacy=%d)", len(v0), len(legacy))
	}

	keys, err := parseV0StaticKeys(v0)
	if err != nil {
		t.Fatalf("parseV0StaticKeys: %v", err)
	}
	inStatic := func(pk Pubkey) bool {
		for _, k := range keys {
			if k == pk {
				return true
			}
		}
		return false
	}

	for _, pk := range others {
		if inStatic(pk) {
			t.Fatalf("expected key %s to be loaded via lookup table, but it was static", pk.Base58())
		}
	}
}
