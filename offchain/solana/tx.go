package solana

import (
	"crypto/ed25519"
	"errors"
)

var ErrMissingSigner = errors.New("missing signer for required signature")

type AccountMeta struct {
	Pubkey     Pubkey
	IsSigner   bool
	IsWritable bool
}

type Instruction struct {
	ProgramID Pubkey
	Accounts  []AccountMeta
	Data      []byte
}

type messageHeader struct {
	NumRequiredSignatures        uint8
	NumReadonlySignedAccounts    uint8
	NumReadonlyUnsignedAccounts  uint8
}

func BuildAndSignLegacyTransaction(
	recentBlockhash [32]byte,
	feePayer Pubkey,
	signers map[Pubkey]ed25519.PrivateKey,
	instructions []Instruction,
) ([]byte, error) {
	msg, accountKeys, header, err := compileLegacyMessage(recentBlockhash, feePayer, instructions)
	if err != nil {
		return nil, err
	}

	sigCount := int(header.NumRequiredSignatures)
	sigs := make([]byte, 0, sigCount*64)
	for i := 0; i < sigCount; i++ {
		pk := accountKeys[i]
		priv, ok := signers[pk]
		if !ok {
			return nil, ErrMissingSigner
		}
		s := ed25519.Sign(priv, msg)
		sigs = append(sigs, s...)
	}

	out := make([]byte, 0, len(msg)+1+len(sigs))
	out = append(out, encodeShortVecLen(sigCount)...)
	out = append(out, sigs...)
	out = append(out, msg...)
	return out, nil
}

type accountInfo struct {
	Pubkey     Pubkey
	IsSigner   bool
	IsWritable bool
	FirstSeen  int
}

func compileLegacyMessage(
	recentBlockhash [32]byte,
	feePayer Pubkey,
	instructions []Instruction,
) ([]byte, []Pubkey, messageHeader, error) {
	infos := make(map[Pubkey]*accountInfo, 32)
	seen := 0

	touch := func(pk Pubkey, signer, writable bool) {
		if ai, ok := infos[pk]; ok {
			ai.IsSigner = ai.IsSigner || signer
			ai.IsWritable = ai.IsWritable || writable
			return
		}
		infos[pk] = &accountInfo{
			Pubkey:     pk,
			IsSigner:   signer,
			IsWritable: writable,
			FirstSeen:  seen,
		}
		seen++
	}

	// Fee payer must be a writable signer.
	touch(feePayer, true, true)

	for _, ix := range instructions {
		touch(ix.ProgramID, false, false)
		for _, am := range ix.Accounts {
			touch(am.Pubkey, am.IsSigner, am.IsWritable)
		}
	}

	signersWritable := make([]*accountInfo, 0, 8)
	signersReadonly := make([]*accountInfo, 0, 8)
	nonsignersWritable := make([]*accountInfo, 0, 16)
	nonsignersReadonly := make([]*accountInfo, 0, 16)

	for _, ai := range infos {
		if ai.IsSigner {
			if ai.IsWritable {
				signersWritable = append(signersWritable, ai)
			} else {
				signersReadonly = append(signersReadonly, ai)
			}
			continue
		}
		if ai.IsWritable {
			nonsignersWritable = append(nonsignersWritable, ai)
		} else {
			nonsignersReadonly = append(nonsignersReadonly, ai)
		}
	}

	sortByFirstSeen(signersWritable)
	sortByFirstSeen(signersReadonly)
	sortByFirstSeen(nonsignersWritable)
	sortByFirstSeen(nonsignersReadonly)

	accountKeys := make([]Pubkey, 0, len(infos))
	for _, ai := range signersWritable {
		accountKeys = append(accountKeys, ai.Pubkey)
	}
	for _, ai := range signersReadonly {
		accountKeys = append(accountKeys, ai.Pubkey)
	}
	for _, ai := range nonsignersWritable {
		accountKeys = append(accountKeys, ai.Pubkey)
	}
	for _, ai := range nonsignersReadonly {
		accountKeys = append(accountKeys, ai.Pubkey)
	}

	h := messageHeader{
		NumRequiredSignatures:       uint8(len(signersWritable) + len(signersReadonly)),
		NumReadonlySignedAccounts:   uint8(len(signersReadonly)),
		NumReadonlyUnsignedAccounts: uint8(len(nonsignersReadonly)),
	}

	indexOf := make(map[Pubkey]uint8, len(accountKeys))
	for i, pk := range accountKeys {
		indexOf[pk] = uint8(i)
	}

	out := make([]byte, 0, 512)
	out = append(out, h.NumRequiredSignatures, h.NumReadonlySignedAccounts, h.NumReadonlyUnsignedAccounts)
	out = append(out, encodeShortVecLen(len(accountKeys))...)
	for _, pk := range accountKeys {
		out = append(out, pk[:]...)
	}
	out = append(out, recentBlockhash[:]...)

	out = append(out, encodeShortVecLen(len(instructions))...)
	for _, ix := range instructions {
		pid := indexOf[ix.ProgramID]
		out = append(out, pid)
		out = append(out, encodeShortVecLen(len(ix.Accounts))...)
		for _, am := range ix.Accounts {
			out = append(out, indexOf[am.Pubkey])
		}
		out = append(out, encodeShortVecLen(len(ix.Data))...)
		out = append(out, ix.Data...)
	}

	return out, accountKeys, h, nil
}

func sortByFirstSeen(infos []*accountInfo) {
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[j].FirstSeen < infos[i].FirstSeen {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
}

