package solana

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

type LookupTable struct {
	AccountKey Pubkey
	Addresses  []Pubkey
}

func BuildAndSignV0Transaction(
	recentBlockhash [32]byte,
	feePayer Pubkey,
	signers map[Pubkey]ed25519.PrivateKey,
	instructions []Instruction,
	lookupTables []LookupTable,
) ([]byte, error) {
	msg, accountKeys, header, err := compileV0Message(recentBlockhash, feePayer, instructions, lookupTables)
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

type lookupRef struct {
	Table int
	Index uint8
}

func compileV0Message(
	recentBlockhash [32]byte,
	feePayer Pubkey,
	instructions []Instruction,
	lookupTables []LookupTable,
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

	programIDs := make(map[Pubkey]struct{}, len(instructions))
	for _, ix := range instructions {
		programIDs[ix.ProgramID] = struct{}{}
		touch(ix.ProgramID, false, false)
		for _, am := range ix.Accounts {
			touch(am.Pubkey, am.IsSigner, am.IsWritable)
		}
	}

	lookupAccountKeys := make(map[Pubkey]struct{}, len(lookupTables))
	for _, lt := range lookupTables {
		lookupAccountKeys[lt.AccountKey] = struct{}{}
		// Lookup table account keys must be present in the static key list.
		touch(lt.AccountKey, false, false)
	}

	// Map pubkey -> (table, index).
	tableIndex := make(map[Pubkey]lookupRef, 256)
	for ti, lt := range lookupTables {
		if len(lt.Addresses) > 256 {
			return nil, nil, messageHeader{}, fmt.Errorf("lookup table %s has too many addresses: %d", lt.AccountKey.Base58(), len(lt.Addresses))
		}
		for i, pk := range lt.Addresses {
			if _, ok := tableIndex[pk]; ok {
				continue
			}
			tableIndex[pk] = lookupRef{Table: ti, Index: uint8(i)}
		}
	}

	// Select loadable (non-signer) keys that are present in a lookup table.
	selected := make(map[Pubkey]lookupRef, 64)
	for pk, ai := range infos {
		if ai.IsSigner {
			continue
		}
		if _, ok := programIDs[pk]; ok {
			continue
		}
		if _, ok := lookupAccountKeys[pk]; ok {
			continue
		}
		if ref, ok := tableIndex[pk]; ok {
			selected[pk] = ref
		}
	}

	signersWritable := make([]*accountInfo, 0, 8)
	signersReadonly := make([]*accountInfo, 0, 8)
	nonsignersWritable := make([]*accountInfo, 0, 16)
	nonsignersReadonly := make([]*accountInfo, 0, 16)

	for _, ai := range infos {
		if _, ok := selected[ai.Pubkey]; ok {
			continue
		}
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

	staticKeys := make([]Pubkey, 0, len(infos))
	for _, ai := range signersWritable {
		staticKeys = append(staticKeys, ai.Pubkey)
	}
	for _, ai := range signersReadonly {
		staticKeys = append(staticKeys, ai.Pubkey)
	}
	for _, ai := range nonsignersWritable {
		staticKeys = append(staticKeys, ai.Pubkey)
	}
	for _, ai := range nonsignersReadonly {
		staticKeys = append(staticKeys, ai.Pubkey)
	}

	h := messageHeader{
		NumRequiredSignatures:       uint8(len(signersWritable) + len(signersReadonly)),
		NumReadonlySignedAccounts:   uint8(len(signersReadonly)),
		NumReadonlyUnsignedAccounts: uint8(len(nonsignersReadonly)),
	}

	indexOf := make(map[Pubkey]uint8, len(staticKeys)+len(selected))
	for i, pk := range staticKeys {
		if i > 0xff {
			return nil, nil, messageHeader{}, errors.New("too many static account keys")
		}
		indexOf[pk] = uint8(i)
	}

	type lookupSelection struct {
		AccountKey      Pubkey
		WritableIndexes []uint8
		ReadonlyIndexes []uint8
	}
	selections := make([]lookupSelection, len(lookupTables))
	for i, lt := range lookupTables {
		selections[i].AccountKey = lt.AccountKey
	}
	for pk, ref := range selected {
		ai := infos[pk]
		if ai == nil {
			return nil, nil, messageHeader{}, errors.New("internal: missing account info")
		}
		if ai.IsWritable {
			selections[ref.Table].WritableIndexes = append(selections[ref.Table].WritableIndexes, ref.Index)
		} else {
			selections[ref.Table].ReadonlyIndexes = append(selections[ref.Table].ReadonlyIndexes, ref.Index)
		}
	}

	lookups := make([]lookupSelection, 0, len(selections))
	loadedKeys := make([]Pubkey, 0, len(selected))
	for ti, sel := range selections {
		sel.WritableIndexes = sortUniqueUint8(sel.WritableIndexes)
		sel.ReadonlyIndexes = sortUniqueUint8(sel.ReadonlyIndexes)
		if len(sel.WritableIndexes) == 0 && len(sel.ReadonlyIndexes) == 0 {
			continue
		}
		lookups = append(lookups, sel)
		for _, ix := range sel.WritableIndexes {
			loadedKeys = append(loadedKeys, lookupTables[ti].Addresses[ix])
		}
		for _, ix := range sel.ReadonlyIndexes {
			loadedKeys = append(loadedKeys, lookupTables[ti].Addresses[ix])
		}
	}

	for i, pk := range loadedKeys {
		j := len(staticKeys) + i
		if j > 0xff {
			return nil, nil, messageHeader{}, errors.New("too many account keys (static+lookup)")
		}
		indexOf[pk] = uint8(j)
	}

	// v0 message prefix: 0x80 | version (0).
	out := make([]byte, 0, 512)
	out = append(out, 0x80)
	out = append(out, h.NumRequiredSignatures, h.NumReadonlySignedAccounts, h.NumReadonlyUnsignedAccounts)
	out = append(out, encodeShortVecLen(len(staticKeys))...)
	for _, pk := range staticKeys {
		out = append(out, pk[:]...)
	}
	out = append(out, recentBlockhash[:]...)

	out = append(out, encodeShortVecLen(len(instructions))...)
	for _, ix := range instructions {
		pid, ok := indexOf[ix.ProgramID]
		if !ok {
			return nil, nil, messageHeader{}, fmt.Errorf("program id missing from account list: %s", ix.ProgramID.Base58())
		}
		out = append(out, pid)
		out = append(out, encodeShortVecLen(len(ix.Accounts))...)
		for _, am := range ix.Accounts {
			ai, ok := indexOf[am.Pubkey]
			if !ok {
				return nil, nil, messageHeader{}, fmt.Errorf("account missing from account list: %s", am.Pubkey.Base58())
			}
			out = append(out, ai)
		}
		out = append(out, encodeShortVecLen(len(ix.Data))...)
		out = append(out, ix.Data...)
	}

	out = append(out, encodeShortVecLen(len(lookups))...)
	for _, sel := range lookups {
		out = append(out, sel.AccountKey[:]...)
		out = append(out, encodeShortVecLen(len(sel.WritableIndexes))...)
		out = append(out, sel.WritableIndexes...)
		out = append(out, encodeShortVecLen(len(sel.ReadonlyIndexes))...)
		out = append(out, sel.ReadonlyIndexes...)
	}

	return out, staticKeys, h, nil
}

func sortUniqueUint8(in []uint8) []uint8 {
	if len(in) == 0 {
		return nil
	}
	out := append([]uint8{}, in...)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	n := 0
	for i := 0; i < len(out); i++ {
		if i > 0 && out[i] == out[i-1] {
			continue
		}
		out[n] = out[i]
		n++
	}
	return out[:n]
}
