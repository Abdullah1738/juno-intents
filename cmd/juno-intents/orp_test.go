package main

import (
	"encoding/binary"
	"testing"

	"github.com/Abdullah1738/juno-intents/offchain/solana"
)

func TestAttestationInfoFromBundleV1(t *testing.T) {
	var (
		imageID     [32]byte
		deployment  [32]byte
		genesisHash [32]byte
		operatorPK  solana.Pubkey
		measurement [32]byte
	)
	for i := range imageID {
		imageID[i] = 0xAA
		deployment[i] = 0x01
		genesisHash[i] = 0x02
		operatorPK[i] = 0x03
		measurement[i] = 0x04
	}
	chainID := uint8(2)

	// journal: version_u16_le || deployment_id_32 || chain_id_u8 || genesis_hash_32 || operator_pubkey_32 || measurement_32
	journal := make([]byte, 0, 131)
	journal = append(journal, 1, 0)
	journal = append(journal, deployment[:]...)
	journal = append(journal, chainID)
	journal = append(journal, genesisHash[:]...)
	journal = append(journal, operatorPK[:]...)
	journal = append(journal, measurement[:]...)
	if len(journal) != 131 {
		t.Fatalf("journal len: got %d want %d", len(journal), 131)
	}

	// bundle: version_u16_le || proof_system_u8 || image_id_32 || journal_len_u16_le || journal || seal_len_u32_le || seal_260
	bundle := make([]byte, 0, 2+1+32+2+len(journal)+4+260)
	bundle = append(bundle, 1, 0)
	bundle = append(bundle, 1)
	bundle = append(bundle, imageID[:]...)
	var tmp2 [2]byte
	binary.LittleEndian.PutUint16(tmp2[:], uint16(len(journal)))
	bundle = append(bundle, tmp2[:]...)
	bundle = append(bundle, journal...)
	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], 260)
	bundle = append(bundle, tmp4[:]...)
	bundle = append(bundle, make([]byte, 260)...)

	info, err := attestationInfoFromBundleV1(bundle)
	if err != nil {
		t.Fatalf("attestationInfoFromBundleV1: %v", err)
	}
	if info.ImageID != imageID {
		t.Fatalf("image id mismatch")
	}
	if info.DeploymentID != deployment {
		t.Fatalf("deployment id mismatch")
	}
	if info.JunocashChainID != chainID {
		t.Fatalf("chain id mismatch: got %d want %d", info.JunocashChainID, chainID)
	}
	if info.JunocashGenesisHash != genesisHash {
		t.Fatalf("genesis hash mismatch")
	}
	if info.OperatorPubkey != operatorPK {
		t.Fatalf("operator pubkey mismatch")
	}
	if info.Measurement != measurement {
		t.Fatalf("measurement mismatch")
	}

	pkOnly, err := operatorPubkeyFromAttestationBundleV1(bundle)
	if err != nil {
		t.Fatalf("operatorPubkeyFromAttestationBundleV1: %v", err)
	}
	var wantPK [32]byte
	copy(wantPK[:], operatorPK[:])
	if pkOnly != wantPK {
		t.Fatalf("operatorPubkeyFromAttestationBundleV1 mismatch")
	}
}

