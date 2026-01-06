package protocol

import (
	"encoding/hex"
	"testing"
)

func TestVectorsV1_Golden(t *testing.T) {
	var crpProgramID SolanaPubkey
	for i := 0; i < 32; i++ {
		crpProgramID[i] = byte(i + 1)
	}

	var iepProgramID SolanaPubkey
	for i := 0; i < 32; i++ {
		iepProgramID[i] = byte(i + 33)
	}

	var junocashGenesisHash JunoBlockHash
	for i := 0; i < 32; i++ {
		junocashGenesisHash[i] = byte(0xA0 + i)
	}

	deploymentID := DeriveDeploymentID(crpProgramID, iepProgramID, junocashGenesisHash)

	obs := CheckpointObservation{
		Height:      1_234_567_890,
		BlockHash:   JunoBlockHash(repeatByte32(0x11)),
		OrchardRoot: OrchardRoot(repeatByte32(0x22)),
		PrevHash:    JunoBlockHash(repeatByte32(0x33)),
	}

	signingBytes := obs.SigningBytes(deploymentID)
	candidateHash := obs.CandidateHash(deploymentID)

	receiverBytes := repeatByte(0x42, OrchardReceiverBytesLen)
	receiverTag, err := ReceiverTagForReceiverBytes(deploymentID, receiverBytes)
	if err != nil {
		t.Fatalf("ReceiverTagForReceiverBytes: %v", err)
	}

	cmx := Cmx(repeatByte32(0x44))
	spentReceiptID := SpentReceiptIDForCmx(deploymentID, cmx)

	inputs := ReceiptPublicInputs{
		DeploymentID: deploymentID,
		OrchardRoot:  obs.OrchardRoot,
		Cmx:          cmx,
		Amount:       12345,
		ReceiverTag:  receiverTag,
	}
	fr := inputs.FrElements()

	// Golden expectations (locks down cross-language wire formats).
	if got, want := deploymentID.Hex(), "cea310a0eef9148a5daac142954ff3c4b4a16a039cf3eb2fc4b5f69990b321e2"; got != want {
		t.Fatalf("deploymentID: got %s want %s", got, want)
	}

	if got, want := hex.EncodeToString(signingBytes), "4a554e4f5f494e54454e5453006372705f6f62736572766174696f6e000100cea310a0eef9148a5daac142954ff3c4b4a16a039cf3eb2fc4b5f69990b321e2d202964900000000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333"; got != want {
		t.Fatalf("signingBytes: got %s want %s", got, want)
	}

	if got, want := candidateHash.Hex(), "b90eae44832add72c4ca365d2f554e6751cf8fc5404e1a0fa80755cac06a1ef2"; got != want {
		t.Fatalf("candidateHash: got %s want %s", got, want)
	}

	if got, want := receiverTag.Hex(), "20c35102852f9a1b2616f109e5a4a038115815c1233683c0fb9cfe0f4a48d297"; got != want {
		t.Fatalf("receiverTag: got %s want %s", got, want)
	}

	if got, want := spentReceiptID.Hex(), "0e5d9602fb6cbee78e42a5cf33192ba6ec62c5ca68ad8eb50cec89fecac5cd4c"; got != want {
		t.Fatalf("spentReceiptID: got %s want %s", got, want)
	}

	if got, want := len(fr), 9; got != want {
		t.Fatalf("fr element count: got %d want %d", got, want)
	}

	if got, want := hex.EncodeToString(fr[0][:]), "00000000000000000000000000000000b4a16a039cf3eb2fc4b5f69990b321e2"; got != want {
		t.Fatalf("fr[0]: got %s want %s", got, want)
	}
	if got, want := hex.EncodeToString(fr[1][:]), "00000000000000000000000000000000cea310a0eef9148a5daac142954ff3c4"; got != want {
		t.Fatalf("fr[1]: got %s want %s", got, want)
	}
	if got, want := hex.EncodeToString(fr[2][:]), "0000000000000000000000000000000022222222222222222222222222222222"; got != want {
		t.Fatalf("fr[2]: got %s want %s", got, want)
	}
	if got, want := hex.EncodeToString(fr[3][:]), "0000000000000000000000000000000022222222222222222222222222222222"; got != want {
		t.Fatalf("fr[3]: got %s want %s", got, want)
	}
	if got, want := hex.EncodeToString(fr[4][:]), "0000000000000000000000000000000044444444444444444444444444444444"; got != want {
		t.Fatalf("fr[4]: got %s want %s", got, want)
	}
	if got, want := hex.EncodeToString(fr[5][:]), "0000000000000000000000000000000044444444444444444444444444444444"; got != want {
		t.Fatalf("fr[5]: got %s want %s", got, want)
	}
	if got, want := hex.EncodeToString(fr[6][:]), "0000000000000000000000000000000000000000000000000000000000003039"; got != want {
		t.Fatalf("fr[6]: got %s want %s", got, want)
	}
	if got, want := hex.EncodeToString(fr[7][:]), "00000000000000000000000000000000115815c1233683c0fb9cfe0f4a48d297"; got != want {
		t.Fatalf("fr[7]: got %s want %s", got, want)
	}
	if got, want := hex.EncodeToString(fr[8][:]), "0000000000000000000000000000000020c35102852f9a1b2616f109e5a4a038"; got != want {
		t.Fatalf("fr[8]: got %s want %s", got, want)
	}
}

func repeatByte32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
