package receipt

import (
	"crypto/sha256"
	"testing"

	"github.com/Abdullah1738/juno-intents/protocol"
)

func TestReceiptProofBundleV1_BinaryRoundTrip(t *testing.T) {
	var proof Groth16ProofBytesV1
	for i := 0; i < len(proof); i++ {
		proof[i] = byte(i)
	}

	var deploymentID protocol.DeploymentID
	for i := range deploymentID {
		deploymentID[i] = 0x01
	}
	var orchardRoot protocol.OrchardRoot
	for i := range orchardRoot {
		orchardRoot[i] = 0x02
	}
	var cmx protocol.Cmx
	for i := range cmx {
		cmx[i] = 0x03
	}
	var receiverTag protocol.ReceiverTag
	for i := range receiverTag {
		receiverTag[i] = 0x04
	}
	var fillID protocol.FillID
	for i := range fillID {
		fillID[i] = 0x05
	}

	pub := protocol.ReceiptPublicInputs{
		DeploymentID: deploymentID,
		OrchardRoot:  orchardRoot,
		Cmx:          cmx,
		Amount:       protocol.Zatoshi(42),
		ReceiverTag:  receiverTag,
		FillID:       fillID,
	}

	b, err := NewReceiptProofBundleV1(proof, pub)
	if err != nil {
		t.Fatalf("NewReceiptProofBundleV1 error: %v", err)
	}

	enc, err := b.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary error: %v", err)
	}
	if len(enc) != ReceiptProofBundleBytesLenV1 {
		t.Fatalf("encoded len mismatch: got %d want %d", len(enc), ReceiptProofBundleBytesLenV1)
	}

	var got ReceiptProofBundleV1
	if err := got.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary error: %v", err)
	}

	if got.Version != ReceiptProofBundleVersionV1 {
		t.Fatalf("version mismatch: got %d", got.Version)
	}
	if got.Proof != proof {
		t.Fatalf("proof mismatch")
	}

	wantFr := pub.FrElements()
	for i := 0; i < ReceiptPublicInputCountV1; i++ {
		if got.PublicInputs[i] != wantFr[i] {
			t.Fatalf("public input %d mismatch", i)
		}
	}
}

func TestReceiptProofBundleV1_UnmarshalBinary_InvalidLen(t *testing.T) {
	var b ReceiptProofBundleV1
	if err := b.UnmarshalBinary(make([]byte, ReceiptProofBundleBytesLenV1-1)); err == nil {
		t.Fatalf("expected error")
	}
}

func TestReceiptProofBundleV1_MarshalBinary_GoldenSHA256(t *testing.T) {
	var proof Groth16ProofBytesV1
	for i := 0; i < len(proof); i++ {
		proof[i] = byte(i)
	}

	var deploymentID protocol.DeploymentID
	for i := range deploymentID {
		deploymentID[i] = 0x01
	}
	var orchardRoot protocol.OrchardRoot
	for i := range orchardRoot {
		orchardRoot[i] = 0x02
	}
	var cmx protocol.Cmx
	for i := range cmx {
		cmx[i] = 0x03
	}
	var receiverTag protocol.ReceiverTag
	for i := range receiverTag {
		receiverTag[i] = 0x04
	}
	var fillID protocol.FillID
	for i := range fillID {
		fillID[i] = 0x05
	}

	pub := protocol.ReceiptPublicInputs{
		DeploymentID: deploymentID,
		OrchardRoot:  orchardRoot,
		Cmx:          cmx,
		Amount:       protocol.Zatoshi(42),
		ReceiverTag:  receiverTag,
		FillID:       fillID,
	}

	b, err := NewReceiptProofBundleV1(proof, pub)
	if err != nil {
		t.Fatalf("NewReceiptProofBundleV1 error: %v", err)
	}
	enc, err := b.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary error: %v", err)
	}

	got := sha256.Sum256(enc)
	want := [32]byte{
		0xa0, 0x05, 0x70, 0xe4, 0xeb, 0x47, 0xb5, 0x11,
		0xf6, 0xb6, 0x5a, 0xd7, 0x25, 0x53, 0xb2, 0x0f,
		0x27, 0x80, 0x21, 0x6e, 0xcf, 0x24, 0x74, 0xe8,
		0x11, 0x9d, 0x0b, 0x12, 0x6a, 0xc6, 0xc4, 0x7e,
	}
	if got != want {
		t.Fatalf("sha256 mismatch: got %x want %x", got, want)
	}
}
