package receipt

import (
	"crypto/sha256"
	"testing"

	"github.com/Abdullah1738/juno-intents/protocol"
)

func TestReceiptZKVMProofBundleV1_BinaryRoundTrip(t *testing.T) {
	var imageID [32]byte
	for i := range imageID {
		imageID[i] = byte(0xA0 + i)
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
	journalBytes := pub.ReceiptJournalBytesV1()

	var journal [protocol.ReceiptJournalBytesLenV1]byte
	copy(journal[:], journalBytes)

	seal := make([]byte, 257)
	for i := range seal {
		seal[i] = byte(i)
	}

	b := ReceiptZKVMProofBundleV1{
		Version:     ReceiptZKVMProofBundleVersionV1,
		ProofSystem: ZKVMProofSystemRisc0Groth16,
		ImageID:     imageID,
		Journal:     journal,
		Seal:        seal,
	}

	enc, err := b.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary error: %v", err)
	}

	var got ReceiptZKVMProofBundleV1
	if err := got.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary error: %v", err)
	}

	if got.Version != b.Version {
		t.Fatalf("version mismatch: got %d want %d", got.Version, b.Version)
	}
	if got.ProofSystem != b.ProofSystem {
		t.Fatalf("proof system mismatch: got %d want %d", got.ProofSystem, b.ProofSystem)
	}
	if got.ImageID != b.ImageID {
		t.Fatalf("image id mismatch")
	}
	if got.Journal != b.Journal {
		t.Fatalf("journal mismatch")
	}
	if len(got.Seal) != len(b.Seal) {
		t.Fatalf("seal len mismatch: got %d want %d", len(got.Seal), len(b.Seal))
	}
	for i := range got.Seal {
		if got.Seal[i] != b.Seal[i] {
			t.Fatalf("seal byte %d mismatch", i)
		}
	}
}

func TestReceiptZKVMProofBundleV1_UnmarshalBinary_InvalidLen(t *testing.T) {
	var b ReceiptZKVMProofBundleV1
	if err := b.UnmarshalBinary([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestReceiptZKVMProofBundleV1_MarshalBinary_GoldenSHA256(t *testing.T) {
	var imageID [32]byte
	for i := range imageID {
		imageID[i] = byte(0xA0 + i)
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
	journalBytes := pub.ReceiptJournalBytesV1()

	var journal [protocol.ReceiptJournalBytesLenV1]byte
	copy(journal[:], journalBytes)

	seal := make([]byte, 257)
	for i := range seal {
		seal[i] = byte(i)
	}

	b := ReceiptZKVMProofBundleV1{
		Version:     ReceiptZKVMProofBundleVersionV1,
		ProofSystem: ZKVMProofSystemRisc0Groth16,
		ImageID:     imageID,
		Journal:     journal,
		Seal:        seal,
	}

	enc, err := b.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary error: %v", err)
	}

	got := sha256.Sum256(enc)
	want := [32]byte{
		0x7a, 0xc0, 0x42, 0x66, 0x1c, 0x54, 0xbb, 0x82,
		0x69, 0x54, 0x15, 0x9e, 0x16, 0x60, 0xca, 0x67,
		0xde, 0x7e, 0x2e, 0x92, 0x82, 0xdd, 0x10, 0x6e,
		0xd7, 0x93, 0x1d, 0x33, 0xf6, 0x52, 0xe4, 0x09,
	}
	if got != want {
		t.Fatalf("sha256 mismatch: got %x want %x", got, want)
	}
}
