package protocol

import (
	"crypto/sha256"
	"testing"
)

func TestReceiptJournalV1_RoundTrip(t *testing.T) {
	var deploymentID DeploymentID
	for i := range deploymentID {
		deploymentID[i] = 0x01
	}
	var orchardRoot OrchardRoot
	for i := range orchardRoot {
		orchardRoot[i] = 0x02
	}
	var cmx Cmx
	for i := range cmx {
		cmx[i] = 0x03
	}
	var receiverTag ReceiverTag
	for i := range receiverTag {
		receiverTag[i] = 0x04
	}
	var fillID FillID
	for i := range fillID {
		fillID[i] = 0x05
	}

	in := ReceiptPublicInputs{
		DeploymentID: deploymentID,
		OrchardRoot:  orchardRoot,
		Cmx:          cmx,
		Amount:       Zatoshi(0x0102030405060708),
		ReceiverTag:  receiverTag,
		FillID:       fillID,
	}

	b := in.ReceiptJournalBytesV1()
	if len(b) != ReceiptJournalBytesLenV1 {
		t.Fatalf("len mismatch: got %d want %d", len(b), ReceiptJournalBytesLenV1)
	}

	got, err := ParseReceiptJournalV1(b)
	if err != nil {
		t.Fatalf("ParseReceiptJournalV1 error: %v", err)
	}
	if got != in {
		t.Fatalf("round trip mismatch")
	}
}

func TestReceiptJournalV1_GoldenSHA256(t *testing.T) {
	var deploymentID DeploymentID
	for i := range deploymentID {
		deploymentID[i] = 0x01
	}
	var orchardRoot OrchardRoot
	for i := range orchardRoot {
		orchardRoot[i] = 0x02
	}
	var cmx Cmx
	for i := range cmx {
		cmx[i] = 0x03
	}
	var receiverTag ReceiverTag
	for i := range receiverTag {
		receiverTag[i] = 0x04
	}
	var fillID FillID
	for i := range fillID {
		fillID[i] = 0x05
	}

	in := ReceiptPublicInputs{
		DeploymentID: deploymentID,
		OrchardRoot:  orchardRoot,
		Cmx:          cmx,
		Amount:       Zatoshi(0x0102030405060708),
		ReceiverTag:  receiverTag,
		FillID:       fillID,
	}

	sum := sha256.Sum256(in.ReceiptJournalBytesV1())
	want := [32]byte{
		0x90, 0x35, 0xc5, 0xc8, 0xd4, 0x39, 0x18, 0x9d,
		0xcf, 0x53, 0xdd, 0xd5, 0x98, 0x03, 0x33, 0x93,
		0x7b, 0x80, 0x45, 0x89, 0x3e, 0x2a, 0x51, 0x69,
		0xa1, 0x5f, 0x19, 0x1d, 0xd8, 0x10, 0x30, 0xe0,
	}
	if sum != want {
		t.Fatalf("sha256 mismatch: got %x want %x", sum, want)
	}
}
