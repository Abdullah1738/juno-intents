package receipt

import (
	"testing"

	"github.com/Abdullah1738/juno-intents/protocol"
)

func TestReceiptWitnessV1_PublicInputs(t *testing.T) {
	var deploymentID protocol.DeploymentID
	for i := range deploymentID {
		deploymentID[i] = 0x11
	}

	var fillID protocol.FillID
	for i := range fillID {
		fillID[i] = 0x22
	}

	var orchardRoot protocol.OrchardRoot
	for i := range orchardRoot {
		orchardRoot[i] = 0x33
	}

	var cmx protocol.Cmx
	for i := range cmx {
		cmx[i] = 0x44
	}

	var receiverBytes [protocol.OrchardReceiverBytesLen]byte
	for i := range receiverBytes {
		receiverBytes[i] = 0x55
	}

	var rho [32]byte
	for i := range rho {
		rho[i] = 0x66
	}

	var rseed [32]byte
	for i := range rseed {
		rseed[i] = 0x77
	}

	w := ReceiptWitnessV1{
		Version:      ReceiptWitnessVersionV1,
		DeploymentID: deploymentID,
		FillID:       fillID,
		OrchardRoot:  orchardRoot,
		Cmx:          cmx,
		Note: OrchardNoteOpeningV1{
			ReceiverBytes: receiverBytes,
			Value:         protocol.Zatoshi(123456),
			Rho:           rho,
			Rseed:         rseed,
		},
	}

	got, err := w.PublicInputs()
	if err != nil {
		t.Fatalf("PublicInputs() error: %v", err)
	}

	wantTag, err := protocol.ReceiverTagForReceiverBytes(deploymentID, fillID, receiverBytes[:])
	if err != nil {
		t.Fatalf("ReceiverTagForReceiverBytes error: %v", err)
	}

	if got.DeploymentID != deploymentID {
		t.Fatalf("deployment_id mismatch")
	}
	if got.FillID != fillID {
		t.Fatalf("fill_id mismatch")
	}
	if got.OrchardRoot != orchardRoot {
		t.Fatalf("orchard_root mismatch")
	}
	if got.Cmx != cmx {
		t.Fatalf("cmx mismatch")
	}
	if got.Amount != w.Note.Value {
		t.Fatalf("amount mismatch")
	}
	if got.ReceiverTag != wantTag {
		t.Fatalf("receiver_tag mismatch")
	}
}
