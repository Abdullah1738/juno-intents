package receipt

import (
	"context"
	"testing"

	"github.com/Abdullah1738/juno-intents/protocol"
)

type fixedProver struct {
	proof Groth16ProofBytesV1
}

func (p fixedProver) ProveReceipt(context.Context, ReceiptWitnessV1) (Groth16ProofBytesV1, error) {
	return p.proof, nil
}

func TestProveReceiptBundleV1(t *testing.T) {
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

	var proof Groth16ProofBytesV1
	for i := 0; i < len(proof); i++ {
		proof[i] = byte(0xA0 + i)
	}

	witness := ReceiptWitnessV1{
		Version:      ReceiptWitnessVersionV1,
		DeploymentID: deploymentID,
		FillID:       fillID,
		OrchardRoot:  orchardRoot,
		Cmx:          cmx,
		Note: OrchardNoteOpeningV1{
			ReceiverBytes: receiverBytes,
			Value:         protocol.Zatoshi(7),
		},
	}

	bundle, err := ProveReceiptBundleV1(context.Background(), fixedProver{proof: proof}, witness)
	if err != nil {
		t.Fatalf("ProveReceiptBundleV1 error: %v", err)
	}

	if bundle.Proof != proof {
		t.Fatalf("proof mismatch")
	}

	pub, err := witness.PublicInputs()
	if err != nil {
		t.Fatalf("PublicInputs error: %v", err)
	}
	wantFr := pub.FrElements()
	for i := 0; i < ReceiptPublicInputCountV1; i++ {
		if bundle.PublicInputs[i] != wantFr[i] {
			t.Fatalf("public input %d mismatch", i)
		}
	}
}
