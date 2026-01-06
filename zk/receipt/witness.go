package receipt

import (
	"errors"

	"github.com/Abdullah1738/juno-intents/protocol"
)

const (
	ReceiptWitnessVersionV1 uint16 = 1

	// OrchardMerkleDepth is the fixed depth of the Orchard note commitment tree.
	OrchardMerkleDepth = 32
)

var (
	ErrUnsupportedWitnessVersion = errors.New("unsupported witness version")
)

// OrchardNoteOpeningV1 contains the private note opening needed to recompute cmx
// inside the circuit.
//
// The circuit must enforce that these bytes correspond to the paid recipient
// and that the resulting commitment equals the public input cmx.
type OrchardNoteOpeningV1 struct {
	ReceiverBytes [protocol.OrchardReceiverBytesLen]byte
	Value         protocol.Zatoshi
	Rho           [32]byte
	Rseed         [32]byte
}

type OrchardMerklePathV1 struct {
	// Index is the leaf index in the Orchard commitment tree.
	Index uint32

	// Siblings are the Merkle sibling nodes from leaf->root (depth = 32).
	Siblings [OrchardMerkleDepth][32]byte
}

// ReceiptWitnessV1 is the full private witness required to prove that a paid
// Orchard note exists under a finalized anchor and is bound to a specific fill.
//
// Public inputs are derived deterministically from this witness using
// ReceiptWitnessV1.PublicInputs().
type ReceiptWitnessV1 struct {
	Version uint16

	DeploymentID protocol.DeploymentID
	FillID       protocol.FillID

	// Anchor (public input).
	OrchardRoot protocol.OrchardRoot

	// Note commitment (public input). The circuit recomputes and enforces equality.
	Cmx protocol.Cmx

	Note OrchardNoteOpeningV1
	Path OrchardMerklePathV1
}

func (w ReceiptWitnessV1) Validate() error {
	if w.Version != ReceiptWitnessVersionV1 {
		return ErrUnsupportedWitnessVersion
	}
	return nil
}

func (w ReceiptWitnessV1) PublicInputs() (protocol.ReceiptPublicInputs, error) {
	if err := w.Validate(); err != nil {
		return protocol.ReceiptPublicInputs{}, err
	}

	receiverTag, err := protocol.ReceiverTagForReceiverBytes(
		w.DeploymentID,
		w.FillID,
		w.Note.ReceiverBytes[:],
	)
	if err != nil {
		return protocol.ReceiptPublicInputs{}, err
	}

	return protocol.ReceiptPublicInputs{
		DeploymentID: w.DeploymentID,
		OrchardRoot:  w.OrchardRoot,
		Cmx:          w.Cmx,
		Amount:       w.Note.Value,
		ReceiverTag:  receiverTag,
		FillID:       w.FillID,
	}, nil
}
