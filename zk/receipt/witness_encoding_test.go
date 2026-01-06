package receipt

import (
	"crypto/sha256"
	"testing"

	"github.com/Abdullah1738/juno-intents/protocol"
)

func TestReceiptWitnessV1_BinaryRoundTrip(t *testing.T) {
	var w ReceiptWitnessV1
	w.Version = ReceiptWitnessVersionV1
	for i := range w.DeploymentID {
		w.DeploymentID[i] = 0x01
		w.FillID[i] = 0x02
		w.OrchardRoot[i] = 0x03
		w.Cmx[i] = 0x04
	}
	for i := range w.Note.ReceiverBytes {
		w.Note.ReceiverBytes[i] = 0x05
	}
	w.Note.Value = protocol.Zatoshi(0x0102030405060708)
	for i := range w.Note.Rho {
		w.Note.Rho[i] = 0x06
		w.Note.Rseed[i] = 0x07
	}
	w.Path.Index = 0xAABBCCDD
	for i := 0; i < OrchardMerkleDepth; i++ {
		for j := 0; j < 32; j++ {
			w.Path.Siblings[i][j] = byte(0x10 + i)
		}
	}

	enc, err := w.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary error: %v", err)
	}
	if len(enc) != ReceiptWitnessBytesLenV1 {
		t.Fatalf("encoded len mismatch: got %d want %d", len(enc), ReceiptWitnessBytesLenV1)
	}

	var got ReceiptWitnessV1
	if err := got.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary error: %v", err)
	}
	if got != w {
		t.Fatalf("round trip mismatch")
	}
}

func TestReceiptWitnessV1_MarshalBinary_GoldenSHA256(t *testing.T) {
	var w ReceiptWitnessV1
	w.Version = ReceiptWitnessVersionV1
	for i := range w.DeploymentID {
		w.DeploymentID[i] = 0x01
		w.FillID[i] = 0x02
		w.OrchardRoot[i] = 0x03
		w.Cmx[i] = 0x04
	}
	for i := range w.Note.ReceiverBytes {
		w.Note.ReceiverBytes[i] = 0x05
	}
	w.Note.Value = protocol.Zatoshi(0x0102030405060708)
	for i := range w.Note.Rho {
		w.Note.Rho[i] = 0x06
		w.Note.Rseed[i] = 0x07
	}
	w.Path.Index = 0xAABBCCDD
	for i := 0; i < OrchardMerkleDepth; i++ {
		for j := 0; j < 32; j++ {
			w.Path.Siblings[i][j] = byte(0x10 + i)
		}
	}

	enc, err := w.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary error: %v", err)
	}

	got := sha256.Sum256(enc)

	want := [32]byte{
		0x14, 0xd1, 0xfb, 0x58, 0x5b, 0xb5, 0x77, 0x25,
		0xdb, 0xff, 0x49, 0xce, 0x1a, 0x93, 0xbd, 0xc4,
		0x39, 0xda, 0x76, 0xeb, 0x1f, 0xcf, 0xd3, 0xef,
		0x07, 0x6f, 0xaf, 0xf0, 0xf8, 0xc6, 0x26, 0x70,
	}
	if got != want {
		t.Fatalf("sha256 mismatch: got %x want %x", got, want)
	}
}
