package solana

import "testing"

func TestCreateProgramAddress_RejectsInvalidSeeds(t *testing.T) {
	_, err := CreateProgramAddress(make([][]byte, 17), SystemProgramID)
	if err != ErrInvalidSeeds {
		t.Fatalf("want ErrInvalidSeeds, got %v", err)
	}

	seed := make([]byte, 33)
	_, err = CreateProgramAddress([][]byte{seed}, SystemProgramID)
	if err != ErrInvalidSeeds {
		t.Fatalf("want ErrInvalidSeeds, got %v", err)
	}
}

func TestFindProgramAddress_ReturnsOffCurve(t *testing.T) {
	pda, bump, err := FindProgramAddress([][]byte{[]byte("test")}, SystemProgramID)
	if err != nil {
		t.Fatalf("FindProgramAddress: %v", err)
	}
	if bump > 255 {
		t.Fatalf("invalid bump: %d", bump)
	}
	if isOnCurve(pda) {
		t.Fatalf("expected off-curve PDA")
	}
}

