package solana

import "testing"

func TestEncodeShortVecLen_Golden(t *testing.T) {
	tests := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{129, []byte{0x81, 0x01}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x80, 0x80, 0x01}},
	}

	for _, tt := range tests {
		got := encodeShortVecLen(tt.n)
		if string(got) != string(tt.want) {
			t.Fatalf("encodeShortVecLen(%d) = %x, want %x", tt.n, got, tt.want)
		}
	}
}

func TestEncodeShortVecLen_NegativePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic")
		}
	}()
	_ = encodeShortVecLen(-1)
}

