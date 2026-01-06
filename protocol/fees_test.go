package protocol

import "testing"

func TestProtocolFeeForNetAmount(t *testing.T) {
	type testCase struct {
		name      string
		netAmount uint64
		bps       FeeBps
		wantFee   uint64
		wantErr   bool
	}

	cases := []testCase{
		{name: "zero", netAmount: 0, bps: 0, wantFee: 0},
		{name: "zero_bps", netAmount: 123, bps: 0, wantFee: 0},
		{name: "one_bps_small", netAmount: 100, bps: 1, wantFee: 0},
		{name: "one_bps_rounding", netAmount: 10_000, bps: 1, wantFee: 1},
		{name: "one_percent", netAmount: 1_000_000, bps: 100, wantFee: 10_000},
		{name: "ten_percent", netAmount: 1_000_000, bps: 1000, wantFee: 100_000},
		{name: "full_fee", netAmount: 777, bps: 10_000, wantFee: 777},
		{name: "max_uint64_safe", netAmount: ^uint64(0), bps: 1, wantFee: 1844674407370955},
		{name: "invalid_bps", netAmount: 1, bps: 10_001, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ProtocolFeeForNetAmount(tc.netAmount, tc.bps)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantFee {
				t.Fatalf("fee: got %d want %d", got, tc.wantFee)
			}
		})
	}
}

func TestGrossForNetAmount(t *testing.T) {
	gross, fee, err := GrossForNetAmount(1_000_000, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fee != 10_000 {
		t.Fatalf("fee: got %d want %d", fee, 10_000)
	}
	if gross != 1_010_000 {
		t.Fatalf("gross: got %d want %d", gross, 1_010_000)
	}
}
