package solanafees

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abdullah1738/juno-intents/offchain/helius"
)

func TestPriorityFeeLamports(t *testing.T) {
	t.Parallel()

	got, err := PriorityFeeLamports(200_000, 1_000_000)
	if err != nil {
		t.Fatalf("PriorityFeeLamports: %v", err)
	}
	if got != 200_000 {
		t.Fatalf("got=%d want=200000", got)
	}

	got, err = PriorityFeeLamports(1, 1)
	if err != nil {
		t.Fatalf("PriorityFeeLamports: %v", err)
	}
	if got != 1 {
		t.Fatalf("got=%d want=1", got)
	}

	if _, err := PriorityFeeLamports(^uint32(0), ^uint64(0)); err == nil {
		t.Fatalf("expected overflow")
	}
}

func TestEstimateFromHeliusByAccountKeys(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "getFees":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"feeCalculator":{"lamportsPerSignature":5000}}}`))
		case "getPriorityFeeEstimate":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"priorityFeeEstimate":1000000}}`))
		default:
			t.Fatalf("unexpected method: %q", req.Method)
		}
	}))
	t.Cleanup(srv.Close)

	c := helius.NewClient(srv.URL, srv.Client())
	est, err := EstimateFromHeliusByAccountKeys(
		context.Background(),
		c,
		[]string{"11111111111111111111111111111111"},
		200_000,
		1,
		&helius.PriorityFeeOptions{PriorityLevel: helius.PriorityMedium, Recommended: true},
	)
	if err != nil {
		t.Fatalf("EstimateFromHeliusByAccountKeys: %v", err)
	}
	if est.BaseFeeLamports != 5000 {
		t.Fatalf("base fee mismatch: got=%d want=5000", est.BaseFeeLamports)
	}
	if est.PriorityFeeLamports != 200_000 {
		t.Fatalf("priority fee mismatch: got=%d want=200000", est.PriorityFeeLamports)
	}
	if est.TotalLamports != 205_000 {
		t.Fatalf("total fee mismatch: got=%d want=205000", est.TotalLamports)
	}
}

