package helius

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRPCURL(t *testing.T) {
	t.Parallel()

	got, err := RPCURL(ClusterMainnet, "k")
	if err != nil {
		t.Fatalf("RPCURL: %v", err)
	}
	if !strings.HasPrefix(got, "https://mainnet.helius-rpc.com") {
		t.Fatalf("unexpected mainnet url: %q", got)
	}
	if !strings.Contains(got, "api-key=k") {
		t.Fatalf("missing api-key query: %q", got)
	}

	got, err = RPCURL(ClusterDevnet, "k")
	if err != nil {
		t.Fatalf("RPCURL: %v", err)
	}
	if !strings.HasPrefix(got, "https://devnet.helius-rpc.com") {
		t.Fatalf("unexpected devnet url: %q", got)
	}

	if _, err := RPCURL(ClusterMainnet, ""); err == nil {
		t.Fatalf("expected missing key error")
	}
	if _, err := RPCURL("unknown", "k"); err == nil {
		t.Fatalf("expected unsupported cluster error")
	}
}

func TestClient_GetPriorityFeeEstimateByAccountKeys(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getPriorityFeeEstimate" {
			t.Fatalf("unexpected method: %q", req.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"priorityFeeEstimate":123.4,"priorityFeeLevels":{"min":1,"medium":3}}}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, srv.Client())
	got, err := c.GetPriorityFeeEstimateByAccountKeys(context.Background(), PriorityFeeEstimateByAccountKeysRequest{
		AccountKeys: []string{"11111111111111111111111111111111"},
		Options:     &PriorityFeeOptions{PriorityLevel: PriorityMedium, Recommended: true},
	})
	if err != nil {
		t.Fatalf("GetPriorityFeeEstimateByAccountKeys: %v", err)
	}
	if got.MicroLamports != 124 {
		t.Fatalf("unexpected microLamports: got=%d want=124", got.MicroLamports)
	}
	if got.Levels == nil || got.Levels.Min != 1 || got.Levels.Medium != 3 {
		t.Fatalf("unexpected levels: %#v", got.Levels)
	}
}

func TestClient_LamportsPerSignature_GetFees(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		switch req.Method {
		case "getFees":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"feeCalculator":{"lamportsPerSignature":7777}}}`))
		default:
			t.Fatalf("unexpected method: %q", req.Method)
		}
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, srv.Client())
	got, err := c.LamportsPerSignature(context.Background())
	if err != nil {
		t.Fatalf("LamportsPerSignature: %v", err)
	}
	if got != 7777 {
		t.Fatalf("unexpected lamports per signature: got=%d want=7777", got)
	}
}

func TestClient_LamportsPerSignature_FallbackGetRecentBlockhash(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		switch req.Method {
		case "getFees":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","error":{"code":-32601,"message":"method not found"}}`))
		case "getRecentBlockhash":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"value":{"feeCalculator":{"lamportsPerSignature":8888}}}}`))
		default:
			t.Fatalf("unexpected method: %q", req.Method)
		}
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, srv.Client())
	got, err := c.LamportsPerSignature(context.Background())
	if err != nil {
		t.Fatalf("LamportsPerSignature: %v", err)
	}
	if got != 8888 {
		t.Fatalf("unexpected lamports per signature: got=%d want=8888", got)
	}
}

