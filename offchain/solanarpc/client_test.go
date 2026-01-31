package solanarpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Slot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getSlot" {
			t.Fatalf("method=%q", req.Method)
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":123}`))
	}))
	defer srv.Close()

	c := New(srv.URL, nil)
	got, err := c.Slot(context.Background())
	if err != nil {
		t.Fatalf("Slot: %v", err)
	}
	if got != 123 {
		t.Fatalf("slot=%d, want 123", got)
	}
}

func TestClient_RPCErrorType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","error":{"code":403,"message":"Access forbidden"}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, nil)
	_, err := c.Slot(context.Background())
	if err == nil {
		t.Fatalf("want error")
	}
	if !errors.Is(err, ErrRPCError) {
		t.Fatalf("errors.Is(err, ErrRPCError)=false: %v", err)
	}
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("errors.As(err, *RPCError)=false: %T %v", err, err)
	}
	if rpcErr.Code != 403 {
		t.Fatalf("code=%d, want 403", rpcErr.Code)
	}
	if rpcErr.Message != "Access forbidden" {
		t.Fatalf("message=%q, want %q", rpcErr.Message, "Access forbidden")
	}
}

func TestClient_BalanceLamports(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getBalance" {
			t.Fatalf("method=%q", req.Method)
		}
		if len(req.Params) != 2 {
			t.Fatalf("params len=%d", len(req.Params))
		}
		if req.Params[0].(string) != "Pubkey111111111111111111111111111111111111" {
			t.Fatalf("pubkey=%v", req.Params[0])
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"value":123}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, nil)
	got, err := c.BalanceLamports(context.Background(), "Pubkey111111111111111111111111111111111111")
	if err != nil {
		t.Fatalf("BalanceLamports: %v", err)
	}
	if got != 123 {
		t.Fatalf("balance=%d, want 123", got)
	}
}

func TestClient_RetryOnRateLimit(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","error":{"code":-32429,"message":"rate limited"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":123}`))
	}))
	defer srv.Close()

	c := New(srv.URL, &http.Client{Timeout: 10 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := c.Slot(ctx)
	if err != nil {
		t.Fatalf("Slot: %v", err)
	}
	if got != 123 {
		t.Fatalf("slot=%d, want 123", got)
	}
	if attempts < 2 {
		t.Fatalf("attempts=%d, want >=2", attempts)
	}
}

func TestClient_RequestAirdrop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "requestAirdrop" {
			t.Fatalf("method=%q", req.Method)
		}
		if len(req.Params) != 2 {
			t.Fatalf("params len=%d", len(req.Params))
		}
		if req.Params[0].(string) != "Pubkey111111111111111111111111111111111111" {
			t.Fatalf("pubkey=%v", req.Params[0])
		}
		if req.Params[1].(float64) != float64(1_000_000_000) {
			t.Fatalf("lamports=%v", req.Params[1])
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":"sig111"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, nil)
	got, err := c.RequestAirdrop(context.Background(), "Pubkey111111111111111111111111111111111111", 1_000_000_000)
	if err != nil {
		t.Fatalf("RequestAirdrop: %v", err)
	}
	if got != "sig111" {
		t.Fatalf("sig=%q, want sig111", got)
	}
}

func TestClient_AccountDataBase64(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getAccountInfo" {
			t.Fatalf("method=%q", req.Method)
		}
		if len(req.Params) != 2 {
			t.Fatalf("params len=%d", len(req.Params))
		}
		if req.Params[0].(string) != "Pubkey111111111111111111111111111111111111" {
			t.Fatalf("pubkey=%v", req.Params[0])
		}
		cfg, ok := req.Params[1].(map[string]any)
		if !ok {
			t.Fatalf("params[1] type=%T", req.Params[1])
		}
		if cfg["encoding"] != "base64" {
			t.Fatalf("encoding=%v", cfg["encoding"])
		}
		if cfg["commitment"] != "confirmed" {
			t.Fatalf("commitment=%v", cfg["commitment"])
		}

		// "YWJj" is "abc"
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"value":{"data":["YWJj","base64"]}}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, nil)
	b, err := c.AccountDataBase64(context.Background(), "Pubkey111111111111111111111111111111111111")
	if err != nil {
		t.Fatalf("AccountDataBase64: %v", err)
	}
	if string(b) != "abc" {
		t.Fatalf("b=%q, want abc", string(b))
	}
}

func TestClient_ProgramAccountsByDataSizeBase64(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getProgramAccounts" {
			t.Fatalf("method=%q", req.Method)
		}
		if len(req.Params) != 2 {
			t.Fatalf("params len=%d", len(req.Params))
		}
		cfg, ok := req.Params[1].(map[string]any)
		if !ok {
			t.Fatalf("params[1] type=%T", req.Params[1])
		}
		if cfg["encoding"] != "base64" {
			t.Fatalf("encoding=%v", cfg["encoding"])
		}
		filters, ok := cfg["filters"].([]any)
		if !ok || len(filters) != 1 {
			t.Fatalf("filters=%T len=%d", cfg["filters"], len(filters))
		}
		filter0, ok := filters[0].(map[string]any)
		if !ok || filter0["dataSize"] == nil {
			t.Fatalf("filter0=%v", filters[0])
		}

		_, _ = w.Write([]byte(`{
  "jsonrpc":"2.0",
  "id":"1",
  "result":[
    {"pubkey":"A","account":{"data":["YWJj","base64"]}},
    {"pubkey":"B","account":{"data":["ZGVm","base64"]}}
  ]
}`))
	}))
	defer srv.Close()

	c := New(srv.URL, nil)
	out, err := c.ProgramAccountsByDataSizeBase64(context.Background(), "Program1111111111111111111111111111111111", 1101)
	if err != nil {
		t.Fatalf("ProgramAccountsByDataSizeBase64: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len=%d", len(out))
	}
	if out[0].Pubkey != "A" || string(out[0].Data) != "abc" {
		t.Fatalf("out[0]=%+v", out[0])
	}
	if out[1].Pubkey != "B" || string(out[1].Data) != "def" {
		t.Fatalf("out[1]=%+v", out[1])
	}
}

func TestClient_SignaturesForAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getSignaturesForAddress" {
			t.Fatalf("method=%q", req.Method)
		}
		if len(req.Params) != 2 {
			t.Fatalf("params len=%d", len(req.Params))
		}
		cfg, ok := req.Params[1].(map[string]any)
		if !ok {
			t.Fatalf("params[1] type=%T", req.Params[1])
		}
		if cfg["limit"] != float64(3) {
			t.Fatalf("limit=%v", cfg["limit"])
		}
		if cfg["commitment"] != "confirmed" {
			t.Fatalf("commitment=%v", cfg["commitment"])
		}

		_, _ = w.Write([]byte(`{
  "jsonrpc":"2.0",
  "id":"1",
  "result":[
    {"signature":"sigA","slot":111,"err":null},
    {"signature":"sigB","slot":222,"err":{"InstructionError":[0,"Custom"]}}
  ]
}`))
	}))
	defer srv.Close()

	c := New(srv.URL, nil)
	out, err := c.SignaturesForAddress(context.Background(), "Addr11111111111111111111111111111111111111111", 3)
	if err != nil {
		t.Fatalf("SignaturesForAddress: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len=%d", len(out))
	}
	if out[0].Signature != "sigA" || out[0].Slot != 111 || out[0].Err != nil {
		t.Fatalf("out[0]=%+v", out[0])
	}
	if out[1].Signature != "sigB" || out[1].Slot != 222 || out[1].Err == nil {
		t.Fatalf("out[1]=%+v", out[1])
	}
}

func TestClient_TransactionBytesBase64(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "getTransaction" {
			t.Fatalf("method=%q", req.Method)
		}
		if len(req.Params) != 2 {
			t.Fatalf("params len=%d", len(req.Params))
		}
		cfg, ok := req.Params[1].(map[string]any)
		if !ok {
			t.Fatalf("params[1] type=%T", req.Params[1])
		}
		if cfg["encoding"] != "base64" {
			t.Fatalf("encoding=%v", cfg["encoding"])
		}
		if cfg["commitment"] != "confirmed" {
			t.Fatalf("commitment=%v", cfg["commitment"])
		}
		if cfg["maxSupportedTransactionVersion"] != float64(0) {
			t.Fatalf("maxSupportedTransactionVersion=%v", cfg["maxSupportedTransactionVersion"])
		}

		// "aGVsbG8=" is "hello"
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":{"transaction":["aGVsbG8=","base64"]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, nil)
	b, err := c.TransactionBytesBase64(context.Background(), "sig")
	if err != nil {
		t.Fatalf("TransactionBytesBase64: %v", err)
	}
	if string(b) != "hello" {
		t.Fatalf("b=%q", string(b))
	}
}
