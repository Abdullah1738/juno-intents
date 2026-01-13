package solanarpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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

