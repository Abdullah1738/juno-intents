package solanarpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Abdullah1738/juno-intents/offchain/helius"
	"github.com/Abdullah1738/juno-intents/offchain/solana"
)

var (
	ErrMissingRPCURL = errors.New("missing rpc url")
	ErrRPCError      = errors.New("solana rpc error")
)

type Client struct {
	rpcURL string
	http   *http.Client
}

func New(rpcURL string, httpClient *http.Client) *Client {
	rpcURL = strings.TrimSpace(rpcURL)
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		rpcURL: rpcURL,
		http:   httpClient,
	}
}

func ClientFromEnv() (*Client, error) {
	if raw := strings.TrimSpace(os.Getenv("SOLANA_RPC_URL")); raw != "" {
		return New(raw, nil), nil
	}
	if raw := strings.TrimSpace(os.Getenv("HELIUS_RPC_URL")); raw != "" {
		return New(raw, nil), nil
	}
	apiKey := strings.TrimSpace(os.Getenv("HELIUS_API_KEY"))
	cluster := helius.Cluster(strings.TrimSpace(os.Getenv("HELIUS_CLUSTER")))
	if cluster == "" {
		cluster = helius.ClusterMainnet
	}
	if apiKey == "" {
		return nil, ErrMissingRPCURL
	}
	u, err := helius.RPCURL(cluster, apiKey)
	if err != nil {
		return nil, err
	}
	return New(u, nil), nil
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func (c *Client) rpcCall(ctx context.Context, method string, params any, out any) error {
	if c == nil {
		return errors.New("nil rpc client")
	}
	if strings.TrimSpace(c.rpcURL) == "" {
		return ErrMissingRPCURL
	}

	reqBody, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      "1",
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.rpcURL, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}

	var rr rpcResponse
	if err := json.Unmarshal(raw, &rr); err != nil {
		return fmt.Errorf("decode rpc response: %w", err)
	}
	if rr.Error != nil {
		return fmt.Errorf("%w: %d %s", ErrRPCError, rr.Error.Code, rr.Error.Message)
	}
	if out == nil {
		return nil
	}
	if len(rr.Result) == 0 {
		return fmt.Errorf("%w: empty result", ErrRPCError)
	}
	if err := json.Unmarshal(rr.Result, out); err != nil {
		return fmt.Errorf("decode result: %w", err)
	}
	return nil
}

func (c *Client) LatestBlockhash(ctx context.Context) ([32]byte, error) {
	var out [32]byte
	var resp struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := c.rpcCall(ctx, "getLatestBlockhash", []any{map[string]any{"commitment": "processed"}}, &resp); err != nil {
		// Some RPCs still require getRecentBlockhash.
		var old struct {
			Value struct {
				Blockhash string `json:"blockhash"`
			} `json:"value"`
		}
		if err2 := c.rpcCall(ctx, "getRecentBlockhash", []any{}, &old); err2 != nil {
			return out, err
		}
		resp.Value.Blockhash = old.Value.Blockhash
	}

	bh, err := solana.ParsePubkey(resp.Value.Blockhash)
	if err != nil {
		return out, fmt.Errorf("invalid blockhash: %w", err)
	}
	copy(out[:], bh[:])
	return out, nil
}

func (c *Client) SendTransaction(ctx context.Context, tx []byte, skipPreflight bool) (string, error) {
	if len(tx) == 0 {
		return "", errors.New("empty tx")
	}
	b64 := base64.StdEncoding.EncodeToString(tx)
	var resp string
	params := []any{
		b64,
		map[string]any{
			"encoding":      "base64",
			"skipPreflight": skipPreflight,
		},
	}
	if err := c.rpcCall(ctx, "sendTransaction", params, &resp); err != nil {
		return "", err
	}
	return resp, nil
}

func (c *Client) AccountDataBase64(ctx context.Context, pubkey string) ([]byte, error) {
	var resp struct {
		Value struct {
			Data []any `json:"data"`
		} `json:"value"`
	}
	if err := c.rpcCall(ctx, "getAccountInfo", []any{pubkey, map[string]any{"encoding": "base64"}}, &resp); err != nil {
		return nil, err
	}
	if len(resp.Value.Data) < 1 {
		return nil, errors.New("account not found or missing data")
	}
	s, ok := resp.Value.Data[0].(string)
	if !ok || strings.TrimSpace(s) == "" {
		return nil, errors.New("unexpected account data encoding")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}

