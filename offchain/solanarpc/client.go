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

type RPCError struct {
	Code    int
	Message string
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("%s: %d %s", ErrRPCError.Error(), e.Code, e.Message)
}

func (e *RPCError) Unwrap() error { return ErrRPCError }

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

func isRateLimitedRPCError(code int, message string) bool {
	if code == 429 || code == -32429 {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(message))
	return strings.Contains(msg, "rate") && strings.Contains(msg, "limit")
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
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

	backoff := 1 * time.Second
	maxBackoff := 10 * time.Second
	maxAttempts := 7

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.rpcURL, bytes.NewReader(reqBody))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return readErr
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("%w: http status=%d", ErrRPCError, resp.StatusCode)
			if attempt < maxAttempts {
				if err := sleepWithContext(ctx, backoff); err != nil {
					return err
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			return lastErr
		}

		var rr rpcResponse
		if err := json.Unmarshal(raw, &rr); err != nil {
			lastErr = fmt.Errorf("decode rpc response: %w", err)
			if attempt < maxAttempts {
				if err := sleepWithContext(ctx, backoff); err != nil {
					return err
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			return lastErr
		}
		if rr.Error != nil {
			lastErr = &RPCError{Code: rr.Error.Code, Message: rr.Error.Message}
			if isRateLimitedRPCError(rr.Error.Code, rr.Error.Message) && attempt < maxAttempts {
				if err := sleepWithContext(ctx, backoff); err != nil {
					return err
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			return lastErr
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
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("%w: no response", ErrRPCError)
}

func (c *Client) LatestBlockhash(ctx context.Context) ([32]byte, error) {
	var out [32]byte
	var resp struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	// Use finalized to avoid "Blockhash not found" when talking to load-balanced public RPCs.
	if err := c.rpcCall(ctx, "getLatestBlockhash", []any{map[string]any{"commitment": "finalized"}}, &resp); err != nil {
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
	params := []any{
		pubkey,
		map[string]any{
			"encoding":   "base64",
			"commitment": "confirmed",
		},
	}
	if err := c.rpcCall(ctx, "getAccountInfo", params, &resp); err != nil {
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

func (c *Client) AddressLookupTableAddresses(ctx context.Context, table solana.Pubkey) ([]solana.Pubkey, error) {
	raw, err := c.AccountDataBase64(ctx, table.Base58())
	if err != nil {
		return nil, err
	}
	addrs, err := solana.ParseAddressLookupTableAddresses(raw)
	if err != nil {
		return nil, fmt.Errorf("parse address lookup table: %w", err)
	}
	return addrs, nil
}

func (c *Client) Slot(ctx context.Context) (uint64, error) {
	var resp uint64
	if err := c.rpcCall(ctx, "getSlot", []any{map[string]any{"commitment": "processed"}}, &resp); err != nil {
		return 0, err
	}
	return resp, nil
}

func (c *Client) BalanceLamports(ctx context.Context, pubkey string) (uint64, error) {
	pubkey = strings.TrimSpace(pubkey)
	if pubkey == "" {
		return 0, errors.New("pubkey required")
	}
	var resp struct {
		Value uint64 `json:"value"`
	}
	if err := c.rpcCall(ctx, "getBalance", []any{pubkey, map[string]any{"commitment": "processed"}}, &resp); err != nil {
		return 0, err
	}
	return resp.Value, nil
}

func (c *Client) RequestAirdrop(ctx context.Context, pubkey string, lamports uint64) (string, error) {
	pubkey = strings.TrimSpace(pubkey)
	if pubkey == "" {
		return "", errors.New("pubkey required")
	}
	if lamports == 0 {
		return "", errors.New("lamports required")
	}
	var sig string
	if err := c.rpcCall(ctx, "requestAirdrop", []any{pubkey, lamports}, &sig); err != nil {
		return "", err
	}
	return sig, nil
}

type ProgramAccount struct {
	Pubkey string
	Data   []byte
}

func (c *Client) ProgramAccountsByDataSizeBase64(ctx context.Context, programID string, dataSize uint64) ([]ProgramAccount, error) {
	programID = strings.TrimSpace(programID)
	if programID == "" {
		return nil, errors.New("program id required")
	}
	if dataSize == 0 {
		return nil, errors.New("dataSize required")
	}

	type resultItem struct {
		Pubkey  string `json:"pubkey"`
		Account struct {
			Data []any `json:"data"`
		} `json:"account"`
	}

	var resp []resultItem
	params := []any{
		programID,
		map[string]any{
			"encoding": "base64",
			"filters": []any{
				map[string]any{"dataSize": dataSize},
			},
		},
	}
	if err := c.rpcCall(ctx, "getProgramAccounts", params, &resp); err != nil {
		return nil, err
	}

	out := make([]ProgramAccount, 0, len(resp))
	for _, it := range resp {
		if strings.TrimSpace(it.Pubkey) == "" {
			return nil, errors.New("missing pubkey in getProgramAccounts response")
		}
		if len(it.Account.Data) < 1 {
			return nil, errors.New("missing account data in getProgramAccounts response")
		}
		s, ok := it.Account.Data[0].(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, errors.New("unexpected account data encoding")
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, ProgramAccount{
			Pubkey: it.Pubkey,
			Data:   b,
		})
	}
	return out, nil
}

type SignatureInfo struct {
	Signature string `json:"signature"`
	Slot      uint64 `json:"slot"`
	Err       any    `json:"err"`
}

func (c *Client) SignaturesForAddress(ctx context.Context, address string, limit int) ([]SignatureInfo, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, errors.New("address required")
	}
	if limit <= 0 {
		return nil, errors.New("limit must be > 0")
	}
	if limit > 1000 {
		return nil, errors.New("limit too large")
	}

	var resp []SignatureInfo
	params := []any{
		address,
		map[string]any{
			"limit":      limit,
			"commitment": "confirmed",
		},
	}
	if err := c.rpcCall(ctx, "getSignaturesForAddress", params, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) TransactionBytesBase64(ctx context.Context, signature string) ([]byte, error) {
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return nil, errors.New("signature required")
	}

	var resp struct {
		Transaction []any `json:"transaction"`
	}
	params := []any{
		signature,
		map[string]any{
			"encoding":                       "base64",
			"commitment":                     "confirmed",
			"maxSupportedTransactionVersion": 0,
		},
	}
	if err := c.rpcCall(ctx, "getTransaction", params, &resp); err != nil {
		return nil, err
	}
	if len(resp.Transaction) < 1 {
		return nil, errors.New("missing transaction in getTransaction response")
	}
	b64, ok := resp.Transaction[0].(string)
	if !ok || strings.TrimSpace(b64) == "" {
		return nil, errors.New("unexpected getTransaction encoding")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return raw, nil
}
