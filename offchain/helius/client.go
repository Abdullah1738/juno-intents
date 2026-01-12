package helius

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	ErrMissingAPIKey = errors.New("missing helius api key")
	ErrRPCError      = errors.New("helius rpc error")
)

type Cluster string

const (
	ClusterMainnet Cluster = "mainnet"
	ClusterDevnet  Cluster = "devnet"
)

func RPCURL(cluster Cluster, apiKey string) (string, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return "", ErrMissingAPIKey
	}

	var host string
	switch cluster {
	case ClusterMainnet, "mainnet-beta":
		host = "https://mainnet.helius-rpc.com"
	case ClusterDevnet:
		host = "https://devnet.helius-rpc.com"
	default:
		return "", fmt.Errorf("unsupported helius cluster: %q", cluster)
	}

	u, err := url.Parse(host)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("api-key", apiKey)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func ClientFromEnv() (*Client, error) {
	if raw := strings.TrimSpace(os.Getenv("HELIUS_RPC_URL")); raw != "" {
		return NewClient(raw, nil), nil
	}

	apiKey := os.Getenv("HELIUS_API_KEY")
	cluster := Cluster(strings.TrimSpace(os.Getenv("HELIUS_CLUSTER")))
	if cluster == "" {
		cluster = ClusterMainnet
	}

	rpcURL, err := RPCURL(cluster, apiKey)
	if err != nil {
		return nil, err
	}
	return NewClient(rpcURL, nil), nil
}

type Client struct {
	rpcURL string
	http   *http.Client
}

func NewClient(rpcURL string, httpClient *http.Client) *Client {
	rpcURL = strings.TrimSpace(rpcURL)
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		rpcURL: rpcURL,
		http:   httpClient,
	}
}

type PriorityLevel string

const (
	PriorityMin       PriorityLevel = "Min"
	PriorityLow       PriorityLevel = "Low"
	PriorityMedium    PriorityLevel = "Medium"
	PriorityHigh      PriorityLevel = "High"
	PriorityVeryHigh  PriorityLevel = "VeryHigh"
	PriorityUnsafeMax PriorityLevel = "UnsafeMax"
)

type TransactionEncoding string

const (
	TxEncodingBase58 TransactionEncoding = "Base58"
	TxEncodingBase64 TransactionEncoding = "Base64"
)

type PriorityFeeOptions struct {
	TransactionEncoding          TransactionEncoding `json:"transactionEncoding,omitempty"`
	PriorityLevel                PriorityLevel       `json:"priorityLevel,omitempty"`
	IncludeAllPriorityFeeLevels  bool                `json:"includeAllPriorityFeeLevels,omitempty"`
	LookbackSlots                int                 `json:"lookbackSlots,omitempty"`
	IncludeVote                  bool                `json:"includeVote,omitempty"`
	Recommended                  bool                `json:"recommended,omitempty"`
	EvaluateEmptySlotAsZero      bool                `json:"evaluateEmptySlotAsZero,omitempty"`
}

type PriorityFeeLevels struct {
	Min       float64 `json:"min,omitempty"`
	Low       float64 `json:"low,omitempty"`
	Medium    float64 `json:"medium,omitempty"`
	High      float64 `json:"high,omitempty"`
	VeryHigh  float64 `json:"veryHigh,omitempty"`
	UnsafeMax float64 `json:"unsafeMax,omitempty"`
}

type PriorityFeeEstimate struct {
	// MicroLamports is the compute-unit price to set via ComputeBudgetProgram.setComputeUnitPrice.
	MicroLamports uint64
	Levels        *PriorityFeeLevels
}

type PriorityFeeEstimateByAccountKeysRequest struct {
	AccountKeys []string
	Options     *PriorityFeeOptions
}

type PriorityFeeEstimateByTransactionRequest struct {
	Transaction string
	Options     *PriorityFeeOptions
}

func (c *Client) GetPriorityFeeEstimateByAccountKeys(
	ctx context.Context,
	req PriorityFeeEstimateByAccountKeysRequest,
) (PriorityFeeEstimate, error) {
	if len(req.AccountKeys) == 0 {
		return PriorityFeeEstimate{}, fmt.Errorf("accountKeys required")
	}

	params := map[string]any{
		"accountKeys": req.AccountKeys,
	}
	if req.Options != nil {
		params["options"] = req.Options
	}

	var out struct {
		PriorityFeeEstimate float64          `json:"priorityFeeEstimate"`
		PriorityFeeLevels   *PriorityFeeLevels `json:"priorityFeeLevels,omitempty"`
	}
	if err := c.rpcCall(ctx, "getPriorityFeeEstimate", []any{params}, &out); err != nil {
		return PriorityFeeEstimate{}, err
	}

	return PriorityFeeEstimate{
		MicroLamports: ceilUint64(out.PriorityFeeEstimate),
		Levels:        out.PriorityFeeLevels,
	}, nil
}

func (c *Client) GetPriorityFeeEstimateByTransaction(
	ctx context.Context,
	req PriorityFeeEstimateByTransactionRequest,
) (PriorityFeeEstimate, error) {
	if strings.TrimSpace(req.Transaction) == "" {
		return PriorityFeeEstimate{}, fmt.Errorf("transaction required")
	}

	params := map[string]any{
		"transaction": strings.TrimSpace(req.Transaction),
	}
	if req.Options != nil {
		params["options"] = req.Options
	}

	var out struct {
		PriorityFeeEstimate float64            `json:"priorityFeeEstimate"`
		PriorityFeeLevels   *PriorityFeeLevels `json:"priorityFeeLevels,omitempty"`
	}
	if err := c.rpcCall(ctx, "getPriorityFeeEstimate", []any{params}, &out); err != nil {
		return PriorityFeeEstimate{}, err
	}

	return PriorityFeeEstimate{
		MicroLamports: ceilUint64(out.PriorityFeeEstimate),
		Levels:        out.PriorityFeeLevels,
	}, nil
}

// LamportsPerSignature tries to fetch the current signature fee via JSON-RPC.
// If the RPC method is unavailable, it falls back to the standard 5000 lamports.
func (c *Client) LamportsPerSignature(ctx context.Context) (uint64, error) {
	type feeCalc struct {
		LamportsPerSignature uint64 `json:"lamportsPerSignature"`
	}
	type feeResult struct {
		FeeCalculator feeCalc `json:"feeCalculator"`
	}
	type wrappedFeeResult struct {
		Value feeResult `json:"value"`
	}

	var out1 feeResult
	if err := c.rpcCall(ctx, "getFees", []any{}, &out1); err == nil && out1.FeeCalculator.LamportsPerSignature != 0 {
		return out1.FeeCalculator.LamportsPerSignature, nil
	}

	var out2 wrappedFeeResult
	if err := c.rpcCall(ctx, "getRecentBlockhash", []any{}, &out2); err == nil && out2.Value.FeeCalculator.LamportsPerSignature != 0 {
		return out2.Value.FeeCalculator.LamportsPerSignature, nil
	}

	return 5000, nil
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
		return errors.New("nil helius client")
	}
	if strings.TrimSpace(c.rpcURL) == "" {
		return errors.New("empty helius rpc url")
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

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.rpcURL, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("helius rpc http %d", resp.StatusCode)
	}

	var decoded rpcResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return err
	}
	if decoded.Error != nil {
		return fmt.Errorf("%w: code=%d message=%s", ErrRPCError, decoded.Error.Code, decoded.Error.Message)
	}
	if out == nil {
		return nil
	}
	if len(decoded.Result) == 0 {
		return errors.New("missing result")
	}
	return json.Unmarshal(decoded.Result, out)
}

func ceilUint64(v float64) uint64 {
	if v <= 0 {
		return 0
	}
	if v >= float64(^uint64(0)) {
		return ^uint64(0)
	}
	return uint64(math.Ceil(v))
}

