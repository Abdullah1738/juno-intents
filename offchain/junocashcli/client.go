package junocashcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

var ErrCLI = errors.New("junocash cli error")

type Client struct {
	path string
	args []string
}

func New(path string, args []string) *Client {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "junocash-cli"
	}
	return &Client{
		path: path,
		args: append([]string{}, args...),
	}
}

func (c *Client) run(ctx context.Context, method string, args ...string) (string, error) {
	if c == nil {
		return "", errors.New("nil client")
	}
	method = strings.TrimSpace(method)
	if method == "" {
		return "", errors.New("empty method")
	}

	cmdArgs := make([]string, 0, len(c.args)+1+len(args))
	cmdArgs = append(cmdArgs, c.args...)
	cmdArgs = append(cmdArgs, method)
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.CommandContext(ctx, c.path, cmdArgs...)
	cmd.Stdin = nil
	cmd.Stderr = nil
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCLI, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (c *Client) BlockCount(ctx context.Context) (uint64, error) {
	raw, err := c.run(ctx, "getblockcount")
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse getblockcount: %w", err)
	}
	return n, nil
}

func (c *Client) BlockHash(ctx context.Context, height uint64) (string, error) {
	raw, err := c.run(ctx, "getblockhash", strconv.FormatUint(height, 10))
	if err != nil {
		return "", err
	}
	raw = strings.Trim(raw, "\"")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty block hash")
	}
	return raw, nil
}

type Block struct {
	Hash              string `json:"hash"`
	Height            uint64 `json:"height"`
	PreviousBlockHash string `json:"previousblockhash"`
	FinalOrchardRoot  string `json:"finalorchardroot"`
}

func ParseBlockJSON(r io.Reader) (Block, error) {
	var b Block
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Block{}, err
	}
	return b, nil
}

func (c *Client) Block(ctx context.Context, blockHash string) (Block, error) {
	blockHash = strings.TrimSpace(strings.Trim(blockHash, "\""))
	if blockHash == "" {
		return Block{}, errors.New("empty block hash")
	}

	raw, err := c.run(ctx, "getblock", blockHash, "1")
	if err != nil {
		return Block{}, err
	}

	b, err := ParseBlockJSON(strings.NewReader(raw))
	if err != nil {
		return Block{}, fmt.Errorf("parse getblock: %w", err)
	}
	return b, nil
}

