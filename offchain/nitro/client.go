package nitro

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Abdullah1738/juno-intents/internal/vsock"
)

type Request struct {
	ID     string `json:"id,omitempty"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

type Response struct {
	ID     string          `json:"id,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func Call(ctx context.Context, cid uint32, port uint32, method string, params any, result any) error {
	if method == "" {
		return errors.New("method required")
	}

	conn, err := vsock.Dial(cid, port)
	if err != nil {
		return err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	req := Request{Method: method, Params: params}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return err
	}

	rd := bufio.NewScanner(conn)
	rd.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	if !rd.Scan() {
		if err := rd.Err(); err != nil {
			return err
		}
		return errors.New("no response")
	}

	line := strings.TrimSpace(rd.Text())
	if line == "" {
		return errors.New("empty response")
	}

	var resp Response
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(resp.Result, result)
}
