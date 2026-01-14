package nitro

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
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

	conn, err := dialVsock(cid, port)
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

func dialVsock(cid uint32, port uint32) (net.Conn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd != -1 {
			_ = unix.Close(fd)
		}
	}()

	if err := unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), "vsock")
	if f == nil {
		return nil, errors.New("os.NewFile failed")
	}

	local := VSockAddr{CID: 0, Port: 0}
	if sa, err := unix.Getsockname(fd); err == nil {
		if vm, ok := sa.(*unix.SockaddrVM); ok {
			local = VSockAddr{CID: vm.CID, Port: vm.Port}
		}
	}

	conn := &vsockConn{
		f:      f,
		fd:     fd,
		local:  local,
		remote: VSockAddr{CID: cid, Port: port},
	}
	fd = -1 // owned by conn.f now
	return conn, nil
}

type VSockAddr struct {
	CID  uint32
	Port uint32
}

func (a VSockAddr) Network() string { return "vsock" }
func (a VSockAddr) String() string  { return fmt.Sprintf("%d:%d", a.CID, a.Port) }

type vsockConn struct {
	f      *os.File
	fd     int
	local  VSockAddr
	remote VSockAddr
}

func (c *vsockConn) Read(b []byte) (int, error)  { return c.f.Read(b) }
func (c *vsockConn) Write(b []byte) (int, error) { return c.f.Write(b) }
func (c *vsockConn) Close() error                { return c.f.Close() }
func (c *vsockConn) LocalAddr() net.Addr         { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr        { return c.remote }

func (c *vsockConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *vsockConn) SetReadDeadline(t time.Time) error {
	return setSockTimeout(c.fd, unix.SO_RCVTIMEO, t)
}

func (c *vsockConn) SetWriteDeadline(t time.Time) error {
	return setSockTimeout(c.fd, unix.SO_SNDTIMEO, t)
}

func setSockTimeout(fd int, opt int, deadline time.Time) error {
	if deadline.IsZero() {
		tv := unix.Timeval{Sec: 0, Usec: 0}
		return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, opt, &tv)
	}

	d := time.Until(deadline)
	if d <= 0 {
		d = time.Microsecond
	}
	tv := unix.NsecToTimeval(d.Nanoseconds())
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, opt, &tv)
}
