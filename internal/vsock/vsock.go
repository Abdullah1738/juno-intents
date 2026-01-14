package vsock

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type Addr struct {
	CID  uint32
	Port uint32
}

func (a Addr) Network() string { return "vsock" }
func (a Addr) String() string  { return fmt.Sprintf("%d:%d", a.CID, a.Port) }

func Dial(cid uint32, port uint32) (net.Conn, error) {
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

	local := Addr{CID: 0, Port: 0}
	if sa, err := unix.Getsockname(fd); err == nil {
		if vm, ok := sa.(*unix.SockaddrVM); ok {
			local = Addr{CID: vm.CID, Port: vm.Port}
		}
	}

	conn := &Conn{
		f:      f,
		fd:     fd,
		local:  local,
		remote: Addr{CID: cid, Port: port},
	}
	fd = -1 // owned by conn.f now
	return conn, nil
}

type Listener struct {
	fd   int
	addr Addr
}

func Listen(port uint32) (*Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Close(fd)
		}
	}()

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return nil, err
	}

	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		return nil, err
	}
	if err := unix.Listen(fd, 128); err != nil {
		return nil, err
	}

	cleanup = false
	return &Listener{
		fd:   fd,
		addr: Addr{CID: unix.VMADDR_CID_ANY, Port: port},
	}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	fd, sa, err := unix.Accept(l.fd)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd != -1 {
			_ = unix.Close(fd)
		}
	}()

	f := os.NewFile(uintptr(fd), "vsock")
	if f == nil {
		return nil, errors.New("os.NewFile failed")
	}

	remote := Addr{CID: 0, Port: 0}
	if vm, ok := sa.(*unix.SockaddrVM); ok {
		remote = Addr{CID: vm.CID, Port: vm.Port}
	}
	local := l.addr
	if sa, err := unix.Getsockname(fd); err == nil {
		if vm, ok := sa.(*unix.SockaddrVM); ok {
			local = Addr{CID: vm.CID, Port: vm.Port}
		}
	}

	conn := &Conn{
		f:      f,
		fd:     fd,
		local:  local,
		remote: remote,
	}
	fd = -1 // owned by conn.f now
	return conn, nil
}

func (l *Listener) Close() error   { return unix.Close(l.fd) }
func (l *Listener) Addr() net.Addr { return l.addr }

type Conn struct {
	f      *os.File
	fd     int
	local  Addr
	remote Addr
}

func (c *Conn) Read(b []byte) (int, error)  { return c.f.Read(b) }
func (c *Conn) Write(b []byte) (int, error) { return c.f.Write(b) }
func (c *Conn) Close() error                { return c.f.Close() }
func (c *Conn) LocalAddr() net.Addr         { return c.local }
func (c *Conn) RemoteAddr() net.Addr        { return c.remote }

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return setSockTimeout(c.fd, unix.SO_RCVTIMEO, t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
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
