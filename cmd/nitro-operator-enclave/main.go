package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/Abdullah1738/juno-intents/protocol"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	fs := flag.NewFlagSet("nitro-operator-enclave", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var vsockPort uint
	var unsafeEphemeral bool
	fs.UintVar(&vsockPort, "vsock-port", 5000, "AF_VSOCK port to listen on")
	fs.BoolVar(&unsafeEphemeral, "unsafe-ephemeral", false, "If set, generates an in-memory ed25519 key at boot (NOT persistent, NOT for production)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}
	if vsockPort == 0 || vsockPort > 0xffff_ffff {
		return errors.New("--vsock-port must fit in u32")
	}

	state := &enclaveState{}
	if unsafeEphemeral {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		state.SetKey(priv, pub)
		fmt.Fprintf(os.Stderr, "unsafe_ephemeral_pubkey_hex=%s\n", hex.EncodeToString(pub))
	}

	ln, err := listenVsock(uint32(vsockPort))
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "listening=vsock:%d\n", vsockPort)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			default:
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = handleConn(ctx, c, state)
		}()
	}
}

type request struct {
	ID     string          `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type response struct {
	ID     string `json:"id,omitempty"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

type initSigningKeyParams struct {
	AwsRegion     string `json:"aws_region"`
	KmsKeyID      string `json:"kms_key_id"`
	KmsVsockPort  uint32 `json:"kms_vsock_port"`
	AwsAccessKey  string `json:"aws_access_key_id"`
	AwsSecretKey  string `json:"aws_secret_access_key"`
	AwsSessionTok string `json:"aws_session_token,omitempty"`

	SealedKey *sealedSigningKeyV1 `json:"sealed_key,omitempty"`
}

type initSigningKeyResult struct {
	SignerPubkeyHex string             `json:"signer_pubkey_hex"`
	SealedKey       sealedSigningKeyV1 `json:"sealed_key"`
}

type signObservationParams struct {
	DeploymentID string `json:"deployment_id"`
	Height       uint64 `json:"height"`
	BlockHash    string `json:"block_hash"`
	OrchardRoot  string `json:"orchard_root"`
	PrevHash     string `json:"prev_hash"`
}

type signObservationResult struct {
	SignerPubkeyHex string `json:"signer_pubkey_hex"`
	SignatureHex    string `json:"signature_hex"`
}

func handleConn(ctx context.Context, c net.Conn, state *enclaveState) error {
	defer c.Close()

	rd := bufio.NewScanner(c)
	rd.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	wr := bufio.NewWriter(c)
	enc := json.NewEncoder(wr)

	for rd.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line := strings.TrimSpace(rd.Text())
		if line == "" {
			continue
		}

		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(response{Error: "invalid_json"})
			_ = wr.Flush()
			continue
		}

		var resp response
		resp.ID = req.ID

		switch req.Method {
		case "ping":
			resp.Result = "pong"
		case "pubkey":
			pub, ok := state.Pubkey()
			if !ok {
				resp.Error = "not_initialized"
				break
			}
			resp.Result = hex.EncodeToString(pub)
		case "init_signing_key":
			var p initSigningKeyParams
			if err := json.Unmarshal(req.Params, &p); err != nil {
				resp.Error = "invalid_params"
				break
			}
			out, err := initSigningKey(ctx, state, p)
			if err != nil {
				resp.Error = err.Error()
				break
			}
			resp.Result = out
		case "sign_observation":
			var p signObservationParams
			if err := json.Unmarshal(req.Params, &p); err != nil {
				resp.Error = "invalid_params"
				break
			}
			priv, pub, ok := state.Key()
			if !ok {
				resp.Error = "not_initialized"
				break
			}
			out, err := signObservation(p, priv, pub)
			if err != nil {
				resp.Error = err.Error()
				break
			}
			resp.Result = out
		default:
			resp.Error = "unknown_method"
		}

		if err := enc.Encode(resp); err != nil {
			return err
		}
		if err := wr.Flush(); err != nil {
			return err
		}
	}
	if err := rd.Err(); err != nil {
		return err
	}
	return nil
}

func signObservation(p signObservationParams, priv ed25519.PrivateKey, pub ed25519.PublicKey) (signObservationResult, error) {
	deploymentID, err := protocol.ParseDeploymentIDHex(trimHex32(p.DeploymentID))
	if err != nil {
		return signObservationResult{}, errors.New("invalid_deployment_id")
	}
	blockHash, err := parseHex32(trimHex32(p.BlockHash))
	if err != nil {
		return signObservationResult{}, errors.New("invalid_block_hash")
	}
	orchardRoot, err := parseHex32(trimHex32(p.OrchardRoot))
	if err != nil {
		return signObservationResult{}, errors.New("invalid_orchard_root")
	}
	prevHash, err := parseHex32(trimHex32(p.PrevHash))
	if err != nil {
		return signObservationResult{}, errors.New("invalid_prev_hash")
	}

	obs := protocol.CheckpointObservation{
		Height:      p.Height,
		BlockHash:   protocol.JunoBlockHash(blockHash),
		OrchardRoot: protocol.OrchardRoot(orchardRoot),
		PrevHash:    protocol.JunoBlockHash(prevHash),
	}
	sig := ed25519.Sign(priv, obs.SigningBytes(deploymentID))
	return signObservationResult{
		SignerPubkeyHex: hex.EncodeToString(pub),
		SignatureHex:    hex.EncodeToString(sig),
	}, nil
}

func trimHex32(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.Trim(s, "\"")
	return s
}

func parseHex32(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 64 {
		return out, errors.New("invalid hex length")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, errors.New("invalid hex")
	}
	copy(out[:], b)
	return out, nil
}

type vsockListener struct {
	fd   int
	addr vsockAddr
}

type vsockAddr struct {
	cid  uint32
	port uint32
}

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("%d:%d", a.cid, a.port) }

func listenVsock(port uint32) (*vsockListener, error) {
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
	return &vsockListener{
		fd:   fd,
		addr: vsockAddr{cid: unix.VMADDR_CID_ANY, port: port},
	}, nil
}

func (l *vsockListener) Accept() (net.Conn, error) {
	fd, _, err := unix.Accept(l.fd)
	if err != nil {
		return nil, err
	}
	_ = unix.SetNonblock(fd, true)

	f := os.NewFile(uintptr(fd), "vsock")
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("os.NewFile failed")
	}
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (l *vsockListener) Close() error   { return unix.Close(l.fd) }
func (l *vsockListener) Addr() net.Addr { return l.addr }
