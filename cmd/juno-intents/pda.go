package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"filippo.io/edwards25519"
	"github.com/mr-tron/base58"
)

var (
	errInvalidHex32 = errors.New("expected 32-byte hex (64 chars)")
	errInvalidKey32 = errors.New("expected 32-byte key")
)

func cmdPDA(argv []string) error {
	fs := flag.NewFlagSet("pda", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		programIDStr  string
		deploymentHex string
		intentHex     string
		printField    string
	)
	fs.StringVar(&programIDStr, "program-id", "", "Solana program id (base58 or 32-byte hex)")
	fs.StringVar(&deploymentHex, "deployment-id", "", "DeploymentID (32-byte hex)")
	fs.StringVar(&intentHex, "intent-nonce", "", "Intent nonce (32-byte hex)")
	fs.StringVar(&printField, "print", "fill-id-hex", "What to print: config|intent|fill|fill-id-hex")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected args: %v", fs.Args())
	}
	if programIDStr == "" {
		return fmt.Errorf("--program-id is required")
	}
	if deploymentHex == "" {
		return fmt.Errorf("--deployment-id is required")
	}

	programID, err := parsePubkey(programIDStr)
	if err != nil {
		return fmt.Errorf("parse --program-id: %w", err)
	}
	deploymentID, err := parseHex32(deploymentHex)
	if err != nil {
		return fmt.Errorf("parse --deployment-id: %w", err)
	}

	config, _, err := findProgramAddress(
		[][]byte{[]byte("config"), deploymentID[:]},
		programID,
	)
	if err != nil {
		return fmt.Errorf("derive config pda: %w", err)
	}

	switch printField {
	case "config":
		fmt.Println(base58.Encode(config[:]))
	case "intent":
		if intentHex == "" {
			return fmt.Errorf("--intent-nonce is required for --print intent")
		}
		intentNonce, err := parseHex32(intentHex)
		if err != nil {
			return fmt.Errorf("parse --intent-nonce: %w", err)
		}
		intent, _, err := findProgramAddress(
			[][]byte{[]byte("intent"), deploymentID[:], intentNonce[:]},
			programID,
		)
		if err != nil {
			return fmt.Errorf("derive intent pda: %w", err)
		}
		fmt.Println(base58.Encode(intent[:]))
	case "fill":
		if intentHex == "" {
			return fmt.Errorf("--intent-nonce is required for --print fill")
		}
		intentNonce, err := parseHex32(intentHex)
		if err != nil {
			return fmt.Errorf("parse --intent-nonce: %w", err)
		}
		intent, _, err := findProgramAddress(
			[][]byte{[]byte("intent"), deploymentID[:], intentNonce[:]},
			programID,
		)
		if err != nil {
			return fmt.Errorf("derive intent pda: %w", err)
		}
		fill, _, err := findProgramAddress(
			[][]byte{[]byte("fill"), intent[:]},
			programID,
		)
		if err != nil {
			return fmt.Errorf("derive fill pda: %w", err)
		}
		fmt.Println(base58.Encode(fill[:]))
	case "fill-id-hex":
		if intentHex == "" {
			return fmt.Errorf("--intent-nonce is required for --print fill-id-hex")
		}
		intentNonce, err := parseHex32(intentHex)
		if err != nil {
			return fmt.Errorf("parse --intent-nonce: %w", err)
		}
		intent, _, err := findProgramAddress(
			[][]byte{[]byte("intent"), deploymentID[:], intentNonce[:]},
			programID,
		)
		if err != nil {
			return fmt.Errorf("derive intent pda: %w", err)
		}
		fill, _, err := findProgramAddress(
			[][]byte{[]byte("fill"), intent[:]},
			programID,
		)
		if err != nil {
			return fmt.Errorf("derive fill pda: %w", err)
		}
		fmt.Println(hex.EncodeToString(fill[:]))
	default:
		return fmt.Errorf("invalid --print: %s", printField)
	}
	return nil
}

func parseHex32(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return out, errInvalidHex32
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, errInvalidHex32
	}
	copy(out[:], b)
	return out, nil
}

func parsePubkey(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if len(s) == 64 {
		return parseHex32(s)
	}

	b, err := base58.Decode(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, errInvalidKey32
	}
	copy(out[:], b)
	return out, nil
}

func findProgramAddress(seeds [][]byte, programID [32]byte) ([32]byte, uint8, error) {
	for bump := uint8(255); ; bump-- {
		pda, err := createProgramAddress(append(seeds, []byte{bump}), programID)
		if err == nil {
			return pda, bump, nil
		}
		if bump == 0 {
			return [32]byte{}, 0, fmt.Errorf("no viable program address found")
		}
	}
}

func createProgramAddress(seeds [][]byte, programID [32]byte) ([32]byte, error) {
	if len(seeds) > 16 {
		return [32]byte{}, fmt.Errorf("too many seeds: %d > 16", len(seeds))
	}

	h := sha256.New()
	for i, seed := range seeds {
		if len(seed) > 32 {
			return [32]byte{}, fmt.Errorf("seed %d too long: %d > 32", i, len(seed))
		}
		h.Write(seed)
	}
	h.Write(programID[:])
	h.Write([]byte("ProgramDerivedAddress"))

	var out [32]byte
	copy(out[:], h.Sum(nil))
	if isOnCurve(out) {
		return [32]byte{}, fmt.Errorf("derived address is on-curve")
	}
	return out, nil
}

func isOnCurve(pk [32]byte) bool {
	// Solana's on-curve check is an Edwards25519 decompression check.
	_, err := new(edwards25519.Point).SetBytes(pk[:])
	return err == nil
}
