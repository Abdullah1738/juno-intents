package solvernet

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrInvalidKeypairFile = errors.New("invalid keypair file")

func DefaultSolanaKeypairPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "solana", "id.json")
}

func LoadSolanaKeypair(path string) (ed25519.PrivateKey, [32]byte, error) {
	var pub [32]byte
	if path == "" {
		return nil, pub, fmt.Errorf("keypair path required")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, pub, err
	}

	var ints []int
	if err := json.Unmarshal(raw, &ints); err != nil {
		return nil, pub, ErrInvalidKeypairFile
	}
	if len(ints) != ed25519.PrivateKeySize {
		return nil, pub, ErrInvalidKeypairFile
	}

	key := make([]byte, ed25519.PrivateKeySize)
	for i, v := range ints {
		if v < 0 || v > 255 {
			return nil, pub, ErrInvalidKeypairFile
		}
		key[i] = byte(v)
	}

	priv := ed25519.PrivateKey(key)
	pk, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pk) != ed25519.PublicKeySize {
		return nil, pub, ErrInvalidKeypairFile
	}
	copy(pub[:], pk)
	return priv, pub, nil
}

