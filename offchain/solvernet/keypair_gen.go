package solvernet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func GenerateSolanaKeypairFile(path string, force bool) ([32]byte, error) {
	var pub [32]byte
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return pub, errors.New("keypair path required")
	}

	if !force {
		if _, err := os.Stat(path); err == nil {
			return pub, fmt.Errorf("keypair already exists: %s", path)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return pub, err
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return pub, err
	}

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return pub, err
	}
	if len(pk) != ed25519.PublicKeySize || len(sk) != ed25519.PrivateKeySize {
		return pub, errors.New("unexpected ed25519 key size")
	}
	copy(pub[:], pk)

	ints := make([]int, 0, ed25519.PrivateKeySize)
	for _, b := range sk {
		ints = append(ints, int(b))
	}
	raw, err := json.Marshal(ints)
	if err != nil {
		return pub, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-solana-keypair-*.json")
	if err != nil {
		return pub, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return pub, err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return pub, err
	}
	if err := tmp.Close(); err != nil {
		return pub, err
	}

	if err := os.Rename(tmpName, path); err != nil {
		return pub, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return pub, err
	}
	return pub, nil
}
