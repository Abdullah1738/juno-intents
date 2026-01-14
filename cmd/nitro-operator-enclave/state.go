package main

import (
	"crypto/ed25519"
	"sync"
)

type enclaveState struct {
	mu   sync.RWMutex
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (s *enclaveState) SetKey(priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.priv = append(ed25519.PrivateKey(nil), priv...)
	s.pub = append(ed25519.PublicKey(nil), pub...)
}

func (s *enclaveState) Key() (ed25519.PrivateKey, ed25519.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.priv) == 0 || len(s.pub) == 0 {
		return nil, nil, false
	}
	return append(ed25519.PrivateKey(nil), s.priv...), append(ed25519.PublicKey(nil), s.pub...), true
}

func (s *enclaveState) Pubkey() (ed25519.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.pub) == 0 {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), s.pub...), true
}
