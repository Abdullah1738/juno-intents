package solvernet

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/Abdullah1738/juno-intents/protocol"
)

type SolverAnnouncementJSON struct {
	DeploymentID string `json:"deployment_id"`
	SolverPubkey string `json:"solver_pubkey"`
	QuoteURL     string `json:"quote_url"`
}

func (a SolverAnnouncementJSON) ToProtocol() (protocol.SolverAnnouncement, error) {
	deployment, err := parseHex32(a.DeploymentID)
	if err != nil {
		return protocol.SolverAnnouncement{}, err
	}
	solver, err := parseBase58_32(a.SolverPubkey)
	if err != nil {
		return protocol.SolverAnnouncement{}, err
	}
	return protocol.SolverAnnouncement{
		DeploymentID: protocol.DeploymentID(deployment),
		SolverPubkey: protocol.SolanaPubkey(solver),
		QuoteURL:     strings.TrimSpace(a.QuoteURL),
	}, nil
}

func SolverAnnouncementJSONFromProtocol(a protocol.SolverAnnouncement) SolverAnnouncementJSON {
	return SolverAnnouncementJSON{
		DeploymentID: encodeHex32([32]byte(a.DeploymentID)),
		SolverPubkey: encodeBase58_32([32]byte(a.SolverPubkey)),
		QuoteURL:     a.QuoteURL,
	}
}

type SignedSolverAnnouncementJSON struct {
	Announcement SolverAnnouncementJSON `json:"announcement"`
	Signature    string               `json:"signature"` // base58(64)
}

func SignSolverAnnouncement(ann protocol.SolverAnnouncement, priv ed25519.PrivateKey) ([64]byte, error) {
	var out [64]byte
	if len(priv) != ed25519.PrivateKeySize {
		return out, errors.New("invalid ed25519 private key")
	}

	pub := priv.Public().(ed25519.PublicKey)
	if len(pub) != ed25519.PublicKeySize {
		return out, errors.New("invalid ed25519 public key")
	}
	if !bytes.Equal(pub, ann.SolverPubkey[:]) {
		return out, fmt.Errorf("solver pubkey mismatch")
	}

	sig := ed25519.Sign(priv, ann.SigningBytes())
	copy(out[:], sig)
	return out, nil
}

func VerifySolverAnnouncement(ann protocol.SolverAnnouncement, sig [64]byte) error {
	pub := ed25519.PublicKey(ann.SolverPubkey[:])
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid solver pubkey")
	}
	if !ed25519.Verify(pub, ann.SigningBytes(), sig[:]) {
		return errors.New("invalid signature")
	}
	return nil
}

func NewSignedSolverAnnouncement(ann protocol.SolverAnnouncement, priv ed25519.PrivateKey) (SignedSolverAnnouncementJSON, error) {
	sig, err := SignSolverAnnouncement(ann, priv)
	if err != nil {
		return SignedSolverAnnouncementJSON{}, err
	}
	return SignedSolverAnnouncementJSON{
		Announcement: SolverAnnouncementJSONFromProtocol(ann),
		Signature:    encodeBase58_64(sig),
	}, nil
}

func (s SignedSolverAnnouncementJSON) Verify() (protocol.SolverAnnouncement, error) {
	ann, err := s.Announcement.ToProtocol()
	if err != nil {
		return protocol.SolverAnnouncement{}, err
	}
	sig, err := parseBase58_64(s.Signature)
	if err != nil {
		return protocol.SolverAnnouncement{}, err
	}
	if err := VerifySolverAnnouncement(ann, sig); err != nil {
		return protocol.SolverAnnouncement{}, err
	}
	return ann, nil
}
