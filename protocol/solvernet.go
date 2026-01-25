package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

type Direction uint8

const (
	DirectionUnknown Direction = 0
	DirectionA       Direction = 1 // JunoCash -> Solana
	DirectionB       Direction = 2 // Solana -> JunoCash
)

var errInvalidDirection = errors.New("invalid direction")

const (
	purposeSolverAnnouncementSigning = "solver_announcement"
	purposeQuoteResponseSigning      = "quote_response"
	purposeQuoteID                   = "quote_id"
)

type QuoteID [32]byte

func (id QuoteID) Hex() string { return hex32([32]byte(id)) }

// QuoteRequest is an unsigned RFQ message sent to a solver endpoint.
//
// It is intentionally minimal; the on-chain Fill is the binding commitment.
type QuoteRequest struct {
	DeploymentID DeploymentID
	RFQNonce     [32]byte

	FillID FillID

	// ReceiverTag is the committed Orchard receiver tag for this fill.
	//
	// - DirectionA: may be zero in the request; solver returns its computed tag.
	// - DirectionB: must be set by the requester (derived from the user's receiver bytes + fill_id).
	ReceiverTag ReceiverTag

	Direction        Direction
	Mint             SolanaPubkey
	NetAmount        uint64
	SolanaRecipient  SolanaPubkey
	IntentExpirySlot uint64
}

func (r QuoteRequest) Validate() error {
	if r.Direction != DirectionA && r.Direction != DirectionB {
		return errInvalidDirection
	}
	if r.FillID == (FillID{}) {
		return errors.New("fill id required")
	}
	if r.Direction == DirectionB && r.ReceiverTag == (ReceiverTag{}) {
		return errors.New("receiver tag required for direction B")
	}
	return nil
}

// SolverAnnouncement is a signed, off-chain advertisement that binds a quote
// endpoint to a solver's on-chain identity without any on-chain registration.
type SolverAnnouncement struct {
	DeploymentID DeploymentID
	SolverPubkey SolanaPubkey

	// QuoteURL is an HTTPS endpoint (or WSS URL) for RFQ quoting.
	// The signature binds the exact bytes of this string; treat it as opaque.
	QuoteURL string
}

func (a SolverAnnouncement) SigningBytes() []byte {
	// Canonical encoding:
	//   prefix(purposeSolverAnnouncementSigning) ||
	//   deployment_id (32) ||
	//   solver_pubkey (32) ||
	//   quote_url_len_u16_le ||
	//   quote_url_bytes
	//
	// NOTE: this encoding is for signatures, not for network transport.
	urlBytes := []byte(a.QuoteURL)
	if len(urlBytes) > 0xFFFF {
		panic("quote url too long")
	}

	b := make([]byte, 0, len(prefixBytes(purposeSolverAnnouncementSigning))+32+32+2+len(urlBytes))
	b = append(b, prefixBytes(purposeSolverAnnouncementSigning)...)
	b = append(b, a.DeploymentID[:]...)
	b = append(b, a.SolverPubkey[:]...)

	var urlLen [2]byte
	binary.LittleEndian.PutUint16(urlLen[:], uint16(len(urlBytes)))
	b = append(b, urlLen[:]...)
	b = append(b, urlBytes...)
	return b
}

// QuoteResponse is a signed response from a solver to an RFQ request.
//
// Quotes are advisory until a Fill exists on-chain, but signatures prevent simple
// spoofing of solver endpoints in aggregators and UIs.
type QuoteResponse struct {
	DeploymentID DeploymentID
	SolverPubkey SolanaPubkey

	QuoteID QuoteID
	// Direction is the intent direction this quote applies to.
	Direction Direction

	// Mint is the SPL token mint for the Solana-side leg.
	Mint SolanaPubkey

	// NetAmount is the Solana-side amount the receiver should get (protocol fee is
	// computed separately).
	NetAmount uint64

	// JunocashAmountRequired is the Orchard payment required on JunoCash in zatoshis.
	JunocashAmountRequired Zatoshi

	// FillID is the fill PDA this quote is bound to.
	FillID FillID

	// ReceiverTag is the Orchard receiver tag that must be proven for settlement.
	ReceiverTag ReceiverTag

	// FillExpirySlot is the latest slot the fill can be settled before refunds are allowed.
	FillExpirySlot uint64
}

func (q QuoteResponse) SigningBytes() ([]byte, error) {
	if q.Direction != DirectionA && q.Direction != DirectionB {
		return nil, errInvalidDirection
	}

	// Canonical encoding:
	//   prefix(purposeQuoteResponseSigning) ||
	//   deployment_id (32) ||
	//   solver_pubkey (32) ||
	//   quote_id (32) ||
	//   direction_u8 ||
	//   mint (32) ||
	//   net_amount_u64_le ||
	//   junocash_amount_u64_le ||
	//   fill_id (32) ||
	//   receiver_tag (32) ||
	//   fill_expiry_slot_u64_le
	b := make([]byte, 0, len(prefixBytes(purposeQuoteResponseSigning))+32+32+32+1+32+8+8+32+32+8)
	b = append(b, prefixBytes(purposeQuoteResponseSigning)...)
	b = append(b, q.DeploymentID[:]...)
	b = append(b, q.SolverPubkey[:]...)
	b = append(b, q.QuoteID[:]...)
	b = append(b, byte(q.Direction))
	b = append(b, q.Mint[:]...)

	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], q.NetAmount)
	b = append(b, tmp[:]...)
	binary.LittleEndian.PutUint64(tmp[:], uint64(q.JunocashAmountRequired))
	b = append(b, tmp[:]...)

	b = append(b, q.FillID[:]...)
	b = append(b, q.ReceiverTag[:]...)

	binary.LittleEndian.PutUint64(tmp[:], q.FillExpirySlot)
	b = append(b, tmp[:]...)
	return b, nil
}

func DeriveQuoteID(deploymentID DeploymentID, solverPubkey SolanaPubkey, rfqNonce [32]byte, fillID FillID) QuoteID {
	// Quote IDs are deterministic from (deployment, solver, nonce, fill_id) so an aggregator
	// can safely de-duplicate responses without parsing signed payloads.
	h := sha256.New()
	h.Write(prefixBytes(purposeQuoteID))
	h.Write(deploymentID[:])
	h.Write(solverPubkey[:])
	h.Write(rfqNonce[:])
	h.Write(fillID[:])
	sum := h.Sum(nil)

	var out QuoteID
	copy(out[:], sum)
	return out
}
