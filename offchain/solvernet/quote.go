package solvernet

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/Abdullah1738/juno-intents/offchain/solanafees"
	"github.com/Abdullah1738/juno-intents/protocol"
)

type QuoteRequestJSON struct {
	DeploymentID      string `json:"deployment_id"`
	RFQNonce          string `json:"rfq_nonce"`
	Direction         uint8  `json:"direction"`
	Mint              string `json:"mint"`
	NetAmount         string `json:"net_amount"`
	SolanaRecipient   string `json:"solana_recipient"`
	IntentExpirySlot  string `json:"intent_expiry_slot"`
}

func (r QuoteRequestJSON) ToProtocol() (protocol.QuoteRequest, error) {
	deployment, err := parseHex32(r.DeploymentID)
	if err != nil {
		return protocol.QuoteRequest{}, err
	}
	rfq, err := parseHex32(r.RFQNonce)
	if err != nil {
		return protocol.QuoteRequest{}, err
	}
	mint, err := parseBase58_32(r.Mint)
	if err != nil {
		return protocol.QuoteRequest{}, err
	}
	recipient, err := parseBase58_32(r.SolanaRecipient)
	if err != nil {
		return protocol.QuoteRequest{}, err
	}
	netAmount, err := parseU64String(r.NetAmount)
	if err != nil {
		return protocol.QuoteRequest{}, err
	}
	expiry, err := parseU64String(r.IntentExpirySlot)
	if err != nil {
		return protocol.QuoteRequest{}, err
	}

	out := protocol.QuoteRequest{
		DeploymentID:      protocol.DeploymentID(deployment),
		RFQNonce:          rfq,
		Direction:         protocol.Direction(r.Direction),
		Mint:              protocol.SolanaPubkey(mint),
		NetAmount:         netAmount,
		SolanaRecipient:   protocol.SolanaPubkey(recipient),
		IntentExpirySlot:  expiry,
	}
	if err := out.Validate(); err != nil {
		return protocol.QuoteRequest{}, err
	}
	return out, nil
}

func QuoteRequestJSONFromProtocol(r protocol.QuoteRequest) QuoteRequestJSON {
	return QuoteRequestJSON{
		DeploymentID:     encodeHex32([32]byte(r.DeploymentID)),
		RFQNonce:         encodeHex32(r.RFQNonce),
		Direction:        uint8(r.Direction),
		Mint:             encodeBase58_32([32]byte(r.Mint)),
		NetAmount:        formatU64String(r.NetAmount),
		SolanaRecipient:  encodeBase58_32([32]byte(r.SolanaRecipient)),
		IntentExpirySlot: formatU64String(r.IntentExpirySlot),
	}
}

type QuoteResponseJSON struct {
	DeploymentID            string `json:"deployment_id"`
	SolverPubkey            string `json:"solver_pubkey"`
	QuoteID                 string `json:"quote_id"`
	Direction               uint8  `json:"direction"`
	Mint                    string `json:"mint"`
	NetAmount               string `json:"net_amount"`
	JunocashAmountRequired  string `json:"junocash_amount_required"`
	FillExpirySlot          string `json:"fill_expiry_slot"`
}

func QuoteResponseJSONFromProtocol(q protocol.QuoteResponse) QuoteResponseJSON {
	return QuoteResponseJSON{
		DeploymentID:           encodeHex32([32]byte(q.DeploymentID)),
		SolverPubkey:           encodeBase58_32([32]byte(q.SolverPubkey)),
		QuoteID:                encodeHex32([32]byte(q.QuoteID)),
		Direction:              uint8(q.Direction),
		Mint:                   encodeBase58_32([32]byte(q.Mint)),
		NetAmount:              formatU64String(q.NetAmount),
		JunocashAmountRequired: formatU64String(uint64(q.JunocashAmountRequired)),
		FillExpirySlot:         formatU64String(q.FillExpirySlot),
	}
}

func (j QuoteResponseJSON) ToProtocol() (protocol.QuoteResponse, error) {
	deployment, err := parseHex32(j.DeploymentID)
	if err != nil {
		return protocol.QuoteResponse{}, err
	}
	solver, err := parseBase58_32(j.SolverPubkey)
	if err != nil {
		return protocol.QuoteResponse{}, err
	}
	quoteID, err := parseHex32(j.QuoteID)
	if err != nil {
		return protocol.QuoteResponse{}, err
	}
	mint, err := parseBase58_32(j.Mint)
	if err != nil {
		return protocol.QuoteResponse{}, err
	}
	netAmount, err := parseU64String(j.NetAmount)
	if err != nil {
		return protocol.QuoteResponse{}, err
	}
	junoAmt, err := parseU64String(j.JunocashAmountRequired)
	if err != nil {
		return protocol.QuoteResponse{}, err
	}
	expiry, err := parseU64String(j.FillExpirySlot)
	if err != nil {
		return protocol.QuoteResponse{}, err
	}

	return protocol.QuoteResponse{
		DeploymentID:          protocol.DeploymentID(deployment),
		SolverPubkey:          protocol.SolanaPubkey(solver),
		QuoteID:               protocol.QuoteID(quoteID),
		Direction:             protocol.Direction(j.Direction),
		Mint:                  protocol.SolanaPubkey(mint),
		NetAmount:             netAmount,
		JunocashAmountRequired: protocol.Zatoshi(junoAmt),
		FillExpirySlot:        expiry,
	}, nil
}

type FeeHint struct {
	FillTx   *solanafees.TxFeeEstimate `json:"fill_tx,omitempty"`
	SettleTx *solanafees.TxFeeEstimate `json:"settle_tx,omitempty"`
}

type SignedQuoteResponseJSON struct {
	Quote     QuoteResponseJSON `json:"quote"`
	Signature string            `json:"signature"` // base58(64)
	FeeHint   *FeeHint          `json:"fee_hint,omitempty"`
}

func SignQuoteResponse(q protocol.QuoteResponse, priv ed25519.PrivateKey) ([64]byte, error) {
	var out [64]byte
	if len(priv) != ed25519.PrivateKeySize {
		return out, errors.New("invalid ed25519 private key")
	}

	pub := priv.Public().(ed25519.PublicKey)
	if len(pub) != ed25519.PublicKeySize {
		return out, errors.New("invalid ed25519 public key")
	}
	var pub32 [32]byte
	copy(pub32[:], pub)
	if q.SolverPubkey != protocol.SolanaPubkey(pub32) {
		return out, fmt.Errorf("solver pubkey mismatch")
	}

	msg, err := q.SigningBytes()
	if err != nil {
		return out, err
	}
	sig := ed25519.Sign(priv, msg)
	copy(out[:], sig)
	return out, nil
}

func VerifyQuoteResponse(q protocol.QuoteResponse, sig [64]byte) error {
	msg, err := q.SigningBytes()
	if err != nil {
		return err
	}
	pub := ed25519.PublicKey(q.SolverPubkey[:])
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid solver pubkey")
	}
	if !ed25519.Verify(pub, msg, sig[:]) {
		return errors.New("invalid signature")
	}
	return nil
}

func NewSignedQuoteResponse(q protocol.QuoteResponse, priv ed25519.PrivateKey, hint *FeeHint) (SignedQuoteResponseJSON, error) {
	sig, err := SignQuoteResponse(q, priv)
	if err != nil {
		return SignedQuoteResponseJSON{}, err
	}
	return SignedQuoteResponseJSON{
		Quote:     QuoteResponseJSONFromProtocol(q),
		Signature: encodeBase58_64(sig),
		FeeHint:   hint,
	}, nil
}

func (s SignedQuoteResponseJSON) Verify() (protocol.QuoteResponse, error) {
	q, err := s.Quote.ToProtocol()
	if err != nil {
		return protocol.QuoteResponse{}, err
	}
	sig, err := parseBase58_64(s.Signature)
	if err != nil {
		return protocol.QuoteResponse{}, err
	}
	if err := VerifyQuoteResponse(q, sig); err != nil {
		return protocol.QuoteResponse{}, err
	}
	return q, nil
}
