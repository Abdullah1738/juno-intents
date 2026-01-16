package solvernet

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/Abdullah1738/juno-intents/offchain/helius"
	"github.com/Abdullah1738/juno-intents/offchain/solanafees"
	"github.com/Abdullah1738/juno-intents/protocol"
)

type FeeProfile struct {
	AccountKeys      []string
	ComputeUnitLimit uint32
	Signatures       uint64
}

type Solver struct {
	DeploymentID protocol.DeploymentID
	SolverPubkey protocol.SolanaPubkey
	QuoteURL     string
	PrivKey      ed25519.PrivateKey

	Strategy FixedPriceStrategy

	Helius *helius.Client

	FillFeeProfile   FeeProfile
	SettleFeeProfile FeeProfile
	PriorityOptions  helius.PriorityFeeOptions
}

func (s *Solver) SignedAnnouncement() (SignedSolverAnnouncementJSON, error) {
	ann := protocol.SolverAnnouncement{
		DeploymentID: s.DeploymentID,
		SolverPubkey: s.SolverPubkey,
		QuoteURL:     s.QuoteURL,
	}
	return NewSignedSolverAnnouncement(ann, s.PrivKey)
}

func (s *Solver) Quote(ctx context.Context, req protocol.QuoteRequest) (SignedQuoteResponseJSON, error) {
	if s == nil {
		return SignedQuoteResponseJSON{}, errors.New("nil solver")
	}
	if req.DeploymentID != s.DeploymentID {
		return SignedQuoteResponseJSON{}, errors.New("deployment mismatch")
	}
	if err := req.Validate(); err != nil {
		return SignedQuoteResponseJSON{}, err
	}

	quoteID := protocol.DeriveQuoteID(s.DeploymentID, s.SolverPubkey, req.RFQNonce)

	required, err := s.Strategy.QuoteZatoshi(req.NetAmount, req.Direction)
	if err != nil {
		return SignedQuoteResponseJSON{}, err
	}

	q := protocol.QuoteResponse{
		DeploymentID:           s.DeploymentID,
		SolverPubkey:           s.SolverPubkey,
		QuoteID:                quoteID,
		Direction:              req.Direction,
		Mint:                   req.Mint,
		NetAmount:              req.NetAmount,
		JunocashAmountRequired: protocol.Zatoshi(required),
		FillExpirySlot:         req.IntentExpirySlot,
	}

	var hint *FeeHint
	if s.Helius != nil {
		h := &FeeHint{}

		opts := &s.PriorityOptions
		if opts.PriorityLevel == "" {
			opts.PriorityLevel = helius.PriorityMedium
			opts.Recommended = true
		}

		if len(s.FillFeeProfile.AccountKeys) != 0 {
			est, err := solanafees.EstimateFromHeliusByAccountKeys(
				ctx,
				s.Helius,
				s.FillFeeProfile.AccountKeys,
				s.FillFeeProfile.ComputeUnitLimit,
				s.FillFeeProfile.Signatures,
				opts,
			)
			if err == nil {
				h.FillTx = &est
			}
		}

		if len(s.SettleFeeProfile.AccountKeys) != 0 {
			est, err := solanafees.EstimateFromHeliusByAccountKeys(
				ctx,
				s.Helius,
				s.SettleFeeProfile.AccountKeys,
				s.SettleFeeProfile.ComputeUnitLimit,
				s.SettleFeeProfile.Signatures,
				opts,
			)
			if err == nil {
				h.SettleTx = &est
			}
		}

		if h.FillTx != nil || h.SettleTx != nil {
			hint = h
		}
	}

	return NewSignedQuoteResponse(q, s.PrivKey, hint)
}
