package solvernet

import (
	"context"
	"errors"
	"sort"

	"github.com/Abdullah1738/juno-intents/protocol"
)

type CollectedQuote struct {
	AnnouncementURL string
	Announcement    protocol.SolverAnnouncement
	Quote           protocol.QuoteResponse
	FeeHint         *FeeHint
}

type QuoteSelection struct {
	Best   CollectedQuote
	Quotes []CollectedQuote
}

func CollectQuotes(ctx context.Context, client *Client, announcementURLs []string, req protocol.QuoteRequest) (QuoteSelection, error) {
	if len(announcementURLs) == 0 {
		return QuoteSelection{}, errors.New("announcement urls required")
	}
	if err := req.Validate(); err != nil {
		return QuoteSelection{}, err
	}

	if client == nil {
		client = &Client{}
	}

	reqJSON := QuoteRequestJSONFromProtocol(req)

	var quotes []CollectedQuote
	for _, announcementURL := range announcementURLs {
		signedAnn, err := client.FetchAnnouncement(ctx, announcementURL)
		if err != nil {
			continue
		}
		ann, err := signedAnn.Verify()
		if err != nil {
			continue
		}
		if ann.DeploymentID != req.DeploymentID {
			continue
		}

		signed, err := client.FetchQuote(ctx, ann.QuoteURL, reqJSON)
		if err != nil {
			continue
		}
		q, err := signed.Verify()
		if err != nil {
			continue
		}
		if q.DeploymentID != req.DeploymentID || q.SolverPubkey != ann.SolverPubkey {
			continue
		}
		if q.Direction != req.Direction || q.Mint != req.Mint || q.NetAmount != req.NetAmount {
			continue
		}
		if q.FillID != req.FillID {
			continue
		}
		if req.ReceiverTag != (protocol.ReceiverTag{}) && q.ReceiverTag != req.ReceiverTag {
			continue
		}

		quotes = append(quotes, CollectedQuote{
			AnnouncementURL: announcementURL,
			Announcement:    ann,
			Quote:           q,
			FeeHint:         signed.FeeHint,
		})
	}

	if len(quotes) == 0 {
		return QuoteSelection{}, errors.New("no quotes")
	}

	sort.Slice(quotes, func(i, j int) bool {
		ai := quotes[i].Quote.JunocashAmountRequired
		aj := quotes[j].Quote.JunocashAmountRequired
		if req.Direction == protocol.DirectionB {
			if ai != aj {
				return ai > aj
			}
		} else {
			if ai != aj {
				return ai < aj
			}
		}
		return string(quotes[i].Quote.SolverPubkey[:]) < string(quotes[j].Quote.SolverPubkey[:])
	})

	return QuoteSelection{Best: quotes[0], Quotes: quotes}, nil
}
