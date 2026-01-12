package solvernet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	HTTP *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) FetchAnnouncement(ctx context.Context, announcementURL string) (SignedSolverAnnouncementJSON, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, announcementURL, nil)
	if err != nil {
		return SignedSolverAnnouncementJSON{}, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return SignedSolverAnnouncementJSON{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SignedSolverAnnouncementJSON{}, fmt.Errorf("http %d", resp.StatusCode)
	}
	var signed SignedSolverAnnouncementJSON
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&signed); err != nil {
		return SignedSolverAnnouncementJSON{}, err
	}
	if _, err := signed.Verify(); err != nil {
		return SignedSolverAnnouncementJSON{}, err
	}
	return signed, nil
}

func (c *Client) FetchQuote(
	ctx context.Context,
	quoteURL string,
	req QuoteRequestJSON,
) (SignedQuoteResponseJSON, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return SignedQuoteResponseJSON{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, quoteURL, bytes.NewReader(body))
	if err != nil {
		return SignedQuoteResponseJSON{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return SignedQuoteResponseJSON{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SignedQuoteResponseJSON{}, fmt.Errorf("http %d", resp.StatusCode)
	}
	var signed SignedQuoteResponseJSON
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&signed); err != nil {
		return SignedQuoteResponseJSON{}, err
	}
	if _, err := signed.Verify(); err != nil {
		return SignedQuoteResponseJSON{}, err
	}
	return signed, nil
}

