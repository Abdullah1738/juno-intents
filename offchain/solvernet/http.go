package solvernet

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func (s *Solver) Handler() (http.Handler, error) {
	if s == nil {
		return nil, errors.New("nil solver")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/announcement", func(w http.ResponseWriter, _ *http.Request) {
		signedAnn, err := s.SignedAnnouncement()
		if err != nil {
			http.Error(w, "announcement error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, signedAnn)
	})
	mux.HandleFunc("/v1/quote", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		var reqJSON QuoteRequestJSON
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&reqJSON); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		req, err := reqJSON.ToProtocol()
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		signed, err := s.Quote(r.Context(), req)
		if err != nil {
			http.Error(w, "quote error", http.StatusBadRequest)
			return
		}
		writeJSON(w, signed)
	})

	return mux, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
