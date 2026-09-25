package attestor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/davidcao20/gc-tee-base/internal/wire"
)

// Status is the non-sensitive runtime state reported by /v1/status.
type Status struct {
	ImageRef       string `json:"imageRef"`
	ImageDigest    string `json:"imageDigest"`
	RestartPolicy  string `json:"restartPolicy"`
	ContainerState string `json:"containerState"`
	CELRecords     int    `json:"celRecords"`
	Version        string `json:"version"`
}

// Server serves attestation evidence. Evidence is public-verifiable (quotes,
// PCRs, certificates), so it is served over plain HTTP: integrity comes from
// the quote signature, and freshness from the caller's nonce.
type Server struct {
	attestor *Attestor
	status   func() Status
	httpSrv  *http.Server
}

// NewServer builds the evidence server. status is polled per request and must
// be safe for concurrent use.
func NewServer(addr string, a *Attestor, status func() Status) *Server {
	s := &Server{attestor: a, status: status}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/attestation", s.handleAttestation)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	s.httpSrv = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	return s
}

// Handler exposes the evidence routes (also used by tests).
func (s *Server) Handler() http.Handler {
	return s.httpSrv.Handler
}

// ListenAndServe blocks serving evidence until Shutdown or failure.
func (s *Server) ListenAndServe() error {
	err := s.httpSrv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	nonceHex := r.URL.Query().Get("nonce")
	if nonceHex == "" {
		http.Error(w, "missing required query parameter: nonce (hex)", http.StatusBadRequest)
		return
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		http.Error(w, "nonce must be hex-encoded", http.StatusBadRequest)
		return
	}
	if len(nonce) < MinNonceLen || len(nonce) > MaxNonceLen {
		http.Error(w, fmt.Sprintf("nonce must be between %d and %d bytes", MinNonceLen, MaxNonceLen),
			http.StatusBadRequest)
		return
	}

	att, err := s.attestor.Attest(nonce)
	if err != nil {
		log.Printf("attestation request failed: %v", err)
		http.Error(w, "failed to generate attestation", http.StatusInternalServerError)
		return
	}

	format := wire.FormatProto
	contentType := "application/x-protobuf"
	if r.URL.Query().Get("format") == "json" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		format = wire.FormatJSON
		contentType = "application/json"
	}
	data, err := wire.Encode(att, format)
	if err != nil {
		log.Printf("encoding attestation failed: %v", err)
		http.Error(w, "failed to encode attestation", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(data)
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.status())
}
