package attestor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/davidcao20/gc-tee-base/internal/provision"
	"github.com/davidcao20/gc-tee-base/internal/wire"
)

// Status is the runtime state reported by /v1/status. Workload details are
// deliberately absent: the only public claim about the workload is its
// commitment hash.
type Status struct {
	Provisioned    bool   `json:"provisioned"`
	Commitment     string `json:"commitment,omitempty"` // hex, once provisioned
	ContainerState string `json:"containerState"`
	CELRecords     int    `json:"celRecords"`
	TEEKind        string `json:"teeKind"`
	Version        string `json:"version"`
}

// WorkloadRequest is the body of POST /v1/workload: an HPKE-encrypted
// payload (enc||ciphertext) bound to the transcript for the given nonce.
type WorkloadRequest struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// WorkloadResponse acknowledges an accepted payload with its commitment.
type WorkloadResponse struct {
	Commitment string `json:"commitment"`
}

// Server serves attestation evidence and receives the encrypted workload
// payload. Evidence is public-verifiable (quotes, PCRs, certificates), so it
// is served over plain HTTP: integrity comes from the quote signature,
// freshness from the caller's nonce, and payload confidentiality from HPKE
// (the ciphertext only opens inside the attested VM).
type Server struct {
	attestor *Attestor
	receiver *provision.Receiver
	status   func() Status
	payloads chan []byte
	httpSrv  *http.Server
}

// NewServer builds the evidence server. status is polled per request and must
// be safe for concurrent use. receiver may be nil (dev -spec mode), which
// disables /v1/workload.
func NewServer(addr string, a *Attestor, receiver *provision.Receiver, status func() Status) *Server {
	s := &Server{attestor: a, receiver: receiver, status: status, payloads: make(chan []byte, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/attestation", s.handleAttestation)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/workload", s.handleWorkload)
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

// Payloads delivers the accepted workload payload plaintext (at most one).
func (s *Server) Payloads() <-chan []byte {
	return s.payloads
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

	var hpkePub []byte
	if s.receiver != nil {
		hpkePub = s.receiver.PublicKey()
	}
	data, err := wire.EncodeEnvelope(att, hpkePub, string(s.attestor.TEEKind()))
	if err != nil {
		log.Printf("encoding attestation failed: %v", err)
		http.Error(w, "failed to encode attestation", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) handleWorkload(w http.ResponseWriter, r *http.Request) {
	if s.receiver == nil {
		http.Error(w, "this launcher was started with a local spec; it does not accept payloads",
			http.StatusConflict)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}
	var req WorkloadRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "body must be JSON {nonce, ciphertext}", http.StatusBadRequest)
		return
	}
	if len(req.Nonce) < MinNonceLen || len(req.Nonce) > MaxNonceLen {
		http.Error(w, fmt.Sprintf("nonce must be between %d and %d bytes", MinNonceLen, MaxNonceLen),
			http.StatusBadRequest)
		return
	}

	plaintext, err := s.receiver.Accept(req.Nonce, s.attestor.AKPubSPKI(), req.Ciphertext)
	if err != nil {
		if errors.Is(err, provision.ErrAlreadyProvisioned) {
			http.Error(w, "a workload payload was already accepted", http.StatusConflict)
			return
		}
		log.Printf("rejected workload payload: %v", err)
		http.Error(w, "payload does not decrypt for this VM and nonce", http.StatusBadRequest)
		return
	}

	// Buffered channel of size 1 plus the receiver latch: exactly one send.
	s.payloads <- plaintext

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(WorkloadResponse{
		Commitment: hex.EncodeToString(provision.Commitment(plaintext)),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.status())
}
