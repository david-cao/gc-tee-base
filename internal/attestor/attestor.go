// Package attestor owns the TPM attestation key and produces nonce-bound
// attestation evidence. The launcher process (never the workload container)
// holds the TPM handle and serves evidence over HTTP.
package attestor

import (
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"

	attestpb "github.com/google/go-tpm-tools/proto/attest"

	"github.com/davidcao20/gc-tee-base/internal/measure"
)

// Nonce length bounds for the evidence API. TPM2 extraData caps at 64 bytes;
// the 16-byte floor keeps challenges unguessable.
const (
	MinNonceLen = 16
	MaxNonceLen = 64
)

// AKType selects which attestation key to use.
type AKType string

const (
	// AKGceECC is the Google-issued GCE attestation key (ECC). The right
	// choice on a real Confidential VM: its certificate chains to Google's
	// CA, anchoring the whole attestation.
	AKGceECC AKType = "gce-ecc"
	// AKGceRSA is the RSA variant of the GCE attestation key.
	AKGceRSA AKType = "gce-rsa"
	// AKOwnerECC is a TPM owner-hierarchy key with no certificate. For
	// development and simulators only: verifiers must trust the raw key.
	AKOwnerECC AKType = "owner-ecc"
)

// OpenTPM opens the kernel TPM resource manager, falling back to direct
// device access.
func OpenTPM() (io.ReadWriteCloser, error) {
	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err == nil {
		return tpm, nil
	}
	tpm, err2 := tpm2.OpenTPM("/dev/tpm0")
	if err2 != nil {
		return nil, fmt.Errorf("opening TPM (/dev/tpmrm0: %v; /dev/tpm0: %v)", err, err2)
	}
	return tpm, nil
}

// Attestor produces attestation evidence over the measured state.
type Attestor struct {
	mu       sync.Mutex
	ak       *client.Key
	measurer *measure.Measurer
}

// New loads the attestation key of the given type. The TPM must be the same
// one the Measurer extends, or quotes will not cover the measurements.
func New(tpm io.ReadWriter, m *measure.Measurer, akType AKType) (*Attestor, error) {
	var ak *client.Key
	var err error
	switch akType {
	case AKGceECC:
		ak, err = client.GceAttestationKeyECC(tpm)
	case AKGceRSA:
		ak, err = client.GceAttestationKeyRSA(tpm)
	case AKOwnerECC:
		ak, err = client.AttestationKeyECC(tpm)
	default:
		return nil, fmt.Errorf("unknown attestation key type %q", akType)
	}
	if err != nil {
		return nil, fmt.Errorf("loading attestation key (%s): %w", akType, err)
	}
	return &Attestor{ak: ak, measurer: m}, nil
}

// Attest returns evidence bound to the given nonce: quotes over all PCR
// banks, the TCG boot log, the canonical event log, and the AK certificate
// chain when one exists.
func (a *Attestor) Attest(nonce []byte) (*attestpb.Attestation, error) {
	if len(nonce) < MinNonceLen || len(nonce) > MaxNonceLen {
		return nil, fmt.Errorf("nonce must be between %d and %d bytes, got %d",
			MinNonceLen, MaxNonceLen, len(nonce))
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	celBytes, err := a.measurer.EncodedCEL()
	if err != nil {
		return nil, fmt.Errorf("encoding canonical event log: %w", err)
	}

	att, err := a.ak.Attest(client.AttestOpts{
		Nonce:            nonce,
		CertChainFetcher: http.DefaultClient,
	})
	if err != nil {
		return nil, fmt.Errorf("generating attestation: %w", err)
	}
	att.CanonicalEventLog = celBytes
	return att, nil
}

// Close releases the attestation key (not the underlying TPM).
func (a *Attestor) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ak.Close()
}
