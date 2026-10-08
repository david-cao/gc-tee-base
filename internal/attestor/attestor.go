// Package attestor owns the TPM attestation key and produces nonce-bound
// attestation evidence. The launcher process (never the workload container)
// holds the TPM handle and serves evidence over HTTP.
package attestor

import (
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"

	attestpb "github.com/google/go-tpm-tools/proto/attest"

	"github.com/davidcao20/gc-tee-base/internal/measure"
	"github.com/davidcao20/gc-tee-base/internal/provision"
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

// TEEKind names the hardware attestation-report source in evidence.
type TEEKind string

const (
	TEESevSnp TEEKind = "sev-snp"
	TEETdx    TEEKind = "tdx"
	TEENone   TEEKind = "none"
)

// TEE is a hardware attestation-report device plus its kind. A nil *TEE
// means evidence carries no hardware report (dev machines, plain VMs).
type TEE struct {
	Device client.TEEDevice
	Kind   TEEKind
}

// DetectTEE probes for a hardware attestation-report device: SEV-SNP first,
// then TDX. Returns nil (not an error) when neither is available, so the
// launcher still runs on non-confidential machines — verifiers decide via
// policy whether evidence without a hardware report is acceptable.
func DetectTEE() *TEE {
	if dev, err := client.CreateSevSnpQuoteProvider(); err == nil {
		return &TEE{Device: dev, Kind: TEESevSnp}
	}
	if dev, err := client.CreateTdxQuoteProvider(); err == nil {
		return &TEE{Device: dev, Kind: TEETdx}
	}
	log.Printf("no SEV-SNP or TDX report device; evidence will carry no hardware report")
	return nil
}

// Attestor produces attestation evidence over the measured state.
type Attestor struct {
	mu        sync.Mutex
	ak        *client.Key
	akPubSPKI []byte
	measurer  *measure.Measurer
	tee       *TEE
	hpkePub   []byte
}

// New loads the attestation key of the given type. The TPM must be the same
// one the Measurer extends, or quotes will not cover the measurements.
// tee may be nil (no hardware report); hpkePub is the per-boot HPKE public
// key that Attest binds into the hardware report's REPORT_DATA.
func New(tpm io.ReadWriter, m *measure.Measurer, akType AKType, tee *TEE, hpkePub []byte) (*Attestor, error) {
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
	spki, err := x509.MarshalPKIXPublicKey(ak.PublicKey())
	if err != nil {
		ak.Close()
		return nil, fmt.Errorf("encoding attestation public key: %w", err)
	}
	return &Attestor{ak: ak, akPubSPKI: spki, measurer: m, tee: tee, hpkePub: hpkePub}, nil
}

// AKPubSPKI returns the PKIX/DER encoding of the attestation public key —
// one of the transcript inputs shared with provision.Receiver.Accept.
func (a *Attestor) AKPubSPKI() []byte { return a.akPubSPKI }

// TEEKind reports which hardware report device the evidence uses.
func (a *Attestor) TEEKind() TEEKind {
	if a.tee == nil {
		return TEENone
	}
	return a.tee.Kind
}

// Attest returns evidence bound to the given nonce: quotes over all PCR
// banks, the TCG boot log, the canonical event log, the AK certificate
// chain when one exists, and — when a TEE device is present — a hardware
// attestation report whose REPORT_DATA is the provisioning transcript
// (binding nonce, AK, and HPKE key to genuine confidential hardware).
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

	opts := client.AttestOpts{
		Nonce:            nonce,
		CertChainFetcher: http.DefaultClient,
	}
	if a.tee != nil {
		transcript := provision.Transcript(nonce, a.akPubSPKI, a.hpkePub)
		opts.TEEDevice = a.tee.Device
		opts.TEENonce = transcript[:]
	} else {
		// Suppress go-tpm-tools' best-effort TEE collection: an unbound
		// report (REPORT_DATA = padded nonce, no key binding) must not
		// appear in evidence where it could be mistaken for a bound one.
		opts.SkipTeeAttestation = true
	}
	att, err := a.ak.Attest(opts)
	if err != nil {
		return nil, fmt.Errorf("generating attestation: %w", err)
	}
	att.CanonicalEventLog = celBytes
	return att, nil
}

// Close releases the attestation key and TEE device (not the underlying TPM).
func (a *Attestor) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ak.Close()
	if a.tee != nil && a.tee.Device != nil {
		a.tee.Device.Close()
	}
}
