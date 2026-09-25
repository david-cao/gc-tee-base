// Package verify checks attestation evidence produced by the launcher.
//
// Trust chain: Google's GCE EK/AK CA roots (bundled in go-tpm-tools) → AK
// certificate → quote signature + nonce → TCG boot log replay (proves boot
// state and confidential technology) → canonical event log replay against
// PCR 13 → container identity claims → user policy.
package verify

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/google/go-tpm-tools/quote"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

// Options configures evidence verification.
type Options struct {
	// Nonce is the challenge the verifier sent; the quote must embed it.
	Nonce []byte

	// TrustedAKs, if non-empty, replaces the Google GCE root-of-trust with
	// directly trusted AK public keys. Development/simulator use only: it
	// proves nothing about where the TPM lives.
	TrustedAKs []crypto.PublicKey
}

// Result is successfully verified evidence.
type Result struct {
	// MachineState is the platform state from the AK cert and TCG boot log:
	// confidential technology, secure boot, GCE instance identity.
	MachineState *attestpb.MachineState
	// Claims is the container identity from the canonical event log.
	Claims *Claims
	// PCRs holds the quote-verified PCR values per bank ("sha1", "sha256",
	// ...): every value was covered by a quote signed by the trusted AK over
	// the caller's nonce. Used for golden-value pinning (e.g. PCR 4/11 of a
	// measured base image).
	PCRs map[string]map[int][]byte
}

// Verify runs the full pipeline on attestation evidence. On success, every
// field of the Result has been cryptographically tied to the vTPM quote and,
// unless Options.TrustedAKs was used, to Google's GCE CA.
func Verify(att *attestpb.Attestation, opts Options) (*Result, error) {
	if len(opts.Nonce) == 0 {
		return nil, fmt.Errorf("a nonce is required")
	}

	vopts := server.VerifyOpts{Nonce: opts.Nonce}
	if len(opts.TrustedAKs) > 0 {
		vopts.TrustedAKs = opts.TrustedAKs
	} else {
		vopts.TrustedRootCerts = server.GceEKRoots
		vopts.IntermediateCerts = server.GceEKIntermediates
	}

	machineState, err := server.VerifyAttestation(att, vopts)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	akPub, err := trustedAKPub(att, opts)
	if err != nil {
		return nil, err
	}
	claims, err := VerifiedClaims(att, akPub, opts.Nonce)
	if err != nil {
		return nil, fmt.Errorf("container claims verification failed: %w", err)
	}

	pcrs, err := verifiedPCRs(att, akPub, opts.Nonce)
	if err != nil {
		return nil, fmt.Errorf("PCR verification failed: %w", err)
	}

	return &Result{MachineState: machineState, Claims: claims, PCRs: pcrs}, nil
}

// verifiedPCRs checks every supported-bank quote against the trusted AK and
// nonce and returns the covered PCR values, keyed by bank name. A quote that
// fails verification is an error, not a skip: evidence containing a bad quote
// is not trustworthy.
func verifiedPCRs(att *attestpb.Attestation, akPub crypto.PublicKey, nonce []byte) (map[string]map[int][]byte, error) {
	pcrs := map[string]map[int][]byte{}
	for _, q := range att.GetQuotes() {
		alg := tpm2.Algorithm(q.GetPcrs().GetHash())
		bank, ok := bankName(alg)
		if !ok {
			continue // unsupported bank (e.g. SM3); nothing pins against it
		}
		if err := quote.Verify(q, akPub, nonce); err != nil {
			return nil, fmt.Errorf("quote over %s bank failed verification: %w", bank, err)
		}
		values := map[int][]byte{}
		for idx, digest := range q.GetPcrs().GetPcrs() {
			values[int(idx)] = digest
		}
		pcrs[bank] = values
	}
	if len(pcrs) == 0 {
		return nil, fmt.Errorf("attestation contains no quotes over supported PCR banks")
	}
	return pcrs, nil
}

func bankName(alg tpm2.Algorithm) (string, bool) {
	switch alg {
	case tpm2.AlgSHA1:
		return "sha1", true
	case tpm2.AlgSHA256:
		return "sha256", true
	case tpm2.AlgSHA384:
		return "sha384", true
	case tpm2.AlgSHA512:
		return "sha512", true
	default:
		return "", false
	}
}

// trustedAKPub returns the AK public key rooted in the configured trust
// anchor, mirroring how VerifyAttestation selects it: with root certs, the
// key comes from the (already chain-verified) AK certificate and the AkPub
// field is ignored; with TrustedAKs, AkPub was checked for equality against
// the trusted keys. Deriving the key the same way keeps the CEL quote
// re-verification anchored to the same root of trust.
func trustedAKPub(att *attestpb.Attestation, opts Options) (crypto.PublicKey, error) {
	if len(opts.TrustedAKs) == 0 && len(att.GetAkCert()) > 0 {
		akCert, err := x509.ParseCertificate(att.GetAkCert())
		if err != nil {
			return nil, fmt.Errorf("parsing AK certificate: %w", err)
		}
		return akCert.PublicKey, nil
	}
	pub, err := tpm2.DecodePublic(att.GetAkPub())
	if err != nil {
		return nil, fmt.Errorf("decoding AK public area: %w", err)
	}
	key, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("extracting AK public key: %w", err)
	}
	return key, nil
}
