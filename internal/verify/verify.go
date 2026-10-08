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

	sevverify "github.com/google/go-sev-guest/verify"
	tdxverify "github.com/google/go-tdx-guest/verify"
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

	// HPKEPublicKey is the per-boot HPKE public key from the evidence
	// envelope. Required to check a hardware report's REPORT_DATA binding
	// (it is a transcript input).
	HPKEPublicKey []byte

	// SNPProductLine ("Milan", "Genoa", ...) selects the AMD cert-chain
	// roots when the SNP report itself does not identify the product
	// (report version 2). Leave empty to use go-sev-guest's default.
	SNPProductLine string

	// SNPVerifyOptions overrides the full SNP chain-verification options.
	// Tests use it to inject fake AMD roots; production leaves it nil.
	SNPVerifyOptions *sevverify.Options

	// TDXVerifyOptions overrides the TDX chain-verification options. Tests
	// use it to pin validation times for canned quotes; production leaves
	// it nil (embedded Intel roots, current time).
	TDXVerifyOptions *tdxverify.Options
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
	// TEE is the verified hardware attestation report (AMD-rooted), or nil
	// when the evidence carries none. Policy decides whether nil passes.
	TEE *TEEResult
	// AKPubSPKI is the PKIX/DER encoding of the trusted AK public key — a
	// transcript input the provisioner needs for sealing a payload.
	AKPubSPKI []byte
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
		// Not server.GceEKRoots: that exports the legacy EK root, which
		// modern GCE AK certs do not chain to (see roots.go).
		vopts.TrustedRootCerts = GceAKRoots
		vopts.IntermediateCerts = GceAKIntermediates
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

	akPubSPKI, err := x509.MarshalPKIXPublicKey(akPub)
	if err != nil {
		return nil, fmt.Errorf("encoding trusted AK public key: %w", err)
	}
	tee, err := verifyTEE(att, akPubSPKI, opts)
	if err != nil {
		return nil, fmt.Errorf("hardware report verification failed: %w", err)
	}

	return &Result{MachineState: machineState, Claims: claims, PCRs: pcrs, TEE: tee, AKPubSPKI: akPubSPKI}, nil
}

// CheckUnprovisioned confirms the evidence describes a fresh base layer: no
// workload claims and PCR 13 still zero in every verified bank. Run it
// before encrypting a payload to the evidence's HPKE key.
func (r *Result) CheckUnprovisioned() error {
	if r.Claims.Provisioned {
		return fmt.Errorf("a workload was already provisioned (commitment %s)", r.Claims.WorkloadCommitment)
	}
	for bank, values := range r.PCRs {
		digest, ok := values[13]
		if !ok {
			continue
		}
		for _, b := range digest {
			if b != 0 {
				return fmt.Errorf("PCR 13 (%s bank) is nonzero (%x): something was measured on this VM already",
					bank, digest)
			}
		}
	}
	return nil
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
