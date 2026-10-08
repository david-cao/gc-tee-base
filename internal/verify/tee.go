// Hardware attestation-report verification: the part of the trust chain
// that roots in the CPU vendor rather than in Google.
//
// For Intel TDX the quote is signed via Intel's provisioning chain (PCK →
// Intel SGX Root CA); for AMD SEV-SNP the report chains to AMD's fused
// root keys (VCEK → ASK → ARK). Either way the signature is one the cloud
// operator cannot forge. The report's REPORT_DATA carries the provisioning
// transcript, binding the verifier's nonce, the vTPM attestation key, and
// the per-boot HPKE public key to genuine confidential hardware.
//
// What the hardware measurement covers differs by technology. On GCE:
//   - SNP: MEASUREMENT is the launch digest of Google's UEFI firmware only;
//     our base image appears solely in the (Google-rooted) vTPM PCRs.
//   - TDX: MRTD covers Google's TD firmware, and the firmware additionally
//     extends the RTMRs at runtime with the boot chain it loads — per
//     Google's documentation RTMR[1]/[2] cover the bootloader (our UKI) and
//     kernel/cmdline. RTMRs ride inside the Intel-signed quote, so TDX can
//     carry base-image identity under the hardware root (pin via policy
//     hardware.tdx.rtmrs after calibrating the values for an image build).
package verify

import (
	"encoding/hex"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevvalidate "github.com/google/go-sev-guest/validate"
	sevverify "github.com/google/go-sev-guest/verify"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxvalidate "github.com/google/go-tdx-guest/validate"
	tdxverify "github.com/google/go-tdx-guest/verify"

	attestpb "github.com/google/go-tpm-tools/proto/attest"

	"github.com/davidcao20/gc-tee-base/internal/provision"
)

// TEEResult is a successfully verified hardware attestation report.
type TEEResult struct {
	// Kind is the report source: "tdx" or "sev-snp".
	Kind string `json:"kind"`
	// Measurement is the hex launch measurement from the report: MRTD for
	// TDX, MEASUREMENT for SNP — on GCE both measure Google's guest
	// firmware (pin via policy hardware.{tdx.mrTd,snp.measurement}; Google
	// publishes signed endorsements for these values).
	Measurement string `json:"measurement"`
	// RTMRs are the hex runtime measurement registers (TDX only): values
	// the guest firmware extended after launch, carried in the Intel-signed
	// quote. RTMR[1]/[2] cover the boot chain on GCE.
	RTMRs []string `json:"rtmrs,omitempty"`
	// ReportDataBound records that REPORT_DATA equaled the provisioning
	// transcript (nonce + AK + HPKE key). Always true on success.
	ReportDataBound bool `json:"reportDataBound"`
}

// snpGuestPolicyMax is the most permissive SNP guest policy we accept:
// debug and migration-agent capability are forbidden (either would let the
// host read guest memory), SMT is allowed (GCE runs with SMT; SMT side
// channels are out of scope for this trust model).
var snpGuestPolicyMax = abi.SnpPolicy{SMT: true}

// verifyTEE checks the hardware attestation report inside the evidence, if
// any. Returns (nil, nil) when the evidence carries no report — policy
// decides whether that is acceptable. A report that is present but does not
// verify is an error: evidence with a bad hardware report is not
// trustworthy. akPubSPKI and opts supply the transcript inputs.
func verifyTEE(att *attestpb.Attestation, akPubSPKI []byte, opts Options) (*TEEResult, error) {
	// An empty HPKEPublicKey is legitimate for -spec (dev) launchers: the
	// report is then bound to nonce+AK only, and both sides compute the
	// transcript over an empty key field. Any mismatch — including a
	// missing key that the report was actually bound to — fails the
	// REPORT_DATA check.
	transcript := provision.Transcript(opts.Nonce, akPubSPKI, opts.HPKEPublicKey)

	if tdx := att.GetTdxAttestation(); tdx != nil {
		return verifyTDX(tdx, transcript, opts)
	}
	if snp := att.GetSevSnpAttestation(); snp != nil {
		return verifySNP(snp, transcript, opts)
	}
	return nil, nil
}

// verifyTDX checks an Intel TDX quote: signature chain to Intel's root,
// debug attribute forbidden, and the REPORT_DATA transcript binding.
func verifyTDX(quote *tdxpb.QuoteV4, transcript [64]byte, opts Options) (*TEEResult, error) {
	// TD_ATTRIBUTES bit 0 (TUD.DEBUG) makes the TD debuggable by the host.
	// go-tdx-guest's validator only supports exact-match on the whole
	// attributes field, so check the one security-critical bit directly
	// (before the more expensive chain verification; every check must pass
	// regardless of order).
	attrs := quote.GetTdQuoteBody().GetTdAttributes()
	if len(attrs) != 8 {
		return nil, fmt.Errorf("TDX quote has malformed TD_ATTRIBUTES (%d bytes)", len(attrs))
	}
	if attrs[0]&0x01 != 0 {
		return nil, fmt.Errorf("TD_ATTRIBUTES has the DEBUG bit set: the host can inspect this TD")
	}

	// Signature chain: quote (ECDSA-P256 by the QE attestation key, itself
	// vouched by the QE report) → PCK certificate → Intel SGX Root CA. The
	// PCK chain travels inside the quote; roots default to go-tdx-guest's
	// embedded Intel root certificate. Tests inject fixed validation times
	// via TDXVerifyOptions; TCB/QE-identity collateral fetching from Intel
	// PCS is deliberately not enabled by default (network dependency) —
	// TCB floors belong to user policy.
	vopts := opts.TDXVerifyOptions
	if vopts == nil {
		vopts = tdxverify.DefaultOptions()
	}
	if err := tdxverify.TdxQuote(quote, vopts); err != nil {
		return nil, fmt.Errorf("TDX quote does not chain to the Intel root of trust: %w", err)
	}

	err := tdxvalidate.TdxQuote(quote, &tdxvalidate.Options{
		TdQuoteBodyOptions: tdxvalidate.TdQuoteBodyOptions{
			ReportData: transcript[:],
		},
	})
	if err != nil {
		return nil, fmt.Errorf("TDX quote validation failed: %w", err)
	}

	body := quote.GetTdQuoteBody()
	rtmrs := make([]string, 0, len(body.GetRtmrs()))
	for _, r := range body.GetRtmrs() {
		rtmrs = append(rtmrs, hex.EncodeToString(r))
	}
	return &TEEResult{
		Kind:            string(TEEKindTdx),
		Measurement:     hex.EncodeToString(body.GetMrTd()),
		RTMRs:           rtmrs,
		ReportDataBound: true,
	}, nil
}

// verifySNP checks an AMD SEV-SNP report: signature chain to AMD's root,
// guest policy, and the REPORT_DATA transcript binding.
func verifySNP(snp *spb.Attestation, transcript [64]byte, opts Options) (*TEEResult, error) {
	// Signature chain: VCEK/VLEK → ASK → ARK. Roots default to go-sev-guest's
	// embedded AMD certificates; tests inject fakes via SNPVerifyOptions.
	vopts := opts.SNPVerifyOptions
	if vopts == nil {
		vopts = sevverify.DefaultOptions()
		if opts.SNPProductLine != "" {
			product, err := kds.ParseProductLine(opts.SNPProductLine)
			if err != nil {
				return nil, fmt.Errorf("invalid SNP product line %q: %w", opts.SNPProductLine, err)
			}
			vopts.Product = product
		}
	}
	if err := sevverify.SnpAttestation(snp, vopts); err != nil {
		return nil, fmt.Errorf("SEV-SNP report does not chain to the AMD root of trust: %w", err)
	}

	// Field validation: REPORT_DATA must equal the transcript (the
	// hardware-rooted binding of nonce, AK, and HPKE key), and the guest
	// policy must not permit debug access or migration.
	// PermitProvisionalFirmware: GCE hosts may run firmware whose current
	// TCB is ahead of the committed TCB; TCB floors belong to user policy.
	err := sevvalidate.SnpAttestation(snp, &sevvalidate.Options{
		ReportData:                transcript[:],
		GuestPolicy:               snpGuestPolicyMax,
		PermitProvisionalFirmware: true,
	})
	if err != nil {
		return nil, fmt.Errorf("SEV-SNP report validation failed: %w", err)
	}

	return &TEEResult{
		Kind:            string(TEEKindSevSnp),
		Measurement:     hex.EncodeToString(snp.GetReport().GetMeasurement()),
		ReportDataBound: true,
	}, nil
}

// TEEKind mirrors attestor.TEEKind without importing the launcher side.
type TEEKind string

const (
	TEEKindSevSnp TEEKind = "sev-snp"
	TEEKindTdx    TEEKind = "tdx"
)
