package verify

import (
	"strings"
	"testing"
	"time"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/testing/testdata"
	tdxverify "github.com/google/go-tdx-guest/verify"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

// cannedQuote returns go-tdx-guest's test fixture: a real Intel-signed TDX
// quote (REPORT_DATA = 63 zero bytes then 0x01). Its certificates are only
// valid around mid-2023, so chain verification pins that time.
func cannedQuote(t *testing.T) *tdxpb.QuoteV4 {
	t.Helper()
	q, err := tdxabi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	quote, ok := q.(*tdxpb.QuoteV4)
	if !ok {
		t.Fatalf("fixture quote is %T, want *QuoteV4", q)
	}
	return quote
}

func cannedQuoteVerifyOptions() *tdxverify.Options {
	fixtureTime := time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)
	return &tdxverify.Options{
		Now: &tdxverify.TimeSet{
			PckCertChain: fixtureTime,
			TcbInfo:      fixtureTime,
			QeIdentity:   fixtureTime,
			PckCrl:       fixtureTime,
			RootCaCrl:    fixtureTime,
		},
	}
}

// TestTDXChainVerifiesAndBindingEnforced: the Intel signature chain of the
// canned quote must verify (embedded Intel roots), and then the REPORT_DATA
// binding must fail — our transcript cannot equal the fixture's canned
// REPORT_DATA, which is exactly the enforcement we want to see. A chain
// error instead would mean the plumbing is wrong.
func TestTDXChainVerifiesAndBindingEnforced(t *testing.T) {
	att := &attestpb.Attestation{
		TeeAttestation: &attestpb.Attestation_TdxAttestation{TdxAttestation: cannedQuote(t)},
	}
	_, err := verifyTEE(att, []byte("ak-spki"), Options{
		Nonce:            []byte("0123456789abcdef0123456789abcdef"),
		TDXVerifyOptions: cannedQuoteVerifyOptions(),
	})
	if err == nil {
		t.Fatal("fixture quote verified against our transcript, want REPORT_DATA mismatch")
	}
	if !strings.Contains(err.Error(), "REPORT_DATA") {
		t.Fatalf("expected a REPORT_DATA binding failure (after a successful chain verification), got: %v", err)
	}
}

// TestTDXDebugAttributeRejected: a quote whose TD_ATTRIBUTES has the DEBUG
// bit set must be rejected before anything else is considered.
func TestTDXDebugAttributeRejected(t *testing.T) {
	quote := cannedQuote(t)
	attrs := append([]byte{}, quote.GetTdQuoteBody().GetTdAttributes()...)
	attrs[0] |= 0x01
	quote.TdQuoteBody.TdAttributes = attrs
	att := &attestpb.Attestation{
		TeeAttestation: &attestpb.Attestation_TdxAttestation{TdxAttestation: quote},
	}
	_, err := verifyTEE(att, []byte("ak-spki"), Options{
		Nonce:            []byte("0123456789abcdef0123456789abcdef"),
		TDXVerifyOptions: cannedQuoteVerifyOptions(),
	})
	if err == nil || !strings.Contains(err.Error(), "DEBUG") {
		t.Fatalf("debuggable TD not rejected: %v", err)
	}
}

// TestTDXExpiredChainRejected: default (current-time) options must reject
// the 2023 fixture chain — stale collateral does not verify.
func TestTDXExpiredChainRejected(t *testing.T) {
	att := &attestpb.Attestation{
		TeeAttestation: &attestpb.Attestation_TdxAttestation{TdxAttestation: cannedQuote(t)},
	}
	_, err := verifyTEE(att, []byte("ak-spki"), Options{
		Nonce: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err == nil {
		t.Fatal("expired fixture chain verified with current-time options")
	}
}

func tdxResult() *Result {
	r := passingResult()
	r.TEE = &TEEResult{
		Kind:        string(TEEKindTdx),
		Measurement: strings.Repeat("ab", 48),
		RTMRs: []string{
			strings.Repeat("00", 48),
			strings.Repeat("11", 48),
			strings.Repeat("22", 48),
			strings.Repeat("33", 48),
		},
		ReportDataBound: true,
	}
	return r
}

func TestTDXPolicyPins(t *testing.T) {
	pass := Policy{WorkloadCommitment: testCommitmentHex, Hardware: &HardwarePolicy{
		Require: true,
		TDX: &TDXPolicy{
			MrTd:  strings.Repeat("AB", 48), // case-insensitive
			Rtmrs: map[int]string{1: strings.Repeat("11", 48), 2: strings.Repeat("22", 48)},
		},
	}}
	if v := pass.Evaluate(tdxResult()); len(v) != 0 {
		t.Errorf("expected pass, got: %v", v)
	}

	wrongMrTd := Policy{WorkloadCommitment: testCommitmentHex, Hardware: &HardwarePolicy{
		TDX: &TDXPolicy{MrTd: strings.Repeat("ff", 48)},
	}}
	if v := wrongMrTd.Evaluate(tdxResult()); len(v) == 0 {
		t.Error("wrong MRTD passed")
	}

	wrongRtmr := Policy{WorkloadCommitment: testCommitmentHex, Hardware: &HardwarePolicy{
		TDX: &TDXPolicy{Rtmrs: map[int]string{1: strings.Repeat("ff", 48)}},
	}}
	if v := wrongRtmr.Evaluate(tdxResult()); len(v) == 0 {
		t.Error("wrong RTMR passed")
	}

	missingRtmr := Policy{WorkloadCommitment: testCommitmentHex, Hardware: &HardwarePolicy{
		TDX: &TDXPolicy{Rtmrs: map[int]string{7: strings.Repeat("11", 48)}},
	}}
	if v := missingRtmr.Evaluate(tdxResult()); len(v) == 0 {
		t.Error("out-of-range RTMR index passed")
	}
}

// TestHardwareKindDowngradeRejected: a policy that configures one
// technology must not be satisfiable by evidence from the other (its pins
// would silently not apply).
func TestHardwareKindDowngradeRejected(t *testing.T) {
	tdxOnly := Policy{WorkloadCommitment: testCommitmentHex, Hardware: &HardwarePolicy{
		TDX: &TDXPolicy{Rtmrs: map[int]string{1: strings.Repeat("11", 48)}},
	}}
	snpEvidence := passingResult() // TEE.Kind == sev-snp
	if v := tdxOnly.Evaluate(snpEvidence); len(v) == 0 {
		t.Error("TDX-only policy accepted SNP evidence")
	}

	snpOnly := Policy{WorkloadCommitment: testCommitmentHex, Hardware: &HardwarePolicy{
		SNP: &SNPPolicy{},
	}}
	if v := snpOnly.Evaluate(tdxResult()); len(v) == 0 {
		t.Error("SNP-only policy accepted TDX evidence")
	}

	both := Policy{WorkloadCommitment: testCommitmentHex, Hardware: &HardwarePolicy{
		TDX: &TDXPolicy{},
		SNP: &SNPPolicy{},
	}}
	if v := both.Evaluate(tdxResult()); len(v) != 0 {
		t.Errorf("both-technologies policy rejected TDX evidence: %v", v)
	}
	if v := both.Evaluate(passingResult()); len(v) != 0 {
		t.Errorf("both-technologies policy rejected SNP evidence: %v", v)
	}

	neither := Policy{WorkloadCommitment: testCommitmentHex, Hardware: &HardwarePolicy{Require: true}}
	if v := neither.Evaluate(tdxResult()); len(v) != 0 {
		t.Errorf("kind-agnostic policy rejected TDX evidence: %v", v)
	}
}
