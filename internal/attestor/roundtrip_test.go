//go:build cgo

// Full local roundtrip: provision an encrypted workload onto a simulated
// TPM + fake SEV-SNP device, measure its commitment, generate attestation
// evidence, and verify it end to end (dev-mode AK trust anchor, test-only
// AMD roots). Everything except the Google AK certificate chain and the
// real AMD certificate chain is exercised here; those final links require a
// real GCE Confidential VM.
package attestor_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sgabi "github.com/google/go-sev-guest/abi"
	sgtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"
	sevverify "github.com/google/go-sev-guest/verify"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/testutil"

	attestpb "github.com/google/go-tpm-tools/proto/attest"

	"github.com/davidcao20/gc-tee-base/internal/attestor"
	"github.com/davidcao20/gc-tee-base/internal/measure"
	"github.com/davidcao20/gc-tee-base/internal/provision"
	"github.com/davidcao20/gc-tee-base/internal/spec"
	"github.com/davidcao20/gc-tee-base/internal/verify"
	"github.com/davidcao20/gc-tee-base/internal/wire"
)

// fakeSNPDevice implements client.TEEDevice: it produces SNP reports with
// the requested REPORT_DATA, signed by a test-only AMD cert chain.
type fakeSNPDevice struct {
	signer *sgtest.AmdSigner
	certs  []byte
	debug  bool // set the forbidden debug policy bit
}

func newFakeSNPDevice(t *testing.T) *fakeSNPDevice {
	t.Helper()
	signer, err := sgtest.DefaultTestOnlyCertChain(sgtest.GetProductName(), time.Now())
	if err != nil {
		t.Fatalf("creating test AMD cert chain: %v", err)
	}
	certs, err := signer.CertTableBytes()
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSNPDevice{signer: signer, certs: certs}
}

func (d *fakeSNPDevice) AddAttestation(att *attestpb.Attestation, opts client.AttestOpts) error {
	var reportData [64]byte
	copy(reportData[:], opts.TEENonce)
	raw := sgtest.CreateRawReport(&sgtest.TestReportOptions{ReportData: reportData[:]})
	report := raw[:sgabi.ReportSize]
	// CreateRawReport sets the debug policy bit; our verifier forbids it.
	binary.LittleEndian.PutUint64(report[0x08:0x10], sgabi.SnpPolicyToBytes(sgabi.SnpPolicy{SMT: true, Debug: d.debug}))
	r, s, err := d.signer.Sign(sgabi.SignedComponent(report))
	if err != nil {
		return err
	}
	if err := sgabi.SetSignature(r, s, report); err != nil {
		return err
	}
	snp, err := sgabi.ReportCertsToProto(append(append([]byte{}, report...), d.certs...))
	if err != nil {
		return err
	}
	att.TeeAttestation = &attestpb.Attestation_SevSnpAttestation{SevSnpAttestation: snp}
	return nil
}

func (d *fakeSNPDevice) Close() error { return nil }

// snpTestVerifyOpts trusts the fake signer's roots instead of AMD's.
func snpTestVerifyOpts(t *testing.T, d *fakeSNPDevice) *sevverify.Options {
	t.Helper()
	roots := map[string][]*trust.AMDRootCerts{
		sgtest.GetProductLine(): {{
			ProductLine: sgtest.GetProductLine(),
			ProductCerts: &trust.ProductCerts{
				Ark:  d.signer.Ark,
				Ask:  d.signer.Ask,
				Asvk: d.signer.Asvk,
			},
		}},
	}
	return &sevverify.Options{
		TrustedRoots:        roots,
		Product:             sgtest.GetProduct(t),
		DisableCertFetching: true,
		Now:                 time.Now(),
	}
}

// setup builds a launcher-side stack. withTEE controls whether evidence
// carries a (fake) hardware report.
type stack struct {
	measurer *measure.Measurer
	attestor *attestor.Attestor
	receiver *provision.Receiver
	server   *attestor.Server
	ts       *httptest.Server
	trusted  []crypto.PublicKey
	snpDev   *fakeSNPDevice
}

func setup(t *testing.T, withTEE bool) *stack {
	t.Helper()
	tpm := testutil.GetTPM(t)
	t.Cleanup(func() { client.CheckedClose(t, tpm) })

	m, err := measure.New(tpm)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := provision.NewReceiver()
	if err != nil {
		t.Fatal(err)
	}

	var tee *attestor.TEE
	var snpDev *fakeSNPDevice
	if withTEE {
		snpDev = newFakeSNPDevice(t)
		tee = &attestor.TEE{Device: snpDev, Kind: attestor.TEESevSnp}
	}
	a, err := attestor.New(tpm, m, attestor.AKOwnerECC, tee, receiver.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	// The verifier trusts the owner-hierarchy AK directly (dev mode).
	ak, err := client.AttestationKeyECC(tpm)
	if err != nil {
		t.Fatal(err)
	}
	pub := ak.PublicKey()
	ak.Close()

	srv := attestor.NewServer("127.0.0.1:0", a, receiver, func() attestor.Status {
		return attestor.Status{ContainerState: "provisioning"}
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &stack{
		measurer: m, attestor: a, receiver: receiver, server: srv, ts: ts,
		trusted: []crypto.PublicKey{pub}, snpDev: snpDev,
	}
}

func freshNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

func fetchEnvelope(t *testing.T, ts *httptest.Server, nonce []byte) (*wire.Envelope, *attestpb.Attestation) {
	t.Helper()
	resp, err := http.Get(ts.URL + "/v1/attestation?nonce=" + hex.EncodeToString(nonce))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attestation endpoint returned %s: %s", resp.Status, body)
	}
	env, att, err := wire.DecodeEnvelope(body)
	if err != nil {
		t.Fatal(err)
	}
	return env, att
}

func postWorkload(t *testing.T, ts *httptest.Server, nonce, ciphertext []byte) *http.Response {
	t.Helper()
	body, err := json.Marshal(attestor.WorkloadRequest{Nonce: nonce, Ciphertext: ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/v1/workload", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestProvisionRoundtrip walks the full two-stage flow: verify a fresh VM
// (hardware-bound key, nothing measured), deliver an encrypted payload,
// measure its commitment, and verify the running state post-launch.
func TestProvisionRoundtrip(t *testing.T) {
	s := setup(t, true)

	policy := verify.Policy{Hardware: &verify.HardwarePolicy{Require: true}}

	// Stage 1: verify the fresh base layer.
	nonce := freshNonce(t)
	env, att := fetchEnvelope(t, s.ts, nonce)
	if env.TEEKind != string(attestor.TEESevSnp) {
		t.Fatalf("envelope teeKind = %q", env.TEEKind)
	}
	opts := verify.Options{
		Nonce:            nonce,
		TrustedAKs:       s.trusted,
		HPKEPublicKey:    env.HPKEPublicKey,
		SNPVerifyOptions: snpTestVerifyOpts(t, s.snpDev),
	}
	result, err := verify.Verify(att, opts)
	if err != nil {
		t.Fatalf("stage-1 Verify: %v", err)
	}
	if result.TEE == nil || !result.TEE.ReportDataBound {
		t.Fatalf("hardware report missing or unbound: %+v", result.TEE)
	}
	if err := result.CheckUnprovisioned(); err != nil {
		t.Fatalf("CheckUnprovisioned: %v", err)
	}
	if v := policy.EvaluateBase(result); len(v) != 0 {
		t.Fatalf("base policy violations: %v", v)
	}

	// Stage 2: seal the payload to the attested key.
	plaintext, err := provision.EncodePayload(&provision.Payload{
		LaunchSpec: spec.LaunchSpec{
			ImageRef: "docker.io/library/busybox@sha256:aaaa",
			Envs:     map[string]string{"SECRET": "hunter2"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	commitment := provision.Commitment(plaintext)
	transcript := provision.Transcript(nonce, result.AKPubSPKI, env.HPKEPublicKey)
	ciphertext, err := provision.Seal(env.HPKEPublicKey, transcript, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	resp := postWorkload(t, s.ts, nonce, ciphertext)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/workload returned %s: %s", resp.Status, body)
	}
	var ack attestor.WorkloadResponse
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		t.Fatal(err)
	}
	if ack.Commitment != hex.EncodeToString(commitment) {
		t.Fatalf("ack commitment = %s, want %s", ack.Commitment, hex.EncodeToString(commitment))
	}

	// Launcher side: receive, decode, measure, seal.
	var received []byte
	select {
	case received = <-s.server.Payloads():
	default:
		t.Fatal("no payload delivered on Payloads()")
	}
	payload, err := provision.DecodePayload(received)
	if err != nil {
		t.Fatal(err)
	}
	if payload.ImageRef != "docker.io/library/busybox@sha256:aaaa" || payload.Envs["SECRET"] != "hunter2" {
		t.Fatalf("payload roundtrip mismatch: %+v", payload)
	}
	if err := s.measurer.MeasureCommitment(provision.Commitment(received)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.measurer.Seal(); err != nil {
		t.Fatal(err)
	}

	// A second payload must be rejected even if well-formed.
	resp2 := postWorkload(t, s.ts, nonce, ciphertext)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("second POST returned %d, want 409", resp2.StatusCode)
	}

	// Garbage ciphertext is rejected.
	resp3 := postWorkload(t, s.ts, nonce, []byte("not a ciphertext but long enough to parse"))
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest && resp3.StatusCode != http.StatusConflict {
		t.Errorf("garbage POST returned %d, want 400/409", resp3.StatusCode)
	}

	// Post-launch verification with a fresh nonce.
	nonce2 := freshNonce(t)
	env2, att2 := fetchEnvelope(t, s.ts, nonce2)
	opts2 := opts
	opts2.Nonce = nonce2
	opts2.HPKEPublicKey = env2.HPKEPublicKey
	result2, err := verify.Verify(att2, opts2)
	if err != nil {
		t.Fatalf("post-launch Verify: %v", err)
	}
	if got := result2.Claims.WorkloadCommitment; got != hex.EncodeToString(commitment) {
		t.Fatalf("verified commitment = %s, want %s", got, hex.EncodeToString(commitment))
	}
	full := policy
	full.WorkloadCommitment = hex.EncodeToString(commitment)
	if v := full.Evaluate(result2); len(v) != 0 {
		t.Fatalf("post-launch policy violations: %v", v)
	}
	if err := result2.CheckUnprovisioned(); err == nil {
		t.Error("CheckUnprovisioned passed on a provisioned VM")
	}

	// A wrong commitment fails.
	wrong := policy
	wrong.WorkloadCommitment = strings.Repeat("00", 32)
	if v := wrong.Evaluate(result2); len(v) == 0 {
		t.Error("wrong commitment passed the policy")
	}
}

// TestSNPDebugPolicyRejected: a report whose guest policy permits debug
// access (host-readable memory) must fail verification outright.
func TestSNPDebugPolicyRejected(t *testing.T) {
	s := setup(t, true)
	s.snpDev.debug = true

	nonce := freshNonce(t)
	env, att := fetchEnvelope(t, s.ts, nonce)
	opts := verify.Options{
		Nonce:            nonce,
		TrustedAKs:       s.trusted,
		HPKEPublicKey:    env.HPKEPublicKey,
		SNPVerifyOptions: snpTestVerifyOpts(t, s.snpDev),
	}
	if _, err := verify.Verify(att, opts); err == nil {
		t.Error("evidence with SNP debug policy verified, want error")
	}
}

// TestSNPReportDataBinding: evidence whose hardware report was produced for
// different transcript inputs (e.g. a different HPKE key) must fail.
func TestSNPReportDataBinding(t *testing.T) {
	s := setup(t, true)

	nonce := freshNonce(t)
	env, att := fetchEnvelope(t, s.ts, nonce)

	otherReceiver, err := provision.NewReceiver()
	if err != nil {
		t.Fatal(err)
	}
	opts := verify.Options{
		Nonce:            nonce,
		TrustedAKs:       s.trusted,
		HPKEPublicKey:    otherReceiver.PublicKey(), // not the attested key
		SNPVerifyOptions: snpTestVerifyOpts(t, s.snpDev),
	}
	if _, err := verify.Verify(att, opts); err == nil {
		t.Error("evidence verified against a substituted HPKE key, want error")
	}
	_ = env
}

// TestPayloadBoundToReceiver: a ciphertext sealed for one VM cannot be
// accepted by another (different per-boot key).
func TestPayloadBoundToReceiver(t *testing.T) {
	s := setup(t, false)

	nonce := freshNonce(t)
	env, att := fetchEnvelope(t, s.ts, nonce)
	result, err := verify.Verify(att, verify.Options{
		Nonce: nonce, TrustedAKs: s.trusted, HPKEPublicKey: env.HPKEPublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := provision.EncodePayload(&provision.Payload{
		LaunchSpec: spec.LaunchSpec{ImageRef: "docker.io/library/busybox@sha256:aaaa"},
	})
	if err != nil {
		t.Fatal(err)
	}
	transcript := provision.Transcript(nonce, result.AKPubSPKI, env.HPKEPublicKey)
	ciphertext, err := provision.Seal(env.HPKEPublicKey, transcript, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	other, err := provision.NewReceiver()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Accept(nonce, s.attestor.AKPubSPKI(), ciphertext); err == nil {
		t.Error("a different receiver decrypted the payload, want error")
	}
	if _, err := s.receiver.Accept(nonce, s.attestor.AKPubSPKI(), ciphertext); err != nil {
		t.Errorf("the attested receiver rejected its own payload: %v", err)
	}
}

func TestAttestVerifyNoTEE(t *testing.T) {
	s := setup(t, false)
	nonce := freshNonce(t)

	env, att := fetchEnvelope(t, s.ts, nonce)
	result, err := verify.Verify(att, verify.Options{
		Nonce: nonce, TrustedAKs: s.trusted, HPKEPublicKey: env.HPKEPublicKey,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.TEE != nil {
		t.Errorf("unexpected TEE result without a device: %+v", result.TEE)
	}
	// Policy requiring hardware must fail this evidence.
	p := verify.Policy{Hardware: &verify.HardwarePolicy{Require: true}}
	if v := p.EvaluateBase(result); len(v) == 0 {
		t.Error("hardware.require passed without a hardware report")
	}
}

func TestWrongNonceFails(t *testing.T) {
	s := setup(t, false)

	_, att := fetchEnvelope(t, s.ts, freshNonce(t))
	if _, err := verify.Verify(att, verify.Options{Nonce: freshNonce(t), TrustedAKs: s.trusted}); err == nil {
		t.Error("verification with wrong nonce succeeded, want error")
	}
}

func TestTamperedCELFails(t *testing.T) {
	s := setup(t, false)
	if err := s.measurer.MeasureCommitment(provision.Commitment([]byte("payload"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.measurer.Seal(); err != nil {
		t.Fatal(err)
	}
	nonce := freshNonce(t)
	_, att := fetchEnvelope(t, s.ts, nonce)
	att.CanonicalEventLog[len(att.CanonicalEventLog)-1] ^= 0x01
	if _, err := verify.Verify(att, verify.Options{Nonce: nonce, TrustedAKs: s.trusted}); err == nil {
		t.Error("verification of tampered CEL succeeded, want error")
	}
}

func TestUntrustedAKFails(t *testing.T) {
	tpm := testutil.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	m, err := measure.New(tpm)
	if err != nil {
		t.Fatal(err)
	}
	a, err := attestor.New(tpm, m, attestor.AKOwnerECC, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	nonce := freshNonce(t)
	att, err := a.Attest(nonce)
	if err != nil {
		t.Fatal(err)
	}
	// Trust a different key (the RSA AK) than the one that signed.
	other, err := client.AttestationKeyRSA(tpm)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	opts := verify.Options{Nonce: nonce, TrustedAKs: []crypto.PublicKey{other.PublicKey()}}
	if _, err := verify.Verify(att, opts); err == nil {
		t.Error("verification with untrusted AK succeeded, want error")
	}
}

func TestHTTPBadNonces(t *testing.T) {
	s := setup(t, false)
	for _, bad := range []string{"", "zz", "abcd"} {
		resp, err := http.Get(s.ts.URL + "/v1/attestation?nonce=" + bad)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("nonce %q: got status %d, want 400", bad, resp.StatusCode)
		}
	}

	// Status endpoint responds and carries no workload details.
	sresp, err := http.Get(s.ts.URL + "/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer sresp.Body.Close()
	if sresp.StatusCode != http.StatusOK {
		t.Errorf("status endpoint returned %d", sresp.StatusCode)
	}
	var status attestor.Status
	if err := json.NewDecoder(sresp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.ContainerState != "provisioning" {
		t.Errorf("status = %+v", status)
	}
}
