//go:build cgo

// Full local roundtrip: measure into a simulated TPM, generate attestation
// evidence, and verify it end to end (dev-mode trust anchor). Everything
// except the Google AK certificate chain is exercised here; that final link
// requires a real GCE Confidential VM.
package attestor_test

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/testutil"

	"github.com/davidcao20/gc-tee-base/internal/attestor"
	"github.com/davidcao20/gc-tee-base/internal/measure"
	"github.com/davidcao20/gc-tee-base/internal/spec"
	"github.com/davidcao20/gc-tee-base/internal/verify"
	"github.com/davidcao20/gc-tee-base/internal/wire"
)

func setup(t *testing.T) (io.ReadWriteCloser, *attestor.Attestor, []crypto.PublicKey) {
	t.Helper()
	tpm := testutil.GetTPM(t)
	t.Cleanup(func() { client.CheckedClose(t, tpm) })

	m, err := measure.New(tpm)
	if err != nil {
		t.Fatal(err)
	}
	claims := measure.ContainerClaims{
		ImageRef:      "docker.io/library/busybox:latest",
		ImageDigest:   "sha256:aaaa",
		ImageID:       "sha256:bbbb",
		Args:          []string{"sh", "-c", "echo hi"},
		EnvVars:       []string{"PATH=/bin"},
		RestartPolicy: spec.RestartNever,
	}
	s := &spec.LaunchSpec{ImageRef: claims.ImageRef, Envs: map[string]string{"FOO": "bar"}}
	s.ApplyDefaults()
	if err := m.MeasureContainer(claims, s); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Seal(); err != nil {
		t.Fatal(err)
	}

	a, err := attestor.New(tpm, m, attestor.AKOwnerECC)
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

	return tpm, a, []crypto.PublicKey{pub}
}

func freshNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}

func TestAttestVerifyRoundtrip(t *testing.T) {
	_, a, trusted := setup(t)
	nonce := freshNonce(t)

	att, err := a.Attest(nonce)
	if err != nil {
		t.Fatal(err)
	}

	result, err := verify.Verify(att, verify.Options{Nonce: nonce, TrustedAKs: trusted})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	c := result.Claims
	if c.ImageDigest != "sha256:aaaa" {
		t.Errorf("ImageDigest = %q", c.ImageDigest)
	}
	if c.OverriddenEnvVars["FOO"] != "bar" {
		t.Errorf("OverriddenEnvVars = %v", c.OverriddenEnvVars)
	}
	if !c.SeparatorSeen {
		t.Error("SeparatorSeen = false")
	}

	policy := verify.Policy{ImageDigest: "sha256:aaaa", AllowedOverrideEnvs: []string{"FOO"}}
	if violations := policy.Evaluate(result); len(violations) != 0 {
		t.Errorf("policy violations: %v", violations)
	}

	// PCR pinning: the quoted values must satisfy a policy pinning them, and
	// a wrong pin must fail.
	sha256PCRs, ok := result.PCRs["sha256"]
	if !ok || len(sha256PCRs) == 0 {
		t.Fatalf("Result.PCRs has no sha256 bank: %v", result.PCRs)
	}
	pcr13, ok := sha256PCRs[13]
	if !ok {
		t.Fatal("quoted sha256 bank is missing PCR 13")
	}
	pinned := policy
	pinned.PCRs = &verify.PCRPolicy{Values: map[int]string{13: hex.EncodeToString(pcr13)}}
	if violations := pinned.Evaluate(result); len(violations) != 0 {
		t.Errorf("pinning the quoted PCR 13 failed: %v", violations)
	}
	wrongPin := policy
	wrongPin.PCRs = &verify.PCRPolicy{Values: map[int]string{13: "00"}}
	if violations := wrongPin.Evaluate(result); len(violations) == 0 {
		t.Error("pinning a wrong PCR 13 value passed")
	}
}

func TestWrongNonceFails(t *testing.T) {
	_, a, trusted := setup(t)

	att, err := a.Attest(freshNonce(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify.Verify(att, verify.Options{Nonce: freshNonce(t), TrustedAKs: trusted}); err == nil {
		t.Error("verification with wrong nonce succeeded, want error")
	}
}

func TestTamperedCELFails(t *testing.T) {
	_, a, trusted := setup(t)
	nonce := freshNonce(t)

	att, err := a.Attest(nonce)
	if err != nil {
		t.Fatal(err)
	}
	att.CanonicalEventLog[len(att.CanonicalEventLog)-1] ^= 0x01
	if _, err := verify.Verify(att, verify.Options{Nonce: nonce, TrustedAKs: trusted}); err == nil {
		t.Error("verification of tampered CEL succeeded, want error")
	}
}

func TestUntrustedAKFails(t *testing.T) {
	tpm, a, _ := setup(t)
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

func TestHTTPServer(t *testing.T) {
	_, a, trusted := setup(t)

	srv := attestor.NewServer("127.0.0.1:0", a, func() attestor.Status {
		return attestor.Status{ImageRef: "busybox", ContainerState: "running"}
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := freshNonce(t)
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
	att, err := wire.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify.Verify(att, verify.Options{Nonce: nonce, TrustedAKs: trusted}); err != nil {
		t.Fatalf("Verify over HTTP evidence: %v", err)
	}

	// Bad nonces are rejected up front.
	for _, bad := range []string{"", "zz", "abcd"} {
		resp, err := http.Get(ts.URL + "/v1/attestation?nonce=" + bad)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("nonce %q: got status %d, want 400", bad, resp.StatusCode)
		}
	}

	// Status endpoint responds.
	sresp, err := http.Get(ts.URL + "/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer sresp.Body.Close()
	if sresp.StatusCode != http.StatusOK {
		t.Errorf("status endpoint returned %d", sresp.StatusCode)
	}
}
