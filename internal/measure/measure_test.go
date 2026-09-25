//go:build cgo

package measure_test

import (
	"bytes"
	"testing"

	gecel "github.com/google/go-eventlog/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/testutil"
	"github.com/google/go-tpm/legacy/tpm2"

	tpmtoolscel "github.com/google/go-tpm-tools/cel"

	"github.com/davidcao20/gc-tee-base/internal/measure"
	"github.com/davidcao20/gc-tee-base/internal/spec"
	"github.com/davidcao20/gc-tee-base/internal/verify"
)

func testClaims() measure.ContainerClaims {
	return measure.ContainerClaims{
		ImageRef:      "docker.io/library/busybox:latest",
		ImageDigest:   "sha256:aaaa",
		ImageID:       "sha256:bbbb",
		Args:          []string{"sh", "-c", "echo hi"},
		EnvVars:       []string{"PATH=/bin"},
		RestartPolicy: spec.RestartNever,
	}
}

func testSpec() *spec.LaunchSpec {
	s := &spec.LaunchSpec{
		ImageRef: "docker.io/library/busybox:latest",
		Envs:     map[string]string{"FOO": "bar"},
	}
	s.ApplyDefaults()
	return s
}

func TestMeasureAndReplayAgainstTPM(t *testing.T) {
	tpm := testutil.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	m, err := measure.New(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.MeasureContainer(testClaims(), testSpec()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Seal(); err != nil {
		t.Fatal(err)
	}

	celBytes, err := m.EncodedCEL()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := gecel.DecodeToCEL(bytes.NewBuffer(celBytes))
	if err != nil {
		t.Fatal(err)
	}

	// The log must replay against the real PCR values in the TPM.
	pcrs, err := client.ReadPCRs(tpm, tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{tpmtoolscel.CosEventPCR},
	})
	if err != nil {
		t.Fatal(err)
	}
	bank, err := verify.PCRBankFromProto(pcrs)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Replay(bank); err != nil {
		t.Fatalf("Replay against TPM PCRs: %v", err)
	}

	// 4 scalar events + 3 args + 1 env + 1 override env + 1 separator = 10
	if got := m.RecordCount(); got != 10 {
		t.Errorf("RecordCount = %d, want 10", got)
	}
}

func TestExtendAfterSealFails(t *testing.T) {
	tpm := testutil.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	m, err := measure.New(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Seal(); err != nil {
		t.Fatal(err)
	}
	tlv := tpmtoolscel.CosTlv{EventType: tpmtoolscel.EnvVarType, EventContent: []byte("SNEAKY=1")}
	if err := m.Extend(tlv); err == nil {
		t.Error("Extend after Seal succeeded, want error")
	}
	if err := m.MeasureContainer(testClaims(), testSpec()); err == nil {
		t.Error("MeasureContainer after Seal succeeded, want error")
	}
}
