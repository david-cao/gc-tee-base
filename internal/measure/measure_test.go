//go:build cgo

package measure_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	gecel "github.com/google/go-eventlog/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/testutil"
	"github.com/google/go-tpm/legacy/tpm2"

	tpmtoolscel "github.com/google/go-tpm-tools/cel"

	"github.com/davidcao20/gc-tee-base/internal/measure"
	"github.com/davidcao20/gc-tee-base/internal/verify"
)

func testCommitment() []byte {
	sum := sha256.Sum256([]byte(`{"image":"docker.io/library/busybox:latest","salt":"..."}`))
	return sum[:]
}

func TestMeasureAndReplayAgainstTPM(t *testing.T) {
	tpm := testutil.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	m, err := measure.New(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.MeasureCommitment(testCommitment()); err != nil {
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

	// 1 commitment + 1 separator = 2
	if got := m.RecordCount(); got != 2 {
		t.Errorf("RecordCount = %d, want 2", got)
	}
}

func TestMeasureCommitmentRejectsWrongSize(t *testing.T) {
	tpm := testutil.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	m, err := measure.New(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.MeasureCommitment([]byte("too short")); err == nil {
		t.Error("undersized commitment accepted, want error")
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
	if err := m.MeasureCommitment(testCommitment()); err == nil {
		t.Error("MeasureCommitment after Seal succeeded, want error")
	}
}
