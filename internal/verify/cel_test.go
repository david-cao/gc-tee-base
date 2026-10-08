package verify

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"

	gecel "github.com/google/go-eventlog/cel"
	statepb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	tpmtoolscel "github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm/legacy/tpm2"

	"github.com/davidcao20/gc-tee-base/internal/measure"
)

// softPCRs simulates a SHA-256 PCR bank in software.
type softPCRs struct {
	vals map[int][]byte
}

func newSoftPCRs() *softPCRs { return &softPCRs{vals: map[int][]byte{}} }

func (s *softPCRs) extender(bank crypto.Hash, idx int, digest []byte) error {
	cur, ok := s.vals[idx]
	if !ok {
		cur = make([]byte, sha256.Size)
	}
	sum := sha256.Sum256(append(cur, digest...))
	s.vals[idx] = sum[:]
	_ = bank
	return nil
}

func (s *softPCRs) bank() register.PCRBank {
	bank := register.PCRBank{TCGHashAlgo: statepb.HashAlgo(tpm2.AlgSHA256)}
	for idx, digest := range s.vals {
		bank.PCRs = append(bank.PCRs, register.PCR{Index: idx, Digest: digest, DigestAlg: crypto.SHA256})
	}
	return bank
}

func appendCos(t *testing.T, c gecel.CEL, soft *softPCRs, pcr int, typ tpmtoolscel.CosType, content []byte) {
	t.Helper()
	tlv := tpmtoolscel.CosTlv{EventType: typ, EventContent: content}
	if err := c.AppendEvent(tlv, []crypto.Hash{crypto.SHA256}, pcr, soft.extender); err != nil {
		t.Fatalf("AppendEvent(%v): %v", typ, err)
	}
}

var testCommitment = bytes.Repeat([]byte{0xab}, sha256.Size)

func buildStandardCEL(t *testing.T, soft *softPCRs) gecel.CEL {
	t.Helper()
	c := gecel.NewPCR()
	pcr := tpmtoolscel.CosEventPCR
	appendCos(t, c, soft, pcr, measure.WorkloadCommitmentType, testCommitment)
	appendCos(t, c, soft, pcr, tpmtoolscel.LaunchSeparatorType, nil)
	return c
}

func encodeDecode(t *testing.T, c gecel.CEL) gecel.CEL {
	t.Helper()
	var buf bytes.Buffer
	if err := c.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	decoded, err := gecel.DecodeToCEL(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestClaimsRoundtrip(t *testing.T) {
	soft := newSoftPCRs()
	decoded := encodeDecode(t, buildStandardCEL(t, soft))

	if err := decoded.Replay(soft.bank()); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	claims, err := claimsFromCEL(decoded)
	if err != nil {
		t.Fatalf("claimsFromCEL: %v", err)
	}

	if !claims.Provisioned {
		t.Error("Provisioned = false")
	}
	if claims.WorkloadCommitment != hex.EncodeToString(testCommitment) {
		t.Errorf("WorkloadCommitment = %q", claims.WorkloadCommitment)
	}
	if !claims.SeparatorSeen {
		t.Error("SeparatorSeen = false")
	}
}

func TestReplayFailsAgainstWrongPCRs(t *testing.T) {
	soft := newSoftPCRs()
	decoded := encodeDecode(t, buildStandardCEL(t, soft))

	// A bank whose PCR 13 value does not match the log.
	wrong := newSoftPCRs()
	wrong.extender(crypto.SHA256, tpmtoolscel.CosEventPCR, bytes.Repeat([]byte{0xff}, 32))
	if err := decoded.Replay(wrong.bank()); err == nil {
		t.Error("Replay against mismatched PCRs succeeded, want error")
	}
}

func TestTamperedCELFailsReplay(t *testing.T) {
	soft := newSoftPCRs()
	c := buildStandardCEL(t, soft)
	var buf bytes.Buffer
	if err := c.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()

	original, err := claimsFromCEL(encodeDecode(t, buildStandardCEL(t, newSoftPCRs())))
	if err != nil {
		t.Fatal(err)
	}

	// Flip one bit in every byte position. Every mutation must either be
	// caught (by decode, replay, or content-digest verification) or leave the
	// extracted claims unchanged (mutations of non-semantic metadata like the
	// record number are benign: ordering is enforced by the PCR hash chain,
	// not by metadata).
	for i := range raw {
		mutated := append([]byte{}, raw...)
		mutated[i] ^= 0x01
		decoded, err := gecel.DecodeToCEL(bytes.NewBuffer(mutated))
		if err != nil {
			continue
		}
		if err := decoded.Replay(soft.bank()); err != nil {
			continue
		}
		claims, err := claimsFromCEL(decoded)
		if err != nil {
			continue
		}
		if !reflect.DeepEqual(claims, original) {
			t.Fatalf("mutation at byte %d changed claims without detection:\n got %+v\nwant %+v",
				i, claims, original)
		}
	}
}

func TestEventAfterSeparatorRejected(t *testing.T) {
	soft := newSoftPCRs()
	c := buildStandardCEL(t, soft)
	appendCos(t, c, soft, tpmtoolscel.CosEventPCR, measure.WorkloadCommitmentType, testCommitment)
	decoded := encodeDecode(t, c)
	if err := decoded.Replay(soft.bank()); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if _, err := claimsFromCEL(decoded); err == nil {
		t.Error("event after separator accepted, want error")
	}
}

func TestDuplicateCommitmentRejected(t *testing.T) {
	soft := newSoftPCRs()
	c := gecel.NewPCR()
	appendCos(t, c, soft, tpmtoolscel.CosEventPCR, measure.WorkloadCommitmentType, testCommitment)
	appendCos(t, c, soft, tpmtoolscel.CosEventPCR, measure.WorkloadCommitmentType, testCommitment)
	if _, err := claimsFromCEL(encodeDecode(t, c)); err == nil {
		t.Error("duplicate WorkloadCommitment accepted, want error")
	}
}

func TestMissingCommitmentRejected(t *testing.T) {
	soft := newSoftPCRs()
	c := gecel.NewPCR()
	appendCos(t, c, soft, tpmtoolscel.CosEventPCR, tpmtoolscel.LaunchSeparatorType, nil)
	if _, err := claimsFromCEL(encodeDecode(t, c)); err == nil {
		t.Error("log without a WorkloadCommitment accepted, want error")
	}
}

func TestWrongCommitmentSizeRejected(t *testing.T) {
	soft := newSoftPCRs()
	c := gecel.NewPCR()
	appendCos(t, c, soft, tpmtoolscel.CosEventPCR, measure.WorkloadCommitmentType, []byte("short"))
	if _, err := claimsFromCEL(encodeDecode(t, c)); err == nil {
		t.Error("undersized commitment accepted, want error")
	}
}

func TestWrongPCRRejected(t *testing.T) {
	soft := newSoftPCRs()
	c := gecel.NewPCR()
	appendCos(t, c, soft, 12, measure.WorkloadCommitmentType, testCommitment)
	if _, err := claimsFromCEL(encodeDecode(t, c)); err == nil {
		t.Error("event on PCR 12 accepted, want error")
	}
}

// The legacy per-claim Confidential Space events are no longer meaningful in
// this log; accepting them would let unverified semantics hide in evidence.
func TestLegacyCosEventsRejected(t *testing.T) {
	soft := newSoftPCRs()
	c := gecel.NewPCR()
	appendCos(t, c, soft, tpmtoolscel.CosEventPCR, tpmtoolscel.ImageRefType, []byte("docker.io/library/busybox"))
	if _, err := claimsFromCEL(encodeDecode(t, c)); err == nil {
		t.Error("legacy ImageRef event accepted, want error")
	}
}
