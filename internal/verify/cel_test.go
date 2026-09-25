package verify

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"reflect"
	"testing"

	gecel "github.com/google/go-eventlog/cel"
	statepb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	tpmtoolscel "github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm/legacy/tpm2"
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

func appendCos(t *testing.T, c gecel.CEL, soft *softPCRs, pcr int, typ tpmtoolscel.CosType, content string) {
	t.Helper()
	tlv := tpmtoolscel.CosTlv{EventType: typ, EventContent: []byte(content)}
	if err := c.AppendEvent(tlv, []crypto.Hash{crypto.SHA256}, pcr, soft.extender); err != nil {
		t.Fatalf("AppendEvent(%v, %q): %v", typ, content, err)
	}
}

func buildStandardCEL(t *testing.T, soft *softPCRs) gecel.CEL {
	t.Helper()
	c := gecel.NewPCR()
	pcr := tpmtoolscel.CosEventPCR
	appendCos(t, c, soft, pcr, tpmtoolscel.ImageRefType, "docker.io/library/busybox:latest")
	appendCos(t, c, soft, pcr, tpmtoolscel.ImageDigestType, "sha256:aaaa")
	appendCos(t, c, soft, pcr, tpmtoolscel.RestartPolicyType, "Never")
	appendCos(t, c, soft, pcr, tpmtoolscel.ImageIDType, "sha256:bbbb")
	appendCos(t, c, soft, pcr, tpmtoolscel.ArgType, "sh")
	appendCos(t, c, soft, pcr, tpmtoolscel.ArgType, "-c")
	appendCos(t, c, soft, pcr, tpmtoolscel.EnvVarType, "PATH=/bin")
	appendCos(t, c, soft, pcr, tpmtoolscel.OverrideEnvType, "FOO=bar")
	appendCos(t, c, soft, pcr, tpmtoolscel.OverrideArgType, "-c")
	appendCos(t, c, soft, pcr, tpmtoolscel.LaunchSeparatorType, "")
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

	if claims.ImageRef != "docker.io/library/busybox:latest" {
		t.Errorf("ImageRef = %q", claims.ImageRef)
	}
	if claims.ImageDigest != "sha256:aaaa" {
		t.Errorf("ImageDigest = %q", claims.ImageDigest)
	}
	if claims.ImageID != "sha256:bbbb" {
		t.Errorf("ImageID = %q", claims.ImageID)
	}
	if claims.RestartPolicy != "Never" {
		t.Errorf("RestartPolicy = %q", claims.RestartPolicy)
	}
	if len(claims.Args) != 2 || claims.Args[0] != "sh" || claims.Args[1] != "-c" {
		t.Errorf("Args = %v", claims.Args)
	}
	if claims.EnvVars["PATH"] != "/bin" {
		t.Errorf("EnvVars = %v", claims.EnvVars)
	}
	if claims.OverriddenEnvVars["FOO"] != "bar" {
		t.Errorf("OverriddenEnvVars = %v", claims.OverriddenEnvVars)
	}
	if len(claims.OverriddenArgs) != 1 || claims.OverriddenArgs[0] != "-c" {
		t.Errorf("OverriddenArgs = %v", claims.OverriddenArgs)
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
	appendCos(t, c, soft, tpmtoolscel.CosEventPCR, tpmtoolscel.EnvVarType, "SNEAKY=1")
	decoded := encodeDecode(t, c)
	if err := decoded.Replay(soft.bank()); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if _, err := claimsFromCEL(decoded); err == nil {
		t.Error("event after separator accepted, want error")
	}
}

func TestDuplicateImageRefRejected(t *testing.T) {
	soft := newSoftPCRs()
	c := gecel.NewPCR()
	appendCos(t, c, soft, tpmtoolscel.CosEventPCR, tpmtoolscel.ImageRefType, "a")
	appendCos(t, c, soft, tpmtoolscel.CosEventPCR, tpmtoolscel.ImageRefType, "b")
	if _, err := claimsFromCEL(encodeDecode(t, c)); err == nil {
		t.Error("duplicate ImageRef accepted, want error")
	}
}

func TestWrongPCRRejected(t *testing.T) {
	soft := newSoftPCRs()
	c := gecel.NewPCR()
	appendCos(t, c, soft, 12, tpmtoolscel.ImageRefType, "a")
	if _, err := claimsFromCEL(encodeDecode(t, c)); err == nil {
		t.Error("event on PCR 12 accepted, want error")
	}
}

func TestUnknownEventTypeRejected(t *testing.T) {
	soft := newSoftPCRs()
	c := gecel.NewPCR()
	appendCos(t, c, soft, tpmtoolscel.CosEventPCR, tpmtoolscel.GpuCCModeType, "on")
	if _, err := claimsFromCEL(encodeDecode(t, c)); err == nil {
		t.Error("unsupported event type accepted, want error")
	}
}
