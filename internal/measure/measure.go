// Package measure builds the canonical event log (CEL) of the workload's
// identity and extends each event into vTPM PCR 13. The log uses the same
// TLV framing, PCR (13), and separator event as the Confidential Space
// launcher, but records a single payload commitment instead of individual
// claims: workload details stay private to whoever knows the payload.
package measure

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"sync"

	gecel "github.com/google/go-eventlog/cel"
	tpmtoolscel "github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// WorkloadCommitmentType is our CEL event type for the payload commitment:
// sha256 over the exact plaintext bytes of the provisioned workload payload.
// The value sits far above the Confidential Space event types (0..11) so the
// logs remain structurally compatible but cannot be confused.
const WorkloadCommitmentType tpmtoolscel.CosType = 128

// ContainerClaims are the resolved, about-to-run properties of the workload.
// All values must come from the same objects the runtime will execute, not
// from user input, so that the measurement matches reality.
type ContainerClaims struct {
	ImageRef      string   // resolved image reference
	ImageDigest   string   // manifest digest ("sha256:...")
	ImageID       string   // image config descriptor digest
	Args          []string // final OCI Process.Args (after override merge)
	EnvVars       []string // final OCI Process.Env ("KEY=VALUE")
	RestartPolicy string
}

// Sealed is proof that measurement is complete (the LaunchSeparator event has
// been extended). The container runtime requires it to start the workload,
// making measure-before-launch a compile-time property.
type Sealed struct{ _ [0]byte }

// Measurer owns the in-memory CEL and the PCR-extend side effects.
type Measurer struct {
	mu        sync.Mutex
	tpm       io.ReadWriter
	cel       gecel.CEL
	hashAlgos []crypto.Hash
	sealed    bool
}

// New creates a Measurer that extends events into every allocated PCR bank of
// the given TPM.
func New(tpm io.ReadWriter) (*Measurer, error) {
	sels, err := client.AllocatedPCRs(tpm)
	if err != nil {
		return nil, fmt.Errorf("reading allocated PCR banks: %w", err)
	}
	var algos []crypto.Hash
	for _, sel := range sels {
		h, err := sel.Hash.Hash()
		if err != nil {
			// Skip banks we cannot hash for (e.g. SM3); the quote covers
			// the banks we do extend.
			continue
		}
		algos = append(algos, h)
	}
	if len(algos) == 0 {
		return nil, fmt.Errorf("no usable PCR banks allocated")
	}
	return &Measurer{tpm: tpm, cel: gecel.NewPCR(), hashAlgos: algos}, nil
}

// extender returns the MRExtender that performs the actual TPM2_PCR_Extend.
func (m *Measurer) extender() gecel.MRExtender {
	return func(bank crypto.Hash, mrIdx int, digest []byte) error {
		alg, err := tpm2.HashToAlgorithm(bank)
		if err != nil {
			return err
		}
		return tpm2.PCRExtend(m.tpm, tpmutil.Handle(mrIdx), alg, digest, "")
	}
}

// Extend appends one event to the CEL and extends it into PCR 13. It fails
// after Seal has been called.
func (m *Measurer) Extend(content gecel.Content) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.extendLocked(content)
}

func (m *Measurer) extendLocked(content gecel.Content) error {
	if m.sealed {
		return fmt.Errorf("measurement is sealed; cannot extend further events")
	}
	return m.cel.AppendEvent(content, m.hashAlgos, tpmtoolscel.CosEventPCR, m.extender())
}

// MeasureCommitment records the workload payload commitment (sha256 of the
// exact payload plaintext) as the single pre-separator event. The commitment
// — not the payload contents — becomes the public claim: a verifier who
// knows the payload can check it; everyone else learns only a hash.
func (m *Measurer) MeasureCommitment(commitment []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(commitment) != crypto.SHA256.Size() {
		return fmt.Errorf("commitment must be %d bytes, got %d", crypto.SHA256.Size(), len(commitment))
	}
	tlv := tpmtoolscel.CosTlv{EventType: WorkloadCommitmentType, EventContent: commitment}
	if err := m.extendLocked(tlv); err != nil {
		return fmt.Errorf("measuring workload commitment: %w", err)
	}
	return nil
}

// Seal extends the LaunchSeparator event and latches the Measurer: any later
// Extend call fails, and the returned token authorizes starting the workload.
func (m *Measurer) Seal() (Sealed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sep := tpmtoolscel.CosTlv{EventType: tpmtoolscel.LaunchSeparatorType, EventContent: nil}
	if err := m.extendLocked(sep); err != nil {
		return Sealed{}, fmt.Errorf("extending launch separator: %w", err)
	}
	m.sealed = true
	return Sealed{}, nil
}

// EncodedCEL returns the TLV encoding of the event log, suitable for
// pb.Attestation.CanonicalEventLog.
func (m *Measurer) EncodedCEL() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var buf bytes.Buffer
	if err := m.cel.EncodeCEL(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RecordCount reports how many events have been measured (for /v1/status).
func (m *Measurer) RecordCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cel.Records())
}
