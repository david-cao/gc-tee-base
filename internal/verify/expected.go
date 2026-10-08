package verify

import (
	"encoding/json"
	"fmt"
	"os"
)

// ExpectedMeasurements is the artifact an image build emits
// (expected-measurements.json): the predicted golden values a verifier pins.
// Written by cmd/predict-measurements, consumed by `verifier verify -expected`.
type ExpectedMeasurements struct {
	// Image is the GCE image name this prediction belongs to.
	Image string `json:"image"`
	// UKISha256 is the plain SHA-256 of the UKI file (build provenance, not
	// a PCR value).
	UKISha256 string `json:"ukiSha256,omitempty"`
	// Roothash is the dm-verity root hash sealed in the UKI cmdline.
	Roothash string `json:"roothash,omitempty"`
	// PCRs maps bank name → PCR index → expected digest (lowercase hex).
	// These are the values quoted when the image boots on SEV-SNP firmware
	// (PCR 4 carries the UKI authentihash there).
	PCRs map[string]map[int]string `json:"pcrs"`
	// TDX holds the values for the same image booted on TDX firmware, where
	// the boot-application measurement moves from PCR 4 into the
	// Intel-signed RTMRs.
	TDX *TDXExpected `json:"tdx,omitempty"`
	// Notes carries calibration remarks (e.g. which PCR 4 variant was
	// confirmed on real hardware).
	Notes string `json:"notes,omitempty"`
}

// TDXExpected is the TDX profile of an image build's golden values.
type TDXExpected struct {
	// PCRs maps bank name → PCR index → expected digest. On TDX firmware
	// PCR 4 holds only the action+separator fold (image-independent) and
	// PCR 11 the stub section fold (same value as on SNP).
	PCRs map[string]map[int]string `json:"pcrs"`
	// RTMRs maps runtime-measurement-register index → expected SHA-384
	// digest. RTMR[2] is the stub section fold — the hardware-rooted pin of
	// the exact UKI contents (kernel, initrd, cmdline with the verity hash).
	RTMRs map[int]string `json:"rtmrs"`
}

// LoadExpectedMeasurements reads an expected-measurements.json file.
func LoadExpectedMeasurements(path string) (*ExpectedMeasurements, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading expected measurements: %w", err)
	}
	var m ExpectedMeasurements
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing expected measurements %q: %w", path, err)
	}
	if len(m.PCRs) == 0 {
		return nil, fmt.Errorf("expected measurements %q contain no PCR values", path)
	}
	return &m, nil
}

// PCRPolicy converts the expected measurements into a pinning policy block,
// preferring the sha256 bank.
func (m *ExpectedMeasurements) PCRPolicy() (*PCRPolicy, error) {
	return pcrPolicyFrom(m.PCRs)
}

// TDXPCRPolicy is PCRPolicy for the TDX profile.
func (m *ExpectedMeasurements) TDXPCRPolicy() (*PCRPolicy, error) {
	if m.TDX == nil {
		return nil, fmt.Errorf("expected measurements carry no TDX profile; regenerate with the current predict-measurements")
	}
	return pcrPolicyFrom(m.TDX.PCRs)
}

func pcrPolicyFrom(pcrs map[string]map[int]string) (*PCRPolicy, error) {
	bank := "sha256"
	values, ok := pcrs[bank]
	if !ok {
		for b, v := range pcrs {
			bank, values = b, v
			break
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("expected measurements have no usable PCR bank")
	}
	return &PCRPolicy{Bank: bank, Values: values}, nil
}
