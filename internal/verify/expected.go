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
	PCRs map[string]map[int]string `json:"pcrs"`
	// Notes carries calibration remarks (e.g. which PCR 4 variant was
	// confirmed on real hardware).
	Notes string `json:"notes,omitempty"`
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
	bank := "sha256"
	values, ok := m.PCRs[bank]
	if !ok {
		for b, v := range m.PCRs {
			bank, values = b, v
			break
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("expected measurements have no usable PCR bank")
	}
	return &PCRPolicy{Bank: bank, Values: values}, nil
}
