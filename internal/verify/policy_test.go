package verify

import (
	"strings"
	"testing"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

const testCommitmentHex = "abababababababababababababababababababababababababababababababab"

func passingResult() *Result {
	return &Result{
		MachineState: &attestpb.MachineState{
			Platform: &attestpb.PlatformState{
				Technology: attestpb.GCEConfidentialTechnology_AMD_SEV_SNP,
				InstanceInfo: &attestpb.GCEInstanceInfo{
					ProjectId:    "my-project",
					Zone:         "us-central1-a",
					InstanceName: "my-cvm",
				},
			},
			SecureBoot: &attestpb.SecureBootState{Enabled: true},
		},
		Claims: &Claims{
			Provisioned:        true,
			WorkloadCommitment: testCommitmentHex,
			SeparatorSeen:      true,
		},
		TEE: &TEEResult{
			Kind:            string(TEEKindSevSnp),
			Measurement:     strings.Repeat("12", 48),
			ReportDataBound: true,
		},
	}
}

func TestPolicyPass(t *testing.T) {
	p := Policy{
		WorkloadCommitment: testCommitmentHex,
		ConfidentialTechs:  []string{"AMD_SEV_SNP", "INTEL_TDX"},
		RequireSecureBoot:  true,
		GCEInstance:        &GCEInstancePolicy{ProjectID: "my-project", Zone: "us-central1-a"},
		Hardware: &HardwarePolicy{
			Require: true,
			SNP:     &SNPPolicy{Measurement: strings.Repeat("12", 48)},
		},
	}
	if violations := p.Evaluate(passingResult()); len(violations) != 0 {
		t.Errorf("expected pass, got violations: %v", violations)
	}
}

func TestPolicyViolations(t *testing.T) {
	cases := []struct {
		name   string
		policy Policy
		mutate func(*Result)
	}{
		{"wrong commitment", Policy{WorkloadCommitment: strings.Repeat("00", 32)}, nil},
		{"missing commitment in policy", Policy{}, nil},
		{"not provisioned", Policy{WorkloadCommitment: testCommitmentHex}, func(r *Result) {
			r.Claims = &Claims{Provisioned: false}
		}},
		{"no separator", Policy{WorkloadCommitment: testCommitmentHex}, func(r *Result) {
			r.Claims.SeparatorSeen = false
		}},
		{"wrong tech", Policy{WorkloadCommitment: testCommitmentHex,
			ConfidentialTechs: []string{"INTEL_TDX"}}, nil},
		{"secure boot off", Policy{WorkloadCommitment: testCommitmentHex, RequireSecureBoot: true},
			func(r *Result) { r.MachineState.SecureBoot.Enabled = false }},
		{"wrong instance", Policy{WorkloadCommitment: testCommitmentHex,
			GCEInstance: &GCEInstancePolicy{InstanceName: "other-vm"}}, nil},
		{"instance pin without info", Policy{WorkloadCommitment: testCommitmentHex,
			GCEInstance: &GCEInstancePolicy{ProjectID: "my-project"}}, func(r *Result) {
			r.MachineState.Platform.InstanceInfo = nil
		}},
		{"hardware required but absent", Policy{WorkloadCommitment: testCommitmentHex,
			Hardware: &HardwarePolicy{Require: true}}, func(r *Result) { r.TEE = nil }},
		{"wrong SNP measurement", Policy{WorkloadCommitment: testCommitmentHex,
			Hardware: &HardwarePolicy{SNP: &SNPPolicy{Measurement: strings.Repeat("ff", 48)}}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := passingResult()
			if tc.mutate != nil {
				tc.mutate(r)
			}
			if violations := tc.policy.Evaluate(r); len(violations) == 0 {
				t.Error("expected a violation, policy passed")
			}
		})
	}
}

// The provisioning-stage policy must accept an unprovisioned VM while the
// post-launch policy rejects it, and the hardware requirement must apply at
// both stages.
func TestEvaluateBase(t *testing.T) {
	p := Policy{
		ConfidentialTechs: []string{"AMD_SEV_SNP"},
		Hardware:          &HardwarePolicy{Require: true},
	}
	r := passingResult()
	r.Claims = &Claims{Provisioned: false}
	if violations := p.EvaluateBase(r); len(violations) != 0 {
		t.Errorf("EvaluateBase on a fresh VM: %v", violations)
	}
	if violations := p.Evaluate(r); len(violations) == 0 {
		t.Error("full Evaluate accepted an unprovisioned VM")
	}
	r.TEE = nil
	if violations := p.EvaluateBase(r); len(violations) == 0 {
		t.Error("EvaluateBase accepted missing hardware report despite require")
	}
}

func TestCheckUnprovisioned(t *testing.T) {
	r := passingResult()
	r.Claims = &Claims{Provisioned: false}
	r.PCRs = map[string]map[int][]byte{"sha256": {13: make([]byte, 32)}}
	if err := r.CheckUnprovisioned(); err != nil {
		t.Errorf("fresh VM rejected: %v", err)
	}
	r.PCRs["sha256"][13][5] = 0x01
	if err := r.CheckUnprovisioned(); err == nil {
		t.Error("nonzero PCR 13 accepted as unprovisioned")
	}
	r.PCRs["sha256"][13][5] = 0x00
	r.Claims.Provisioned = true
	if err := r.CheckUnprovisioned(); err == nil {
		t.Error("provisioned claims accepted as unprovisioned")
	}
}

func TestPCRPinning(t *testing.T) {
	r := passingResult()
	r.PCRs = map[string]map[int][]byte{
		"sha256": {
			4:  []byte{0xaa, 0xbb},
			11: []byte{0xcc, 0xdd},
		},
	}
	base := Policy{WorkloadCommitment: testCommitmentHex}

	pass := base
	pass.PCRs = &PCRPolicy{Values: map[int]string{4: "aabb", 11: "ccdd"}}
	if violations := pass.Evaluate(r); len(violations) != 0 {
		t.Errorf("expected pass, got: %v", violations)
	}

	// Uppercase hex in the policy must still match.
	upper := base
	upper.PCRs = &PCRPolicy{Bank: "sha256", Values: map[int]string{4: "AABB"}}
	if violations := upper.Evaluate(r); len(violations) != 0 {
		t.Errorf("expected pass with uppercase hex, got: %v", violations)
	}

	wrongValue := base
	wrongValue.PCRs = &PCRPolicy{Values: map[int]string{4: "beef"}}
	if violations := wrongValue.Evaluate(r); len(violations) == 0 {
		t.Error("wrong PCR value passed")
	}

	missingIndex := base
	missingIndex.PCRs = &PCRPolicy{Values: map[int]string{7: "aabb"}}
	if violations := missingIndex.Evaluate(r); len(violations) == 0 {
		t.Error("missing PCR index passed")
	}

	missingBank := base
	missingBank.PCRs = &PCRPolicy{Bank: "sha384", Values: map[int]string{4: "aabb"}}
	if violations := missingBank.Evaluate(r); len(violations) == 0 {
		t.Error("missing bank passed")
	}
}

func TestExpectedMeasurementsToPolicy(t *testing.T) {
	m := ExpectedMeasurements{
		Image: "gc-tee-base-20260925",
		PCRs: map[string]map[int]string{
			"sha256": {4: "aabb", 11: "ccdd"},
			"sha1":   {4: "1122"},
		},
	}
	p, err := m.PCRPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p.Bank != "sha256" || p.Values[4] != "aabb" || p.Values[11] != "ccdd" {
		t.Errorf("PCRPolicy = %+v", p)
	}
}
