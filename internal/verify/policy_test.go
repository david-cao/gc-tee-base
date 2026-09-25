package verify

import (
	"testing"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

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
			ImageRef:          "docker.io/library/busybox:latest",
			ImageDigest:       "sha256:aaaa",
			ImageID:           "sha256:bbbb",
			RestartPolicy:     "Never",
			Args:              []string{"sh"},
			EnvVars:           map[string]string{},
			OverriddenArgs:    []string{},
			OverriddenEnvVars: map[string]string{},
			SeparatorSeen:     true,
		},
	}
}

func TestPolicyPass(t *testing.T) {
	p := Policy{
		ImageDigest:       "sha256:aaaa",
		ImageRefPattern:   `docker\.io/library/busybox:.*`,
		ConfidentialTechs: []string{"AMD_SEV_SNP", "INTEL_TDX"},
		RequireSecureBoot: true,
		GCEInstance:       &GCEInstancePolicy{ProjectID: "my-project", Zone: "us-central1-a"},
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
		{"wrong digest", Policy{ImageDigest: "sha256:other"}, nil},
		{"missing digest in policy", Policy{}, nil},
		{"ref pattern mismatch", Policy{ImageDigest: "sha256:aaaa", ImageRefPattern: `gcr\.io/.*`}, nil},
		{"no separator", Policy{ImageDigest: "sha256:aaaa"}, func(r *Result) { r.Claims.SeparatorSeen = false }},
		{"disallowed env override", Policy{ImageDigest: "sha256:aaaa"}, func(r *Result) {
			r.Claims.OverriddenEnvVars["FOO"] = "bar"
		}},
		{"disallowed arg override", Policy{ImageDigest: "sha256:aaaa"}, func(r *Result) {
			r.Claims.OverriddenArgs = []string{"--evil"}
		}},
		{"wrong tech", Policy{ImageDigest: "sha256:aaaa", ConfidentialTechs: []string{"INTEL_TDX"}}, nil},
		{"secure boot off", Policy{ImageDigest: "sha256:aaaa", RequireSecureBoot: true}, func(r *Result) {
			r.MachineState.SecureBoot.Enabled = false
		}},
		{"wrong instance", Policy{ImageDigest: "sha256:aaaa",
			GCEInstance: &GCEInstancePolicy{InstanceName: "other-vm"}}, nil},
		{"instance pin without info", Policy{ImageDigest: "sha256:aaaa",
			GCEInstance: &GCEInstancePolicy{ProjectID: "my-project"}}, func(r *Result) {
			r.MachineState.Platform.InstanceInfo = nil
		}},
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

func TestPCRPinning(t *testing.T) {
	r := passingResult()
	r.PCRs = map[string]map[int][]byte{
		"sha256": {
			4:  []byte{0xaa, 0xbb},
			11: []byte{0xcc, 0xdd},
		},
	}
	base := Policy{ImageDigest: "sha256:aaaa"}

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

func TestAllowedOverrides(t *testing.T) {
	p := Policy{
		ImageDigest:         "sha256:aaaa",
		AllowedOverrideEnvs: []string{"FOO"},
		AllowOverrideArgs:   true,
	}
	r := passingResult()
	r.Claims.OverriddenEnvVars["FOO"] = "bar"
	r.Claims.OverriddenArgs = []string{"custom"}
	if violations := p.Evaluate(r); len(violations) != 0 {
		t.Errorf("expected pass with allowed overrides, got: %v", violations)
	}
}
