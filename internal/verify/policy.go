package verify

import (
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

// Policy is what a relying party requires of verified evidence. The zero
// value accepts nothing: ImageDigest is mandatory.
type Policy struct {
	// ImageDigest is the exact manifest digest the workload must run
	// ("sha256:..."). Required.
	ImageDigest string `yaml:"imageDigest"`

	// ImageRefPattern, if set, is an anchored regular expression the image
	// reference must match.
	ImageRefPattern string `yaml:"imageRefPattern"`

	// AllowedOverrideEnvs lists env var names the operator may override.
	// Any other override fails the policy. Default: none allowed.
	AllowedOverrideEnvs []string `yaml:"allowedEnvOverrides"`

	// AllowOverrideArgs permits the operator to override the container
	// command. Default: not allowed.
	AllowOverrideArgs bool `yaml:"allowArgOverrides"`

	// ConfidentialTechs lists acceptable confidential computing technologies
	// (any of AMD_SEV, AMD_SEV_ES, AMD_SEV_SNP, INTEL_TDX). Empty means the
	// platform is not checked, which also accepts non-confidential VMs.
	ConfidentialTechs []string `yaml:"confidentialTechs"`

	// RequireSecureBoot fails evidence from VMs booted without secure boot.
	// For custom measured images (unsigned UKI, secure boot off) leave this
	// false and use PCRs pinning instead: pinning PCR 4/11 identifies the
	// exact UKI (kernel + initrd + cmdline + verity root hash), which covers
	// strictly more than a secure boot flag.
	RequireSecureBoot bool `yaml:"requireSecureBoot"`

	// PCRs, if set, pins exact PCR values in one bank (golden values from an
	// image build's expected-measurements.json). Any mismatch or missing
	// index fails the policy.
	PCRs *PCRPolicy `yaml:"pcrs"`

	// GCEInstance, if set, pins the evidence to one VM identity taken from
	// the Google-issued AK certificate.
	GCEInstance *GCEInstancePolicy `yaml:"gceInstance"`
}

// PCRPolicy pins exact PCR values within one bank.
type PCRPolicy struct {
	// Bank is the PCR bank to check ("sha256" by default).
	Bank string `yaml:"bank"`
	// Values maps PCR index to the expected digest, lowercase hex.
	Values map[int]string `yaml:"values"`
}

// GCEInstancePolicy pins evidence to a specific GCE instance. Empty fields
// are not checked.
type GCEInstancePolicy struct {
	ProjectID    string `yaml:"projectId"`
	Zone         string `yaml:"zone"`
	InstanceName string `yaml:"instanceName"`
}

// LoadPolicy reads a Policy from a YAML file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy %q: %w", path, err)
	}
	return &p, nil
}

// Evaluate checks verified evidence against the policy and returns every
// violation (empty means the policy passed).
func (p *Policy) Evaluate(r *Result) []error {
	var violations []error
	fail := func(format string, args ...any) {
		violations = append(violations, fmt.Errorf(format, args...))
	}

	c := r.Claims

	if p.ImageDigest == "" {
		fail("policy is missing required imageDigest")
	} else if c.ImageDigest != p.ImageDigest {
		fail("image digest %q does not match required %q", c.ImageDigest, p.ImageDigest)
	}

	if p.ImageRefPattern != "" {
		re, err := regexp.Compile("^(?:" + p.ImageRefPattern + ")$")
		if err != nil {
			fail("invalid imageRefPattern: %v", err)
		} else if !re.MatchString(c.ImageRef) {
			fail("image reference %q does not match pattern %q", c.ImageRef, p.ImageRefPattern)
		}
	}

	if !c.SeparatorSeen {
		fail("event log is missing the LaunchSeparator event (measurement may be incomplete)")
	}

	allowedEnvs := map[string]bool{}
	for _, name := range p.AllowedOverrideEnvs {
		allowedEnvs[name] = true
	}
	for name := range c.OverriddenEnvVars {
		if !allowedEnvs[name] {
			fail("env var %q was overridden but is not in allowedEnvOverrides", name)
		}
	}

	if len(c.OverriddenArgs) > 0 && !p.AllowOverrideArgs {
		fail("container args were overridden but allowArgOverrides is false")
	}

	platform := r.MachineState.GetPlatform()

	if len(p.ConfidentialTechs) > 0 {
		tech := platform.GetTechnology()
		ok := false
		for _, want := range p.ConfidentialTechs {
			val, known := attestpb.GCEConfidentialTechnology_value[want]
			if !known {
				fail("policy lists unknown confidential technology %q", want)
				continue
			}
			if tech == attestpb.GCEConfidentialTechnology(val) {
				ok = true
			}
		}
		if !ok {
			fail("VM confidential technology %s is not in the allowed set %v",
				tech, p.ConfidentialTechs)
		}
	}

	if p.RequireSecureBoot && !r.MachineState.GetSecureBoot().GetEnabled() {
		fail("secure boot is required but was not enabled")
	}

	if p.PCRs != nil {
		bank := p.PCRs.Bank
		if bank == "" {
			bank = "sha256"
		}
		quoted, ok := r.PCRs[bank]
		if !ok {
			fail("policy pins PCRs in bank %q but the evidence has no verified quote over it", bank)
		} else {
			indices := make([]int, 0, len(p.PCRs.Values))
			for idx := range p.PCRs.Values {
				indices = append(indices, idx)
			}
			sort.Ints(indices)
			for _, idx := range indices {
				want := strings.ToLower(p.PCRs.Values[idx])
				got, ok := quoted[idx]
				if !ok {
					fail("PCR %d is pinned but missing from the quoted %s bank", idx, bank)
					continue
				}
				if hex.EncodeToString(got) != want {
					fail("PCR %d (%s) is %x, expected %s", idx, bank, got, want)
				}
			}
		}
	}

	if p.GCEInstance != nil {
		info := platform.GetInstanceInfo()
		if info == nil {
			fail("policy pins a GCE instance but the evidence has no instance info (AK cert missing or non-GCE)")
		} else {
			if p.GCEInstance.ProjectID != "" && info.GetProjectId() != p.GCEInstance.ProjectID {
				fail("GCE project %q does not match required %q", info.GetProjectId(), p.GCEInstance.ProjectID)
			}
			if p.GCEInstance.Zone != "" && info.GetZone() != p.GCEInstance.Zone {
				fail("GCE zone %q does not match required %q", info.GetZone(), p.GCEInstance.Zone)
			}
			if p.GCEInstance.InstanceName != "" && info.GetInstanceName() != p.GCEInstance.InstanceName {
				fail("GCE instance name %q does not match required %q", info.GetInstanceName(), p.GCEInstance.InstanceName)
			}
		}
	}

	return violations
}
