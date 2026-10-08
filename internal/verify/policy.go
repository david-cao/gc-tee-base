package verify

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

// Policy is what a relying party requires of verified evidence.
type Policy struct {
	// WorkloadCommitment is the hex sha256 of the payload plaintext the
	// workload must be running (from a provisioning receipt). Usually
	// supplied at verify time (-receipt/-commitment) rather than written
	// here; either way it is required for post-launch verification.
	WorkloadCommitment string `yaml:"workloadCommitment"`

	// ConfidentialTechs lists acceptable confidential computing technologies
	// (any of AMD_SEV, AMD_SEV_ES, AMD_SEV_SNP, INTEL_TDX) as asserted by
	// the boot log (Google-attested). Empty means the platform is not
	// checked, which also accepts non-confidential VMs. For the AMD-rooted
	// proof, set hardware.require.
	ConfidentialTechs []string `yaml:"confidentialTechs"`

	// Hardware states requirements on the hardware attestation report (the
	// AMD-rooted part of the chain).
	Hardware *HardwarePolicy `yaml:"hardware"`

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

// HardwarePolicy states requirements on the CPU-vendor-rooted attestation
// report.
type HardwarePolicy struct {
	// Require fails evidence that carries no verified hardware report. With
	// it false, a present report is still verified (bad reports always
	// fail), but absence is accepted — the chain is then vTPM-only.
	Require bool `yaml:"require"`

	// TDX holds Intel TDX specifics.
	TDX *TDXPolicy `yaml:"tdx"`

	// SNP holds SEV-SNP specifics.
	SNP *SNPPolicy `yaml:"snp"`
}

// TDXPolicy pins Intel TDX quote fields.
type TDXPolicy struct {
	// MrTd, if set, is the expected hex MRTD (48 bytes): the launch
	// measurement of the TD firmware — on GCE, Google's firmware, covered
	// by Google's signed launch endorsements.
	MrTd string `yaml:"mrTd"`

	// Rtmrs, if set, pins runtime measurement registers by index (0–3),
	// hex. On GCE the firmware extends RTMR[1]/[2] with the boot chain
	// (bootloader/UKI, kernel + cmdline), so pinning them pins the base
	// image under the Intel root. Obtain golden values from a calibration
	// run of the image build.
	Rtmrs map[int]string `yaml:"rtmrs"`
}

// SNPPolicy pins SEV-SNP report fields.
type SNPPolicy struct {
	// ProductLine ("Milan", "Genoa", ...) selects the AMD root certificates
	// when the report does not identify the CPU product itself.
	ProductLine string `yaml:"productLine"`

	// Measurement, if set, is the expected hex launch measurement (48
	// bytes): on GCE, the measurement of Google's UEFI firmware. Obtain the
	// value from a trusted run or from Google's signed launch endorsement
	// (gs://gce_tcb_integrity, see the README).
	Measurement string `yaml:"measurement"`
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

// Evaluate checks verified post-launch evidence against the policy and
// returns every violation (empty means the policy passed): platform checks
// plus the workload commitment.
func (p *Policy) Evaluate(r *Result) []error {
	violations := p.EvaluateBase(r)
	fail := func(format string, args ...any) {
		violations = append(violations, fmt.Errorf(format, args...))
	}

	c := r.Claims
	if !c.Provisioned {
		fail("no workload has been provisioned on this VM yet")
		return violations
	}
	if p.WorkloadCommitment == "" {
		fail("policy is missing the required workloadCommitment (pass -receipt or -commitment)")
	} else if !strings.EqualFold(c.WorkloadCommitment, p.WorkloadCommitment) {
		fail("workload commitment %s does not match required %s", c.WorkloadCommitment, p.WorkloadCommitment)
	}
	if !c.SeparatorSeen {
		fail("event log is missing the LaunchSeparator event (measurement may be incomplete)")
	}
	return violations
}

// EvaluateBase checks the platform requirements only — everything except
// the workload commitment. This is the stage-1 (provisioning) policy: run
// it, together with Result.CheckUnprovisioned, before encrypting a payload
// to the VM.
func (p *Policy) EvaluateBase(r *Result) []error {
	var violations []error
	fail := func(format string, args ...any) {
		violations = append(violations, fmt.Errorf(format, args...))
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

	if p.Hardware != nil {
		if p.Hardware.Require && r.TEE == nil {
			fail("policy requires a hardware attestation report but the evidence carries none " +
				"(is the VM TDX/SEV-SNP with its guest report device available?)")
		}
		if r.TEE != nil {
			// The technology blocks present in the policy define the
			// accepted set: a policy that pins TDX fields must not be
			// satisfiable by SNP evidence (whose RTMR pins would silently
			// not apply), and vice versa. A policy with neither block
			// accepts either technology.
			if p.Hardware.TDX != nil || p.Hardware.SNP != nil {
				kindAllowed := (r.TEE.Kind == string(TEEKindTdx) && p.Hardware.TDX != nil) ||
					(r.TEE.Kind == string(TEEKindSevSnp) && p.Hardware.SNP != nil)
				if !kindAllowed {
					fail("evidence carries a %s report but the policy only configures %s",
						r.TEE.Kind, hardwareKinds(p.Hardware))
				}
			}
			switch {
			case r.TEE.Kind == string(TEEKindSevSnp) && p.Hardware.SNP != nil:
				if want := strings.ToLower(p.Hardware.SNP.Measurement); want != "" && r.TEE.Measurement != want {
					fail("SNP launch measurement %s does not match required %s (unexpected firmware?)",
						r.TEE.Measurement, want)
				}
			case r.TEE.Kind == string(TEEKindTdx) && p.Hardware.TDX != nil:
				if want := strings.ToLower(p.Hardware.TDX.MrTd); want != "" && r.TEE.Measurement != want {
					fail("TDX MRTD %s does not match required %s (unexpected firmware?)",
						r.TEE.Measurement, want)
				}
				indices := make([]int, 0, len(p.Hardware.TDX.Rtmrs))
				for idx := range p.Hardware.TDX.Rtmrs {
					indices = append(indices, idx)
				}
				sort.Ints(indices)
				for _, idx := range indices {
					want := strings.ToLower(p.Hardware.TDX.Rtmrs[idx])
					if idx < 0 || idx >= len(r.TEE.RTMRs) {
						fail("policy pins RTMR[%d] but the quote carries %d RTMRs", idx, len(r.TEE.RTMRs))
						continue
					}
					if r.TEE.RTMRs[idx] != want {
						fail("RTMR[%d] is %s, expected %s", idx, r.TEE.RTMRs[idx], want)
					}
				}
			}
		}
	}

	return violations
}

func hardwareKinds(h *HardwarePolicy) string {
	kinds := []string{}
	if h.TDX != nil {
		kinds = append(kinds, string(TEEKindTdx))
	}
	if h.SNP != nil {
		kinds = append(kinds, string(TEEKindSevSnp))
	}
	return strings.Join(kinds, "/")
}
