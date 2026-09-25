// Package spec defines the launch specification for an attestable container:
// which image to run and the runtime configuration that will be measured into
// the vTPM before the container starts.
package spec

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Restart policies use the same strings as the upstream Confidential Space
// launcher so the measured bytes are directly comparable.
const (
	RestartAlways    = "Always"
	RestartOnFailure = "OnFailure"
	RestartNever     = "Never"
)

// DefaultAttestAddr is where the attestation evidence server listens if the
// spec does not say otherwise.
const DefaultAttestAddr = "0.0.0.0:8080"

// LaunchSpec describes the workload container and how to run it. Everything
// here except AttestAddr is measured into the vTPM before launch.
type LaunchSpec struct {
	// ImageRef is the container image to run, as a tag or digest reference
	// (e.g. "docker.io/library/busybox@sha256:..."). Required.
	ImageRef string `yaml:"image" json:"image"`

	// Cmd overrides the image's CMD (docker semantics: the image ENTRYPOINT
	// is kept and Cmd replaces the image CMD). Measured as OverrideArg events.
	Cmd []string `yaml:"cmd" json:"cmd,omitempty"`

	// Envs are environment variable overrides, layered on top of the image's
	// environment. Measured as OverrideEnv events.
	Envs map[string]string `yaml:"env" json:"env,omitempty"`

	// RestartPolicy is one of Always, OnFailure, Never. Defaults to Never.
	RestartPolicy string `yaml:"restartPolicy" json:"restartPolicy,omitempty"`

	// AttestAddr is the listen address for the attestation evidence server.
	// Not measured (it does not affect workload identity).
	AttestAddr string `yaml:"attestAddr" json:"attestAddr,omitempty"`
}

// Load reads a LaunchSpec from a YAML (or JSON, being a YAML subset) file.
func Load(path string) (*LaunchSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading launch spec: %w", err)
	}
	var s LaunchSpec
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing launch spec %q: %w", path, err)
	}
	return &s, nil
}

// ApplyDefaults fills in unset optional fields.
func (s *LaunchSpec) ApplyDefaults() {
	if s.RestartPolicy == "" {
		s.RestartPolicy = RestartNever
	}
	if s.AttestAddr == "" {
		s.AttestAddr = DefaultAttestAddr
	}
}

// Validate checks the spec for internal consistency. Call after ApplyDefaults.
func (s *LaunchSpec) Validate() error {
	if s.ImageRef == "" {
		return fmt.Errorf("launch spec: image is required")
	}
	switch s.RestartPolicy {
	case RestartAlways, RestartOnFailure, RestartNever:
	default:
		return fmt.Errorf("launch spec: invalid restartPolicy %q (want %s, %s, or %s)",
			s.RestartPolicy, RestartAlways, RestartOnFailure, RestartNever)
	}
	for name := range s.Envs {
		if name == "" || strings.Contains(name, "=") {
			return fmt.Errorf("launch spec: invalid env var name %q", name)
		}
	}
	return nil
}

// SortedEnvNames returns the override env var names in deterministic order,
// which fixes the measurement order of OverrideEnv events.
func (s *LaunchSpec) SortedEnvNames() []string {
	names := make([]string, 0, len(s.Envs))
	for name := range s.Envs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
