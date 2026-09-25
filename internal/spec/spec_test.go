package spec

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadAndDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.yaml")
	content := `
image: docker.io/library/busybox@sha256:abc
cmd: ["sleep", "5"]
env:
  FOO: bar
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.ApplyDefaults()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.ImageRef != "docker.io/library/busybox@sha256:abc" {
		t.Errorf("ImageRef = %q", s.ImageRef)
	}
	if !reflect.DeepEqual(s.Cmd, []string{"sleep", "5"}) {
		t.Errorf("Cmd = %v", s.Cmd)
	}
	if s.RestartPolicy != RestartNever {
		t.Errorf("default RestartPolicy = %q, want Never", s.RestartPolicy)
	}
	if s.AttestAddr != DefaultAttestAddr {
		t.Errorf("default AttestAddr = %q", s.AttestAddr)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		spec    LaunchSpec
		wantErr bool
	}{
		{"missing image", LaunchSpec{RestartPolicy: RestartNever}, true},
		{"bad restart policy", LaunchSpec{ImageRef: "x", RestartPolicy: "sometimes"}, true},
		{"bad env name", LaunchSpec{ImageRef: "x", RestartPolicy: RestartNever, Envs: map[string]string{"A=B": "v"}}, true},
		{"ok", LaunchSpec{ImageRef: "x", RestartPolicy: RestartOnFailure, Envs: map[string]string{"A": "b"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.spec.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestSortedEnvNames(t *testing.T) {
	s := LaunchSpec{Envs: map[string]string{"Z": "1", "A": "2", "M": "3"}}
	got := s.SortedEnvNames()
	if !reflect.DeepEqual(got, []string{"A", "M", "Z"}) {
		t.Errorf("SortedEnvNames = %v", got)
	}
}
