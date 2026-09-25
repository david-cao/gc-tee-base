package spec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func metadataServer(t *testing.T, attrs map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/computeMetadata/v1/instance/attributes/" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing Metadata-Flavor header", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(attrs)
	}))
}

func TestFromMetadata(t *testing.T) {
	ts := metadataServer(t, map[string]string{
		"tee-image-reference": "docker.io/library/busybox@sha256:abc",
		"tee-cmd":             `["sh","-c","sleep 5"]`,
		"tee-env-FOO":         "bar",
		"tee-env-BAZ":         "qux",
		"tee-restart-policy":  "OnFailure",
		"tee-attest-addr":     "0.0.0.0:9090",
		"ssh-keys":            "ignored:ssh-rsa AAAA",
		"startup-script":      "#!/bin/sh ignored",
	})
	defer ts.Close()

	s, err := FromMetadata(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if s.ImageRef != "docker.io/library/busybox@sha256:abc" {
		t.Errorf("ImageRef = %q", s.ImageRef)
	}
	if !reflect.DeepEqual(s.Cmd, []string{"sh", "-c", "sleep 5"}) {
		t.Errorf("Cmd = %v", s.Cmd)
	}
	if !reflect.DeepEqual(s.Envs, map[string]string{"FOO": "bar", "BAZ": "qux"}) {
		t.Errorf("Envs = %v", s.Envs)
	}
	if s.RestartPolicy != "OnFailure" {
		t.Errorf("RestartPolicy = %q", s.RestartPolicy)
	}
	if s.AttestAddr != "0.0.0.0:9090" {
		t.Errorf("AttestAddr = %q", s.AttestAddr)
	}

	s.ApplyDefaults()
	if err := s.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestFromMetadataNoWorkload(t *testing.T) {
	ts := metadataServer(t, map[string]string{"ssh-keys": "whatever"})
	defer ts.Close()

	_, err := FromMetadata(context.Background(), ts.URL)
	if !errors.Is(err, ErrNoMetadataSpec) {
		t.Errorf("err = %v, want ErrNoMetadataSpec", err)
	}
}

func TestFromMetadataUnknownTeeKey(t *testing.T) {
	ts := metadataServer(t, map[string]string{
		"tee-image-reference": "img",
		"tee-restart-polcy":   "Always", // typo must fail closed
	})
	defer ts.Close()

	if _, err := FromMetadata(context.Background(), ts.URL); err == nil {
		t.Error("unknown tee-* key accepted, want error")
	}
}

func TestFromMetadataBadCmd(t *testing.T) {
	ts := metadataServer(t, map[string]string{
		"tee-image-reference": "img",
		"tee-cmd":             "not-json",
	})
	defer ts.Close()

	if _, err := FromMetadata(context.Background(), ts.URL); err == nil {
		t.Error("non-JSON tee-cmd accepted, want error")
	}
}

func TestFromMetadataUnreachable(t *testing.T) {
	if _, err := FromMetadata(context.Background(), "http://127.0.0.1:1"); err == nil {
		t.Error("unreachable metadata server did not error")
	}
}
