package spec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestAttestAddrFromMetadata(t *testing.T) {
	ts := metadataServer(t, map[string]string{
		"tee-attest-addr": "0.0.0.0:9090",
		"ssh-keys":        "ignored:ssh-rsa AAAA",
		"startup-script":  "#!/bin/sh ignored",
	})
	defer ts.Close()

	addr, err := AttestAddrFromMetadata(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "0.0.0.0:9090" {
		t.Errorf("addr = %q", addr)
	}
}

func TestAttestAddrFromMetadataAbsent(t *testing.T) {
	ts := metadataServer(t, map[string]string{"ssh-keys": "whatever"})
	defer ts.Close()

	addr, err := AttestAddrFromMetadata(context.Background(), ts.URL)
	if err != nil || addr != "" {
		t.Errorf("got (%q, %v), want empty and nil", addr, err)
	}
}

// The old metadata workload keys must fail loudly: silently ignoring them
// would run a VM without the workload its operator thinks was configured.
func TestRemovedWorkloadKeysRejected(t *testing.T) {
	for _, key := range []string{"tee-image-reference", "tee-cmd", "tee-restart-policy", "tee-env-FOO"} {
		ts := metadataServer(t, map[string]string{key: "value"})
		if _, err := AttestAddrFromMetadata(context.Background(), ts.URL); err == nil {
			t.Errorf("removed workload key %q accepted, want error", key)
		}
		ts.Close()
	}
}

func TestUnknownTeeKeyRejected(t *testing.T) {
	ts := metadataServer(t, map[string]string{
		"tee-attest-adr": "typo", // typo must fail closed
	})
	defer ts.Close()

	if _, err := AttestAddrFromMetadata(context.Background(), ts.URL); err == nil {
		t.Error("unknown tee-* key accepted, want error")
	}
}

func TestMetadataUnreachable(t *testing.T) {
	if _, err := AttestAddrFromMetadata(context.Background(), "http://127.0.0.1:1"); err == nil {
		t.Error("unreachable metadata server did not error")
	}
}
