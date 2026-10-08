package spec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultMetadataBase is the GCE metadata server. It is a link-local service
// only reachable from inside a GCE VM.
const DefaultMetadataBase = "http://metadata.google.internal"

// The only supported metadata attribute. The workload itself is delivered
// via the encrypted provisioning flow (POST /v1/workload), never via
// metadata: metadata is cleartext to anyone with project access.
const metaAttestAddr = "tee-attest-addr"

// Workload keys from the metadata-based flow (and Confidential Space). They
// are rejected with a pointed error so a stale deployment fails loudly
// instead of silently ignoring its workload configuration.
var removedWorkloadKeys = []string{
	"tee-image-reference", "tee-cmd", "tee-restart-policy",
}

// AttestAddrFromMetadata returns the tee-attest-addr attribute, or "" if the
// instance does not set it. Unknown tee-* keys are an error: an operator
// typo must fail the launch, not be silently dropped. Non-tee keys
// (ssh-keys, startup-script, ...) are ignored.
func AttestAddrFromMetadata(ctx context.Context, baseURL string) (string, error) {
	attrs, err := fetchAttributes(ctx, baseURL)
	if err != nil {
		return "", err
	}
	addr := ""
	for key, value := range attrs {
		switch {
		case key == metaAttestAddr:
			addr = value
		case isRemovedWorkloadKey(key):
			return "", fmt.Errorf("metadata key %q is no longer supported: the workload is delivered "+
				"as an encrypted payload (verifier provision), not via instance metadata", key)
		case strings.HasPrefix(key, "tee-"):
			return "", fmt.Errorf("unknown tee-* metadata key %q (only %s is supported)", key, metaAttestAddr)
		}
	}
	return addr, nil
}

func isRemovedWorkloadKey(key string) bool {
	for _, k := range removedWorkloadKeys {
		if key == k {
			return true
		}
	}
	return strings.HasPrefix(key, "tee-env-")
}

func fetchAttributes(ctx context.Context, baseURL string) (map[string]string, error) {
	url := strings.TrimSuffix(baseURL, "/") +
		"/computeMetadata/v1/instance/attributes/?recursive=true&alt=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying metadata server: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading metadata response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata server returned %s", resp.Status)
	}

	attrs := map[string]string{}
	if err := json.Unmarshal(body, &attrs); err != nil {
		return nil, fmt.Errorf("parsing metadata attributes: %w", err)
	}
	return attrs, nil
}
