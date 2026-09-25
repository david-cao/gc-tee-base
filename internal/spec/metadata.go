package spec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DefaultMetadataBase is the GCE metadata server. It is a link-local service
// only reachable from inside a GCE VM.
const DefaultMetadataBase = "http://metadata.google.internal"

// Metadata attribute keys, mirroring Confidential Space so specs are portable
// between the two launchers. tee-attest-addr is our own extension.
const (
	metaImageRef      = "tee-image-reference"
	metaCmd           = "tee-cmd"
	metaRestartPolicy = "tee-restart-policy"
	metaAttestAddr    = "tee-attest-addr"
	metaEnvPrefix     = "tee-env-"
)

// ErrNoMetadataSpec is returned when the metadata server is reachable but the
// instance has no tee-image-reference attribute (i.e. no workload was
// configured via metadata).
var ErrNoMetadataSpec = errors.New("instance metadata has no " + metaImageRef + " attribute")

// FromMetadata builds a LaunchSpec from GCE instance metadata attributes.
// baseURL is the metadata server base (DefaultMetadataBase outside tests).
//
// Unknown tee-* keys are an error: an operator typo must fail the launch, not
// silently drop a measured override. Non-tee keys (ssh-keys, startup-script,
// ...) are ignored.
func FromMetadata(ctx context.Context, baseURL string) (*LaunchSpec, error) {
	attrs, err := fetchAttributes(ctx, baseURL)
	if err != nil {
		return nil, err
	}
	return specFromAttributes(attrs)
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

func specFromAttributes(attrs map[string]string) (*LaunchSpec, error) {
	if _, ok := attrs[metaImageRef]; !ok {
		return nil, ErrNoMetadataSpec
	}

	s := &LaunchSpec{}
	// Deterministic iteration keeps error messages stable.
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := attrs[key]
		switch {
		case key == metaImageRef:
			s.ImageRef = value
		case key == metaCmd:
			var cmd []string
			if err := json.Unmarshal([]byte(value), &cmd); err != nil {
				return nil, fmt.Errorf("%s must be a JSON string array (e.g. [\"sh\",\"-c\",\"...\"]): %w",
					metaCmd, err)
			}
			s.Cmd = cmd
		case key == metaRestartPolicy:
			s.RestartPolicy = value
		case key == metaAttestAddr:
			s.AttestAddr = value
		case strings.HasPrefix(key, metaEnvPrefix):
			name := strings.TrimPrefix(key, metaEnvPrefix)
			if name == "" {
				return nil, fmt.Errorf("metadata key %q has an empty env var name", key)
			}
			if s.Envs == nil {
				s.Envs = map[string]string{}
			}
			s.Envs[name] = value
		case strings.HasPrefix(key, "tee-"):
			return nil, fmt.Errorf("unknown tee-* metadata key %q (supported: %s, %s, %s, %s, %s<NAME>)",
				key, metaImageRef, metaCmd, metaRestartPolicy, metaAttestAddr, metaEnvPrefix)
		}
	}
	return s, nil
}
