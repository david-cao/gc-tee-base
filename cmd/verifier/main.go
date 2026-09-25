// The verifier checks attestation evidence produced by the launcher, from
// anywhere: it trusts Google's bundled GCE CA roots (the vTPM attestation key
// certificate must chain to them), verifies the quote against a fresh nonce,
// replays the event logs, and evaluates a user policy over the extracted
// container claims.
//
// Subcommands:
//
//	nonce                     generate a fresh challenge
//	fetch  -host H -nonce N   fetch evidence from a launcher
//	verify -evidence F|-host H [-nonce N] -policy P
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/davidcao20/gc-tee-base/internal/verify"
	"github.com/davidcao20/gc-tee-base/internal/wire"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "nonce":
		err = cmdNonce()
	case "fetch":
		err = cmdFetch(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("verifier: %v", err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  verifier nonce
  verifier fetch  -host HOST:PORT -nonce HEX [-out FILE]
  verifier verify -evidence FILE -nonce HEX -policy FILE [-json] [-trusted-ak-pub PEM]
  verifier verify -host HOST:PORT -policy FILE [-json] [-trusted-ak-pub PEM]

'verify -host' generates a nonce, fetches evidence, and verifies in one shot.
`)
}

func cmdNonce() error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(nonce))
	return nil
}

func fetchEvidence(host string, nonce []byte) ([]byte, error) {
	u := url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     "/v1/attestation",
		RawQuery: url.Values{"nonce": {hex.EncodeToString(nonce)}}.Encode(),
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("fetching evidence: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading evidence response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("launcher returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	host := fs.String("host", "", "launcher address HOST:PORT (required)")
	nonceHex := fs.String("nonce", "", "hex nonce (required; see 'verifier nonce')")
	out := fs.String("out", "evidence.pb", "output file")
	fs.Parse(args)
	if *host == "" || *nonceHex == "" {
		return fmt.Errorf("fetch requires -host and -nonce")
	}
	nonce, err := hex.DecodeString(*nonceHex)
	if err != nil {
		return fmt.Errorf("nonce must be hex: %w", err)
	}
	data, err := fetchEvidence(*host, nonce)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return err
	}
	log.Printf("wrote %d bytes of evidence to %s", len(data), *out)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	evidencePath := fs.String("evidence", "", "evidence file (from 'verifier fetch')")
	host := fs.String("host", "", "launcher address HOST:PORT (fetch + verify in one shot)")
	nonceHex := fs.String("nonce", "", "hex nonce the evidence was bound to (required with -evidence)")
	policyPath := fs.String("policy", "", "policy YAML file (required)")
	expectedPath := fs.String("expected", "",
		"expected-measurements.json from an image build; its PCR values are pinned in addition to the policy")
	jsonOut := fs.Bool("json", false, "print the verification result as JSON")
	trustedAKPem := fs.String("trusted-ak-pub", "",
		"PEM file with a trusted AK public key (DEV ONLY: replaces the Google root of trust)")
	fs.Parse(args)

	if *policyPath == "" {
		return fmt.Errorf("verify requires -policy")
	}
	if (*evidencePath == "") == (*host == "") {
		return fmt.Errorf("verify requires exactly one of -evidence or -host")
	}

	policy, err := verify.LoadPolicy(*policyPath)
	if err != nil {
		return err
	}
	if *expectedPath != "" {
		expected, err := verify.LoadExpectedMeasurements(*expectedPath)
		if err != nil {
			return err
		}
		pcrPolicy, err := expected.PCRPolicy()
		if err != nil {
			return err
		}
		if policy.PCRs != nil {
			return fmt.Errorf("policy already has a pcrs block; drop it or drop -expected")
		}
		policy.PCRs = pcrPolicy
		log.Printf("pinning %d PCRs (%s bank) from %s (image %q)",
			len(pcrPolicy.Values), pcrPolicy.Bank, *expectedPath, expected.Image)
	}

	var nonce, evidence []byte
	if *host != "" {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		if evidence, err = fetchEvidence(*host, nonce); err != nil {
			return err
		}
	} else {
		if *nonceHex == "" {
			return fmt.Errorf("-evidence requires -nonce (the challenge the evidence was bound to)")
		}
		if nonce, err = hex.DecodeString(*nonceHex); err != nil {
			return fmt.Errorf("nonce must be hex: %w", err)
		}
		if evidence, err = os.ReadFile(*evidencePath); err != nil {
			return err
		}
	}

	att, err := wire.Decode(evidence)
	if err != nil {
		return err
	}

	opts := verify.Options{Nonce: nonce}
	if *trustedAKPem != "" {
		key, err := loadPublicKey(*trustedAKPem)
		if err != nil {
			return err
		}
		opts.TrustedAKs = []crypto.PublicKey{key}
		log.Printf("WARNING: using -trusted-ak-pub; evidence is NOT anchored to Google's CA")
	}

	result, err := verify.Verify(att, opts)
	if err != nil {
		return err
	}
	violations := policy.Evaluate(result)

	if *jsonOut {
		printJSON(result, policy, violations)
	} else {
		printHuman(result, policy, violations)
	}
	if len(violations) > 0 {
		os.Exit(1)
	}
	return nil
}

func loadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: parsing public key: %w", path, err)
	}
	return key, nil
}

// pinnedPCRs returns "index → quoted hex value" for the bank the policy pins.
func pinnedPCRs(result *verify.Result, policy *verify.Policy) (string, map[int]string) {
	if policy.PCRs == nil {
		return "", nil
	}
	bank := policy.PCRs.Bank
	if bank == "" {
		bank = "sha256"
	}
	out := map[int]string{}
	for idx := range policy.PCRs.Values {
		if got, ok := result.PCRs[bank][idx]; ok {
			out[idx] = hex.EncodeToString(got)
		} else {
			out[idx] = "(missing)"
		}
	}
	return bank, out
}

func printJSON(result *verify.Result, policy *verify.Policy, violations []error) {
	msgs := make([]string, len(violations))
	for i, v := range violations {
		msgs[i] = v.Error()
	}
	platform := result.MachineState.GetPlatform()
	out := map[string]any{
		"policyPassed":     len(violations) == 0,
		"policyViolations": msgs,
		"claims":           result.Claims,
		"platform": map[string]any{
			"confidentialTechnology": platform.GetTechnology().String(),
			"secureBoot":             result.MachineState.GetSecureBoot().GetEnabled(),
			"gceInstance":            platform.GetInstanceInfo(),
		},
	}
	if bank, quoted := pinnedPCRs(result, policy); quoted != nil {
		out["quotedPCRs"] = map[string]any{"bank": bank, "values": quoted}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func printHuman(result *verify.Result, policy *verify.Policy, violations []error) {
	c := result.Claims
	platform := result.MachineState.GetPlatform()

	fmt.Println("=== Verified platform ===")
	fmt.Printf("  confidential tech: %s\n", platform.GetTechnology())
	fmt.Printf("  secure boot:       %v\n", result.MachineState.GetSecureBoot().GetEnabled())
	if info := platform.GetInstanceInfo(); info != nil {
		fmt.Printf("  GCE instance:      projects/%s/zones/%s/instances/%s\n",
			info.GetProjectId(), info.GetZone(), info.GetInstanceName())
	} else {
		fmt.Printf("  GCE instance:      (no instance info; dev-mode AK?)\n")
	}

	fmt.Println("=== Verified container claims ===")
	fmt.Printf("  image ref:      %s\n", c.ImageRef)
	fmt.Printf("  image digest:   %s\n", c.ImageDigest)
	fmt.Printf("  image id:       %s\n", c.ImageID)
	fmt.Printf("  restart policy: %s\n", c.RestartPolicy)
	fmt.Printf("  args:           %v\n", c.Args)
	if len(c.EnvVars) > 0 {
		fmt.Printf("  env vars:       %v\n", c.EnvVars)
	}
	if len(c.OverriddenArgs) > 0 {
		fmt.Printf("  overridden args: %v\n", c.OverriddenArgs)
	}
	if len(c.OverriddenEnvVars) > 0 {
		fmt.Printf("  overridden envs: %v\n", c.OverriddenEnvVars)
	}
	fmt.Printf("  launch separator seen: %v\n", c.SeparatorSeen)

	if bank, quoted := pinnedPCRs(result, policy); quoted != nil {
		fmt.Printf("=== Quoted PCRs (%s, pinned by policy) ===\n", bank)
		indices := make([]int, 0, len(quoted))
		for idx := range quoted {
			indices = append(indices, idx)
		}
		sort.Ints(indices)
		for _, idx := range indices {
			fmt.Printf("  PCR %2d: %s\n", idx, quoted[idx])
		}
	}

	if len(violations) == 0 {
		fmt.Println("=== POLICY: PASS ===")
	} else {
		fmt.Println("=== POLICY: FAIL ===")
		for _, v := range violations {
			fmt.Printf("  - %v\n", v)
		}
	}
}
