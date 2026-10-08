// The verifier checks attestation evidence produced by the launcher and
// provisions workloads onto verified VMs, from anywhere.
//
// Trust chain: Google's GCE CA (vTPM AK certificate) plus, when present,
// the AMD root of trust (SEV-SNP report whose REPORT_DATA binds the nonce,
// the AK, and the VM's per-boot HPKE public key). Workloads are delivered
// encrypted to that key; what evidence reveals publicly is a commitment
// (hash) of the payload, not its contents.
//
// Subcommands:
//
//	nonce                          generate a fresh challenge
//	fetch     -host H -nonce N     fetch evidence from a launcher
//	verify    -evidence F|-host H  verify evidence against a policy
//	provision -host H -payload F   verify a fresh VM, then send the payload
package main

import (
	"bytes"
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

	"gopkg.in/yaml.v3"

	"github.com/davidcao20/gc-tee-base/internal/attestor"
	"github.com/davidcao20/gc-tee-base/internal/provision"
	"github.com/davidcao20/gc-tee-base/internal/spec"
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
	case "provision":
		err = cmdProvision(os.Args[2:])
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
  verifier fetch     -host HOST:PORT -nonce HEX [-out FILE]
  verifier provision -host HOST:PORT -policy FILE -payload FILE
                     [-expected FILE] [-receipt-out FILE] [-trusted-ak-pub PEM]
  verifier verify    -host HOST:PORT -policy FILE
                     [-receipt FILE | -commitment HEX] [-expected FILE] [-json] [-trusted-ak-pub PEM]
  verifier verify    -evidence FILE -nonce HEX -policy FILE [...]

'provision' verifies a freshly booted base layer (nothing measured yet,
hardware report binds the VM's encryption key), then sends the workload
payload encrypted to that key, and writes a receipt. 'verify' checks a
running VM: pass the receipt (or its commitment) so the policy can require
the exact payload. 'verify -host' generates a nonce, fetches, and verifies
in one shot.
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
	out := fs.String("out", "evidence.json", "output file")
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

// loadPolicyWithExpected loads the policy and merges -expected pins for the
// chosen technology profile: PCR values always; for tdx also the RTMR pins
// (the Intel-rooted base-image identity).
func loadPolicyWithExpected(policyPath, expectedPath, tech string) (*verify.Policy, error) {
	policy, err := verify.LoadPolicy(policyPath)
	if err != nil {
		return nil, err
	}
	if expectedPath == "" {
		return policy, nil
	}
	expected, err := verify.LoadExpectedMeasurements(expectedPath)
	if err != nil {
		return nil, err
	}
	if policy.PCRs != nil {
		return nil, fmt.Errorf("policy already has a pcrs block; drop it or drop -expected")
	}

	var pcrPolicy *verify.PCRPolicy
	switch tech {
	case "tdx":
		if pcrPolicy, err = expected.TDXPCRPolicy(); err != nil {
			return nil, err
		}
		if policy.Hardware == nil {
			policy.Hardware = &verify.HardwarePolicy{}
		}
		if policy.Hardware.TDX == nil {
			policy.Hardware.TDX = &verify.TDXPolicy{}
		}
		if len(policy.Hardware.TDX.Rtmrs) > 0 {
			return nil, fmt.Errorf("policy already pins RTMRs; drop them or drop -expected")
		}
		policy.Hardware.TDX.Rtmrs = expected.TDX.RTMRs
		log.Printf("pinning %d RTMRs (Intel-rooted) from %s", len(expected.TDX.RTMRs), expectedPath)
	case "snp":
		if pcrPolicy, err = expected.PCRPolicy(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown -expected-tech %q (want tdx or snp)", tech)
	}
	policy.PCRs = pcrPolicy
	log.Printf("pinning %d PCRs (%s bank, %s profile) from %s (image %q)",
		len(pcrPolicy.Values), pcrPolicy.Bank, tech, expectedPath, expected.Image)
	return policy, nil
}

// verifyOptions assembles verify.Options from common flags and the policy.
func verifyOptions(nonce []byte, env *wire.Envelope, policy *verify.Policy, trustedAKPem string) (verify.Options, error) {
	opts := verify.Options{Nonce: nonce, HPKEPublicKey: env.HPKEPublicKey}
	if policy.Hardware != nil && policy.Hardware.SNP != nil {
		opts.SNPProductLine = policy.Hardware.SNP.ProductLine
	}
	if trustedAKPem != "" {
		key, err := loadPublicKey(trustedAKPem)
		if err != nil {
			return opts, err
		}
		opts.TrustedAKs = []crypto.PublicKey{key}
		log.Printf("WARNING: using -trusted-ak-pub; evidence is NOT anchored to Google's CA")
	}
	return opts, nil
}

// Receipt records a completed provisioning: everything needed to later
// verify that the exact payload is running. It contains the payload
// plaintext (including env vars) — keep it as private as the payload.
type Receipt struct {
	Host        string          `json:"host"`
	Commitment  string          `json:"commitment"`
	Nonce       string          `json:"nonce"`
	Payload     json.RawMessage `json:"payload"`
	TEE         *verify.TEEResult `json:"tee,omitempty"`
	GCEInstance string          `json:"gceInstance,omitempty"`
	CreatedAt   time.Time       `json:"createdAt"`
}

func cmdProvision(args []string) error {
	fs := flag.NewFlagSet("provision", flag.ExitOnError)
	host := fs.String("host", "", "launcher address HOST:PORT (required)")
	policyPath := fs.String("policy", "", "base policy YAML file (required; workloadCommitment not needed)")
	payloadPath := fs.String("payload", "", "workload payload YAML file: image, cmd, env, restartPolicy (required)")
	expectedPath := fs.String("expected", "",
		"expected-measurements.json from an image build; its PCR (and, for tdx, RTMR) values are pinned in addition to the policy")
	expectedTech := fs.String("expected-tech", "tdx", "which profile of -expected to pin: tdx | snp")
	receiptOut := fs.String("receipt-out", "receipt.json", "where to write the provisioning receipt")
	trustedAKPem := fs.String("trusted-ak-pub", "",
		"PEM file with a trusted AK public key (DEV ONLY: replaces the Google root of trust)")
	fs.Parse(args)
	if *host == "" || *policyPath == "" || *payloadPath == "" {
		return fmt.Errorf("provision requires -host, -policy, and -payload")
	}

	policy, err := loadPolicyWithExpected(*policyPath, *expectedPath, *expectedTech)
	if err != nil {
		return err
	}

	// Read the payload before touching the network so a malformed file
	// cannot strand a half-provisioned VM.
	payloadYAML, err := os.ReadFile(*payloadPath)
	if err != nil {
		return err
	}
	var s spec.LaunchSpec
	if err := yaml.Unmarshal(payloadYAML, &s); err != nil {
		return fmt.Errorf("parsing payload %q: %w", *payloadPath, err)
	}
	plaintext, err := provision.EncodePayload(&provision.Payload{LaunchSpec: s})
	if err != nil {
		return fmt.Errorf("invalid payload %q: %w", *payloadPath, err)
	}
	commitment := provision.Commitment(plaintext)

	// Stage 1: verify the fresh base layer.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	raw, err := fetchEvidence(*host, nonce)
	if err != nil {
		return err
	}
	env, att, err := wire.DecodeEnvelope(raw)
	if err != nil {
		return err
	}
	if len(env.HPKEPublicKey) == 0 {
		return fmt.Errorf("evidence carries no HPKE public key: the launcher is not in provisioning mode " +
			"(already provisioned, or started with -spec)")
	}

	opts, err := verifyOptions(nonce, env, policy, *trustedAKPem)
	if err != nil {
		return err
	}
	result, err := verify.Verify(att, opts)
	if err != nil {
		return err
	}
	if err := result.CheckUnprovisioned(); err != nil {
		return err
	}
	if violations := policy.EvaluateBase(result); len(violations) > 0 {
		fmt.Println("=== BASE POLICY: FAIL — NOT provisioning ===")
		for _, v := range violations {
			fmt.Printf("  - %v\n", v)
		}
		os.Exit(1)
	}
	printPlatform(result)
	if result.TEE == nil {
		log.Printf("WARNING: evidence carries no hardware report; the encryption key is bound only via the vTPM (Google-rooted) chain")
	}

	// Stage 2: the payload only opens on the VM whose evidence we just
	// verified — the transcript ties the HPKE key to this nonce and AK.
	transcript := provision.Transcript(nonce, result.AKPubSPKI, env.HPKEPublicKey)
	ciphertext, err := provision.Seal(env.HPKEPublicKey, transcript, plaintext)
	if err != nil {
		return err
	}
	ack, err := postWorkload(*host, nonce, ciphertext)
	if err != nil {
		return err
	}
	if !strings.EqualFold(ack.Commitment, hex.EncodeToString(commitment)) {
		return fmt.Errorf("launcher acknowledged commitment %s, expected %s", ack.Commitment, hex.EncodeToString(commitment))
	}

	receipt := &Receipt{
		Host:       *host,
		Commitment: hex.EncodeToString(commitment),
		Nonce:      hex.EncodeToString(nonce),
		Payload:    plaintext,
		TEE:        result.TEE,
		CreatedAt:  time.Now().UTC(),
	}
	if info := result.MachineState.GetPlatform().GetInstanceInfo(); info != nil {
		receipt.GCEInstance = fmt.Sprintf("projects/%s/zones/%s/instances/%s",
			info.GetProjectId(), info.GetZone(), info.GetInstanceName())
	}
	receiptJSON, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*receiptOut, receiptJSON, 0o600); err != nil {
		return err
	}

	fmt.Println("=== PROVISIONED ===")
	fmt.Printf("  commitment: %s\n", receipt.Commitment)
	fmt.Printf("  receipt:    %s (contains the payload — keep it private)\n", *receiptOut)
	fmt.Printf("verify later with: verifier verify -host %s -policy %s -receipt %s\n",
		*host, *policyPath, *receiptOut)
	return nil
}

func postWorkload(host string, nonce, ciphertext []byte) (*attestor.WorkloadResponse, error) {
	body, err := json.Marshal(attestor.WorkloadRequest{Nonce: nonce, Ciphertext: ciphertext})
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "http", Host: host, Path: "/v1/workload"}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("posting workload payload: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading workload response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("launcher rejected the payload (%s): %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	var ack attestor.WorkloadResponse
	if err := json.Unmarshal(respBody, &ack); err != nil {
		return nil, fmt.Errorf("parsing workload response: %w", err)
	}
	return &ack, nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	evidencePath := fs.String("evidence", "", "evidence file (from 'verifier fetch')")
	host := fs.String("host", "", "launcher address HOST:PORT (fetch + verify in one shot)")
	nonceHex := fs.String("nonce", "", "hex nonce the evidence was bound to (required with -evidence)")
	policyPath := fs.String("policy", "", "policy YAML file (required)")
	receiptPath := fs.String("receipt", "", "provisioning receipt; its commitment becomes the required workloadCommitment")
	commitmentHex := fs.String("commitment", "", "required workload commitment (hex; alternative to -receipt)")
	expectedPath := fs.String("expected", "",
		"expected-measurements.json from an image build; its PCR (and, for tdx, RTMR) values are pinned in addition to the policy")
	expectedTech := fs.String("expected-tech", "tdx", "which profile of -expected to pin: tdx | snp")
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
	if *receiptPath != "" && *commitmentHex != "" {
		return fmt.Errorf("pass either -receipt or -commitment, not both")
	}

	policy, err := loadPolicyWithExpected(*policyPath, *expectedPath, *expectedTech)
	if err != nil {
		return err
	}
	switch {
	case *receiptPath != "":
		data, err := os.ReadFile(*receiptPath)
		if err != nil {
			return err
		}
		var r Receipt
		if err := json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("parsing receipt %q: %w", *receiptPath, err)
		}
		if policy.WorkloadCommitment != "" && !strings.EqualFold(policy.WorkloadCommitment, r.Commitment) {
			return fmt.Errorf("policy workloadCommitment and receipt commitment disagree")
		}
		policy.WorkloadCommitment = r.Commitment
	case *commitmentHex != "":
		if policy.WorkloadCommitment != "" && !strings.EqualFold(policy.WorkloadCommitment, *commitmentHex) {
			return fmt.Errorf("policy workloadCommitment and -commitment disagree")
		}
		policy.WorkloadCommitment = *commitmentHex
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

	env, att, err := wire.DecodeEnvelope(evidence)
	if err != nil {
		return err
	}
	opts, err := verifyOptions(nonce, env, policy, *trustedAKPem)
	if err != nil {
		return err
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
	if result.TEE != nil {
		out["hardwareReport"] = result.TEE
	}
	if bank, quoted := pinnedPCRs(result, policy); quoted != nil {
		out["quotedPCRs"] = map[string]any{"bank": bank, "values": quoted}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func printPlatform(result *verify.Result) {
	platform := result.MachineState.GetPlatform()
	fmt.Println("=== Verified platform ===")
	fmt.Printf("  confidential tech (boot log): %s\n", platform.GetTechnology())
	if result.TEE != nil {
		root := "AMD-rooted"
		if result.TEE.Kind == string(verify.TEEKindTdx) {
			root = "Intel-rooted"
		}
		fmt.Printf("  hardware report:   %s (%s), launch measurement %s\n",
			result.TEE.Kind, root, result.TEE.Measurement)
		for i, r := range result.TEE.RTMRs {
			fmt.Printf("    RTMR[%d]: %s\n", i, r)
		}
	} else {
		fmt.Printf("  hardware report:   none (vTPM chain only)\n")
	}
	fmt.Printf("  secure boot:       %v\n", result.MachineState.GetSecureBoot().GetEnabled())
	if info := platform.GetInstanceInfo(); info != nil {
		fmt.Printf("  GCE instance:      projects/%s/zones/%s/instances/%s\n",
			info.GetProjectId(), info.GetZone(), info.GetInstanceName())
	} else {
		fmt.Printf("  GCE instance:      (no instance info; dev-mode AK?)\n")
	}
}

func printHuman(result *verify.Result, policy *verify.Policy, violations []error) {
	printPlatform(result)

	c := result.Claims
	fmt.Println("=== Verified workload claims ===")
	fmt.Printf("  provisioned:           %v\n", c.Provisioned)
	if c.Provisioned {
		fmt.Printf("  workload commitment:   %s\n", c.WorkloadCommitment)
		fmt.Printf("  launch separator seen: %v\n", c.SeparatorSeen)
	}

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
