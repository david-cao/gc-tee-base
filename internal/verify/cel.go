// CEL verification: replays the attestation's canonical event log against a
// quote-verified PCR bank and extracts container identity claims.
//
// This is a port of getVerifiedCosState/parseCanonicalEventLog from
// go-tpm-tools v0.4.4 server/eventlog.go (removed upstream in later versions)
// onto the current go-eventlog API.
package verify

import (
	"bytes"
	"crypto"
	"fmt"
	"sort"

	gecel "github.com/google/go-eventlog/cel"
	statepb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	tpmtoolscel "github.com/google/go-tpm-tools/cel"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/quote"
	"github.com/google/go-tpm/legacy/tpm2"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

// Claims is the container identity extracted from a successfully replayed
// canonical event log. Every field was verified against the vTPM quote.
type Claims struct {
	ImageRef          string            `json:"imageRef"`
	ImageDigest       string            `json:"imageDigest"`
	ImageID           string            `json:"imageID"`
	RestartPolicy     string            `json:"restartPolicy"`
	Args              []string          `json:"args"`
	EnvVars           map[string]string `json:"envVars"`
	OverriddenArgs    []string          `json:"overriddenArgs"`
	OverriddenEnvVars map[string]string `json:"overriddenEnvVars"`
	SeparatorSeen     bool              `json:"separatorSeen"`
}

// quotePreference orders PCR banks from most to least preferred for CEL
// replay.
var quotePreference = []tpm2.Algorithm{
	tpm2.AlgSHA384,
	tpm2.AlgSHA256,
	tpm2.AlgSHA1,
}

// VerifiedClaims re-verifies one quote against the AK public key and nonce,
// replays the canonical event log against that quote's PCR bank, and parses
// the container claims. The quote re-verification makes this function
// self-contained: the returned claims are trustworthy iff akPub is.
func VerifiedClaims(att *attestpb.Attestation, akPub crypto.PublicKey, nonce []byte) (*Claims, error) {
	if len(att.GetCanonicalEventLog()) == 0 {
		return nil, fmt.Errorf("attestation has no canonical event log")
	}

	q, err := chooseQuote(att.GetQuotes())
	if err != nil {
		return nil, err
	}
	if err := quote.Verify(q, akPub, nonce); err != nil {
		return nil, fmt.Errorf("verifying quote for CEL replay: %w", err)
	}

	bank, err := PCRBankFromProto(q.GetPcrs())
	if err != nil {
		return nil, err
	}

	decoded, err := gecel.DecodeToCEL(bytes.NewBuffer(att.GetCanonicalEventLog()))
	if err != nil {
		return nil, fmt.Errorf("decoding canonical event log: %w", err)
	}
	if err := decoded.Replay(bank); err != nil {
		return nil, fmt.Errorf("replaying canonical event log against quoted PCRs: %w", err)
	}

	return claimsFromCEL(decoded)
}

func chooseQuote(quotes []*tpmpb.Quote) (*tpmpb.Quote, error) {
	for _, alg := range quotePreference {
		for _, q := range quotes {
			if tpm2.Algorithm(q.GetPcrs().GetHash()) == alg {
				return q, nil
			}
		}
	}
	return nil, fmt.Errorf("attestation contains no quote with a supported PCR bank")
}

// PCRBankFromProto converts go-tpm-tools PCR values into a go-eventlog bank
// suitable for CEL replay.
func PCRBankFromProto(pcrs *tpmpb.PCRs) (register.PCRBank, error) {
	// go-tpm-tools and go-eventlog HashAlgo enums both use raw TPM2 algorithm
	// IDs, so the cast is value-preserving.
	alg := tpm2.Algorithm(pcrs.GetHash())
	cryptoHash, err := alg.Hash()
	if err != nil {
		return register.PCRBank{}, fmt.Errorf("unsupported PCR bank algorithm %v: %w", alg, err)
	}
	bank := register.PCRBank{TCGHashAlgo: statepb.HashAlgo(pcrs.GetHash())}
	for idx, digest := range pcrs.GetPcrs() {
		bank.PCRs = append(bank.PCRs, register.PCR{
			Index:     int(idx),
			Digest:    digest,
			DigestAlg: cryptoHash,
		})
	}
	sort.Slice(bank.PCRs, func(i, j int) bool { return bank.PCRs[i].Index < bank.PCRs[j].Index })
	return bank, nil
}

// claimsFromCEL walks the replayed records and folds them into Claims. Any
// record we do not fully understand is an error: since unknown content cannot
// be interpreted, accepting it would let unmeasured semantics hide in the log.
func claimsFromCEL(decoded gecel.CEL) (*Claims, error) {
	claims := &Claims{
		Args:              []string{},
		EnvVars:           map[string]string{},
		OverriddenArgs:    []string{},
		OverriddenEnvVars: map[string]string{},
	}

	for _, record := range decoded.Records() {
		if record.IndexType != gecel.PCRType {
			return nil, fmt.Errorf("found non-PCR record (type %d) in CEL", record.IndexType)
		}
		if int(record.Index) != tpmtoolscel.CosEventPCR {
			return nil, fmt.Errorf("found unexpected PCR %d in CEL (only PCR %d is allowed)",
				record.Index, tpmtoolscel.CosEventPCR)
		}

		cosTlv, err := tpmtoolscel.ParseToCosTlv(record.Content)
		if err != nil {
			return nil, fmt.Errorf("parsing CEL record %d: %w", record.RecNum, err)
		}
		// Replay only proved the record digests fold into the PCR; this ties
		// the content bytes to those digests.
		if err := gecel.VerifyDigests(cosTlv, record.Digests); err != nil {
			return nil, fmt.Errorf("content digest mismatch in CEL record %d: %w", record.RecNum, err)
		}

		if claims.SeparatorSeen {
			return nil, fmt.Errorf("found COS event type %v after LaunchSeparator event", cosTlv.EventType)
		}

		content := string(cosTlv.EventContent)
		switch cosTlv.EventType {
		case tpmtoolscel.ImageRefType:
			if claims.ImageRef != "" {
				return nil, fmt.Errorf("found more than one ImageRef event")
			}
			claims.ImageRef = content
		case tpmtoolscel.ImageDigestType:
			if claims.ImageDigest != "" {
				return nil, fmt.Errorf("found more than one ImageDigest event")
			}
			claims.ImageDigest = content
		case tpmtoolscel.ImageIDType:
			if claims.ImageID != "" {
				return nil, fmt.Errorf("found more than one ImageID event")
			}
			claims.ImageID = content
		case tpmtoolscel.RestartPolicyType:
			if _, ok := attestpb.RestartPolicy_value[content]; !ok {
				return nil, fmt.Errorf("unknown restart policy in CEL: %q", content)
			}
			if claims.RestartPolicy != "" {
				return nil, fmt.Errorf("found more than one RestartPolicy event")
			}
			claims.RestartPolicy = content
		case tpmtoolscel.ArgType:
			claims.Args = append(claims.Args, content)
		case tpmtoolscel.EnvVarType:
			name, value, err := tpmtoolscel.ParseEnvVar(content)
			if err != nil {
				return nil, fmt.Errorf("parsing EnvVar event: %w", err)
			}
			claims.EnvVars[name] = value
		case tpmtoolscel.OverrideArgType:
			claims.OverriddenArgs = append(claims.OverriddenArgs, content)
		case tpmtoolscel.OverrideEnvType:
			name, value, err := tpmtoolscel.ParseEnvVar(content)
			if err != nil {
				return nil, fmt.Errorf("parsing OverrideEnv event: %w", err)
			}
			claims.OverriddenEnvVars[name] = value
		case tpmtoolscel.LaunchSeparatorType:
			claims.SeparatorSeen = true
		default:
			return nil, fmt.Errorf("found unsupported COS event type %v", cosTlv.EventType)
		}
	}
	return claims, nil
}
