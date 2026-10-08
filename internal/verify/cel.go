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
	"encoding/hex"
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

	"github.com/davidcao20/gc-tee-base/internal/measure"
)

// Claims is the workload state extracted from a successfully replayed
// canonical event log. Every field was verified against the vTPM quote.
//
// The log carries a commitment (hash of the exact payload plaintext), not
// the workload details themselves: whoever knows the payload can check the
// commitment; everyone else learns only that *some* committed payload runs.
type Claims struct {
	// Provisioned is false for a fresh base layer: empty event log, PCR 13
	// still zero, no workload accepted yet.
	Provisioned bool `json:"provisioned"`
	// WorkloadCommitment is the hex sha256 of the provisioned payload bytes.
	WorkloadCommitment string `json:"workloadCommitment,omitempty"`
	// SeparatorSeen means measurement was sealed before launch.
	SeparatorSeen bool `json:"separatorSeen"`
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
		// Fresh base layer: nothing measured yet. The unprovisioned state is
		// confirmed by the PCR 13 zero check (see VerifyUnprovisioned).
		return &Claims{Provisioned: false}, nil
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
// A well-formed log is exactly one WorkloadCommitment followed by the
// LaunchSeparator.
func claimsFromCEL(decoded gecel.CEL) (*Claims, error) {
	claims := &Claims{Provisioned: true}

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

		switch cosTlv.EventType {
		case measure.WorkloadCommitmentType:
			if claims.WorkloadCommitment != "" {
				return nil, fmt.Errorf("found more than one WorkloadCommitment event")
			}
			if len(cosTlv.EventContent) != crypto.SHA256.Size() {
				return nil, fmt.Errorf("WorkloadCommitment event has %d bytes, want %d",
					len(cosTlv.EventContent), crypto.SHA256.Size())
			}
			claims.WorkloadCommitment = hex.EncodeToString(cosTlv.EventContent)
		case tpmtoolscel.LaunchSeparatorType:
			claims.SeparatorSeen = true
		default:
			return nil, fmt.Errorf("found unsupported COS event type %v", cosTlv.EventType)
		}
	}
	if claims.WorkloadCommitment == "" {
		return nil, fmt.Errorf("event log has no WorkloadCommitment event")
	}
	return claims, nil
}
