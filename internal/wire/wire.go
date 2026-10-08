// Package wire encodes attestation evidence for transport and storage. The
// canonical format is the raw pb.Attestation protobuf; protojson is supported
// for human inspection. Decoding sniffs the format.
package wire

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

// Format identifies an evidence encoding.
type Format string

const (
	FormatProto Format = "proto"
	FormatJSON  Format = "json"
)

// Encode serializes an attestation in the given format.
func Encode(att *attestpb.Attestation, f Format) ([]byte, error) {
	switch f {
	case FormatProto:
		return proto.Marshal(att)
	case FormatJSON:
		return protojson.MarshalOptions{Multiline: true}.Marshal(att)
	default:
		return nil, fmt.Errorf("unknown evidence format %q", f)
	}
}

// Envelope wraps an attestation with the provisioning material that has no
// slot in pb.Attestation: the per-boot HPKE public key (bound into the
// hardware report's REPORT_DATA via the transcript) and which TEE produced
// the hardware report. This is the transport format of /v1/attestation.
type Envelope struct {
	Version       int    `json:"version"`
	Attestation   []byte `json:"attestation"` // proto-encoded pb.Attestation
	HPKEPublicKey []byte `json:"hpkePublicKey,omitempty"`
	TEEKind       string `json:"teeKind,omitempty"`
}

// EnvelopeVersion is the current envelope format version.
const EnvelopeVersion = 1

// EncodeEnvelope serializes evidence plus provisioning material as JSON.
func EncodeEnvelope(att *attestpb.Attestation, hpkePub []byte, teeKind string) ([]byte, error) {
	raw, err := proto.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("encoding attestation: %w", err)
	}
	return json.Marshal(&Envelope{
		Version:       EnvelopeVersion,
		Attestation:   raw,
		HPKEPublicKey: hpkePub,
		TEEKind:       teeKind,
	})
}

// DecodeEnvelope parses evidence: an Envelope (canonical), or a bare
// attestation in either legacy format (then the envelope carries no HPKE
// key or TEE kind).
func DecodeEnvelope(data []byte) (*Envelope, *attestpb.Attestation, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("empty evidence")
	}
	if data[0] == '{' {
		var env Envelope
		if err := json.Unmarshal(data, &env); err == nil && len(env.Attestation) > 0 {
			att := &attestpb.Attestation{}
			if err := proto.Unmarshal(env.Attestation, att); err != nil {
				return nil, nil, fmt.Errorf("parsing attestation inside envelope: %w", err)
			}
			return &env, att, nil
		}
	}
	att, err := Decode(data)
	if err != nil {
		return nil, nil, err
	}
	return &Envelope{Version: 0, Attestation: data}, att, nil
}

// Decode parses evidence in either format, sniffing JSON by its first byte.
func Decode(data []byte) (*attestpb.Attestation, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty evidence")
	}
	att := &attestpb.Attestation{}
	if data[0] == '{' {
		if err := protojson.Unmarshal(data, att); err != nil {
			return nil, fmt.Errorf("parsing JSON evidence: %w", err)
		}
		return att, nil
	}
	if err := proto.Unmarshal(data, att); err != nil {
		return nil, fmt.Errorf("parsing protobuf evidence: %w", err)
	}
	return att, nil
}
