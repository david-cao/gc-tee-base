// Package wire encodes attestation evidence for transport and storage. The
// canonical format is the raw pb.Attestation protobuf; protojson is supported
// for human inspection. Decoding sniffs the format.
package wire

import (
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
