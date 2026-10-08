// Package provision implements encrypted two-stage workload delivery.
//
// A freshly booted base-layer VM holds a per-boot HPKE keypair whose public
// key is bound into the hardware attestation report: REPORT_DATA carries a
// transcript hash over the verifier's nonce, the vTPM attestation key, and
// the HPKE public key. A provisioner verifies the attestation first, then
// encrypts the workload payload to that key — only the attested VM (not the
// host, not the network) can read it. The launcher measures a commitment
// (hash) of the exact payload bytes into PCR 13, so post-launch evidence
// proves which payload runs without revealing its contents.
package provision

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/davidcao20/gc-tee-base/internal/spec"
)

// Domain separation labels. The transcript label covers the attestation
// binding; the workload label covers payload encryption. Both end in NUL so
// no label is a prefix of another input.
const (
	transcriptLabel = "gc-tee-base/provision/v1\x00"
	workloadLabel   = "gc-tee-base/workload/v1\x00"
)

// SaltSize is the size of the random salt inside a payload. It makes the
// public commitment hash useless for brute-forcing low-entropy payloads.
const SaltSize = 32

// suite returns the fixed HPKE ciphersuite: DHKEM(X25519) + HKDF-SHA256 +
// ChaCha20-Poly1305.
func suite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305()
}

// Transcript computes the 64-byte binding hash placed in the hardware
// report's REPORT_DATA. Inputs are length-prefixed so field boundaries are
// unambiguous. akPubSPKI is the PKIX/DER encoding of the vTPM attestation
// public key; hpkePub is the serialized HPKE public key.
func Transcript(nonce, akPubSPKI, hpkePub []byte) [64]byte {
	h := sha512.New()
	h.Write([]byte(transcriptLabel))
	for _, field := range [][]byte{nonce, akPubSPKI, hpkePub} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(field)))
		h.Write(l[:])
		h.Write(field)
	}
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Commitment is the value measured into PCR 13: a hash of the exact payload
// plaintext bytes the provisioner encrypted. Hashing the received bytes (not
// a re-serialization) means no canonicalization is needed on either side.
func Commitment(plaintext []byte) []byte {
	sum := sha256.Sum256(plaintext)
	return sum[:]
}

// Payload is the workload description a provisioner sends. The embedded
// LaunchSpec's AttestAddr must be empty: the evidence server is already
// listening before the payload arrives.
type Payload struct {
	spec.LaunchSpec
	// Salt is provisioner-chosen randomness (SaltSize bytes) that keeps the
	// public commitment from leaking a guessable payload.
	Salt []byte `json:"salt"`
}

// EncodePayload validates a payload, fills in a random salt if absent, and
// returns the plaintext bytes to encrypt. The returned bytes are what the
// commitment must be computed over.
func EncodePayload(p *Payload) ([]byte, error) {
	p.ApplyDefaults()
	p.AttestAddr = "" // never carried in the payload
	if err := p.LaunchSpec.Validate(); err != nil {
		return nil, err
	}
	if len(p.Salt) == 0 {
		p.Salt = make([]byte, SaltSize)
		if _, err := rand.Read(p.Salt); err != nil {
			return nil, fmt.Errorf("generating payload salt: %w", err)
		}
	}
	if len(p.Salt) < SaltSize {
		return nil, fmt.Errorf("payload salt must be at least %d bytes, got %d", SaltSize, len(p.Salt))
	}
	return json.Marshal(p)
}

// DecodePayload parses received plaintext bytes back into a Payload,
// enforcing the same validity rules the provisioner applied.
func DecodePayload(plaintext []byte) (*Payload, error) {
	var p Payload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("parsing workload payload: %w", err)
	}
	if len(p.Salt) < SaltSize {
		return nil, fmt.Errorf("workload payload salt is missing or too short")
	}
	p.AttestAddr = ""
	p.ApplyDefaults()
	if err := p.LaunchSpec.Validate(); err != nil {
		return nil, fmt.Errorf("invalid workload payload: %w", err)
	}
	return &p, nil
}

// Seal encrypts payload plaintext to the VM's HPKE public key, bound to the
// attestation transcript: a ciphertext only opens on the VM whose evidence
// carried this exact transcript. Returns enc||ciphertext (single blob).
func Seal(hpkePub []byte, transcript [64]byte, plaintext []byte) ([]byte, error) {
	kem, kdf, aead := suite()
	pk, err := kem.NewPublicKey(hpkePub)
	if err != nil {
		return nil, fmt.Errorf("parsing HPKE public key: %w", err)
	}
	info := append([]byte(workloadLabel), transcript[:]...)
	ct, err := hpke.Seal(pk, kdf, aead, info, plaintext)
	if err != nil {
		return nil, fmt.Errorf("HPKE seal: %w", err)
	}
	return ct, nil
}

// Receiver holds the per-boot HPKE keypair and latches on the first payload
// that decrypts successfully.
type Receiver struct {
	key hpke.PrivateKey

	mu       sync.Mutex
	accepted []byte // plaintext of the accepted payload, nil until latched
}

// NewReceiver generates a fresh in-memory keypair. The private key never
// leaves the process; a reboot or restart discards it, which invalidates any
// evidence (and ciphertext) bound to it.
func NewReceiver() (*Receiver, error) {
	kem, _, _ := suite()
	key, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating HPKE keypair: %w", err)
	}
	return &Receiver{key: key}, nil
}

// PublicKey returns the serialized HPKE public key for inclusion in
// attestation evidence.
func (r *Receiver) PublicKey() []byte {
	return r.key.PublicKey().Bytes()
}

// Accept decrypts a posted ciphertext under the transcript for the given
// nonce and latches on first success: exactly one payload is ever accepted.
// The caller supplies akPubSPKI so the transcript matches what Attest put in
// REPORT_DATA. The returned bytes are the payload plaintext (hash them for
// the commitment).
func (r *Receiver) Accept(nonce, akPubSPKI, ciphertext []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.accepted != nil {
		return nil, ErrAlreadyProvisioned
	}
	transcript := Transcript(nonce, akPubSPKI, r.PublicKey())
	_, kdf, aead := suite()
	info := append([]byte(workloadLabel), transcript[:]...)
	plaintext, err := hpke.Open(r.key, kdf, aead, info, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("payload does not decrypt for this VM and nonce: %w", err)
	}
	r.accepted = plaintext
	return plaintext, nil
}

// Accepted returns the latched payload plaintext, or nil before provisioning.
func (r *Receiver) Accepted() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.accepted
}

// ErrAlreadyProvisioned is returned by Accept after a payload has latched.
var ErrAlreadyProvisioned = fmt.Errorf("a workload payload was already accepted")
