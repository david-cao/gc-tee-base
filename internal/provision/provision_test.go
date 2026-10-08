package provision

import (
	"bytes"
	"testing"

	"github.com/davidcao20/gc-tee-base/internal/spec"
)

func testPayload(t *testing.T) []byte {
	t.Helper()
	plaintext, err := EncodePayload(&Payload{
		LaunchSpec: spec.LaunchSpec{
			ImageRef: "docker.io/library/busybox@sha256:aaaa",
			Cmd:      []string{"sh", "-c", "echo hi"},
			Envs:     map[string]string{"SECRET": "hunter2"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

func TestSealOpenRoundtrip(t *testing.T) {
	r, err := NewReceiver()
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("0123456789abcdef0123456789abcdef")
	akPub := []byte("fake-ak-spki")
	plaintext := testPayload(t)

	transcript := Transcript(nonce, akPub, r.PublicKey())
	ct, err := Seal(r.PublicKey(), transcript, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Accept(nonce, akPub, ct)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("decrypted payload differs from plaintext")
	}

	p, err := DecodePayload(got)
	if err != nil {
		t.Fatal(err)
	}
	if p.ImageRef != "docker.io/library/busybox@sha256:aaaa" || p.Envs["SECRET"] != "hunter2" {
		t.Errorf("payload = %+v", p)
	}
	if p.RestartPolicy != spec.RestartNever {
		t.Errorf("RestartPolicy default = %q", p.RestartPolicy)
	}

	// Latch: a second accept fails even with the same valid ciphertext.
	if _, err := r.Accept(nonce, akPub, ct); err == nil {
		t.Error("second Accept succeeded, want latch error")
	}
	if !bytes.Equal(r.Accepted(), plaintext) {
		t.Error("Accepted() does not return the latched payload")
	}
}

// Each transcript input must be bound: changing any of them makes the
// ciphertext undecryptable.
func TestTranscriptBinding(t *testing.T) {
	r, err := NewReceiver()
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("0123456789abcdef0123456789abcdef")
	akPub := []byte("fake-ak-spki")
	plaintext := testPayload(t)
	transcript := Transcript(nonce, akPub, r.PublicKey())
	ct, err := Seal(r.PublicKey(), transcript, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := r.Accept([]byte("ffffffffffffffffffffffffffffffff"), akPub, ct); err == nil {
		t.Error("wrong nonce decrypted")
	}
	if _, err := r.Accept(nonce, []byte("other-ak"), ct); err == nil {
		t.Error("wrong AK decrypted")
	}
	other, err := NewReceiver()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Accept(nonce, akPub, ct); err == nil {
		t.Error("wrong receiver key decrypted")
	}
	// Unchanged inputs still work (the failures above must not latch).
	if _, err := r.Accept(nonce, akPub, ct); err != nil {
		t.Errorf("correct inputs rejected after failed attempts: %v", err)
	}
}

// Transcript framing: moving a byte between adjacent fields must change the
// transcript (length prefixes prevent ambiguity).
func TestTranscriptFraming(t *testing.T) {
	a := Transcript([]byte("ab"), []byte("c"), []byte("d"))
	b := Transcript([]byte("a"), []byte("bc"), []byte("d"))
	if a == b {
		t.Error("field-boundary shift produced the same transcript")
	}
}

func TestCommitmentIsOverExactBytes(t *testing.T) {
	p1 := testPayload(t)
	p2 := testPayload(t)
	// Different salts → different bytes → different commitments.
	if bytes.Equal(p1, p2) {
		t.Fatal("two EncodePayload calls produced identical bytes (salt missing?)")
	}
	if bytes.Equal(Commitment(p1), Commitment(p2)) {
		t.Error("different payloads share a commitment")
	}
	if !bytes.Equal(Commitment(p1), Commitment(append([]byte{}, p1...))) {
		t.Error("commitment is not deterministic over the same bytes")
	}
}

func TestDecodePayloadRejectsInvalid(t *testing.T) {
	cases := map[string][]byte{
		"not json":      []byte("nope"),
		"missing salt":  []byte(`{"image":"busybox"}`),
		"missing image": []byte(`{"salt":"` + string(bytes.Repeat([]byte("A"), 44)) + `"}`),
	}
	for name, data := range cases {
		if _, err := DecodePayload(data); err == nil {
			t.Errorf("%s: DecodePayload accepted invalid input", name)
		}
	}
}

func TestEncodePayloadValidates(t *testing.T) {
	if _, err := EncodePayload(&Payload{}); err == nil {
		t.Error("payload without image accepted")
	}
	if _, err := EncodePayload(&Payload{LaunchSpec: spec.LaunchSpec{
		ImageRef:      "busybox",
		RestartPolicy: "Sometimes",
	}}); err == nil {
		t.Error("payload with bad restart policy accepted")
	}
}
