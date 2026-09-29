package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestGarbageInputErrors(t *testing.T) {
	garbage := []byte("this is not a PE file at all")
	if _, err := predictPCR11(garbage); err == nil {
		t.Error("predictPCR11 accepted garbage input")
	}
	if _, err := predictPCR4Variants(garbage); err == nil {
		t.Error("predictPCR4Variants accepted garbage input")
	}
}

func TestRunUnknownInput(t *testing.T) {
	dir := t.TempDir()
	uki := filepath.Join(dir, "uki.efi")
	if err := os.WriteFile(uki, []byte("not a pe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(uki, "img", "hash", "uki-only", filepath.Join(dir, "out.json")); err == nil {
		t.Error("run on a non-PE file did not error")
	}
}

// TestRealUKI validates prediction against a real UKI when one is available
// (set GC_TEE_UKI_PATH; used during image-build calibration). The values it
// prints were confirmed against a live GCE SEV-SNP VM on 2026-09-29 — see
// nix/README.md calibration results.
func TestRealUKI(t *testing.T) {
	ukiPath := os.Getenv("GC_TEE_UKI_PATH")
	if ukiPath == "" {
		t.Skip("set GC_TEE_UKI_PATH to a real UKI to run")
	}
	out := filepath.Join(t.TempDir(), "expected.json")
	if err := run(ukiPath, "test-image", "", "uki-only", out); err != nil {
		t.Fatalf("run: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("expected measurements:\n%s", data)
}

func TestReaderAt(t *testing.T) {
	r := &readerAt{data: []byte("hello world")}
	buf := make([]byte, 5)
	if n, err := r.ReadAt(buf, 6); err != nil && err != io.EOF || n != 5 || !bytes.Equal(buf, []byte("world")) {
		t.Errorf("ReadAt = %d, %v, %q", n, err, buf)
	}
	if _, err := r.ReadAt(buf, 100); err != io.EOF {
		t.Errorf("past-end ReadAt err = %v, want EOF", err)
	}
}

func TestFullReader(t *testing.T) {
	r := &fullReader{data: []byte("abc")}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, []byte("abc")) {
		t.Errorf("ReadAll = %q, %v", got, err)
	}
}
