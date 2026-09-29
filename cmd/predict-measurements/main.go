// predict-measurements computes the expected golden PCR values for a
// gc-tee-base measured image build, from the UKI alone — no boot required.
//
// Models calibrated against GCE firmware + systemd-stub on 2026-09-29 (TCG
// log from a live SEV-SNP Confidential VM; see nix/README.md):
//
//	PCR 4:  EV_EFI_ACTION "Calling EFI Application from Boot Option",
//	        EV_SEPARATOR, then ONE EV_EFI_BOOT_SERVICES_APPLICATION event
//	        whose digest is the PE authentihash of the UKI ("uki-only" —
//	        GCE's firmware does not add an event for the embedded kernel).
//	PCR 11: systemd-stub measures each recognized UKI section, in its fixed
//	        section order, as two events: sha256(ASCII section name + NUL)
//	        then sha256(section content as loaded: raw data truncated/zero-
//	        padded to VirtualSize). The image masks all systemd-pcr* units,
//	        so nothing extends PCR 11 after the stub.
//
// IMPORTANT: predict from the UKI that is actually in the image's ESP. The
// build script cross-checks this (an out-of-tree flake eval difference once
// made the standalone UKI differ from the image's in its .cmdline).
//
// Output feeds `verifier verify -expected expected-measurements.json`.
package main

import (
	"crypto"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/edgelesssys/uplosi/measured-boot/measure"

	"github.com/davidcao20/gc-tee-base/internal/verify"
)

// stubSectionOrder is systemd-stub's fixed measurement order for UKI
// sections (UnifiedSection enum order; .pcrsig is never measured). Sections
// absent from the UKI are skipped.
var stubSectionOrder = []string{
	".linux", ".osrel", ".cmdline", ".initrd", ".ucode",
	".splash", ".dtb", ".uname", ".sbat", ".pcrpkey",
	".profile", ".dtbauto", ".hwids",
}

func main() {
	log.SetFlags(0)
	var (
		ukiPath     = flag.String("uki", "", "path to the UKI .efi file (required; must be the image's ESP UKI)")
		imageName   = flag.String("image", "", "GCE image name this build produces")
		roothash    = flag.String("roothash", "", "dm-verity hash sealed in the UKI cmdline (usrhash)")
		pcr4Variant = flag.String("pcr4-variant", "uki-only",
			"PCR 4 model: uki-only (calibrated on GCE) | uki-and-kernel")
		out = flag.String("out", "expected-measurements.json", "output file")
	)
	flag.Parse()
	if *ukiPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*ukiPath, *imageName, *roothash, *pcr4Variant, *out); err != nil {
		log.Fatalf("predict-measurements: %v", err)
	}
}

func run(ukiPath, imageName, roothash, pcr4Variant, out string) error {
	uki, err := os.ReadFile(ukiPath)
	if err != nil {
		return err
	}
	ukiSha := sha256.Sum256(uki)

	pcr11, err := predictPCR11(uki)
	if err != nil {
		return fmt.Errorf("predicting PCR 11: %w", err)
	}
	pcr4, err := predictPCR4Variants(uki)
	if err != nil {
		return fmt.Errorf("predicting PCR 4: %w", err)
	}
	selected, ok := pcr4[pcr4Variant]
	if !ok {
		return fmt.Errorf("unknown -pcr4-variant %q (have: uki-only, uki-and-kernel)", pcr4Variant)
	}

	m := verify.ExpectedMeasurements{
		Image:     imageName,
		UKISha256: hex.EncodeToString(ukiSha[:]),
		Roothash:  roothash,
		PCRs: map[string]map[int]string{
			"sha256": {4: selected, 11: pcr11},
		},
		Notes: fmt.Sprintf("pcr4 variant %q pinned (uki-only calibrated on GCE 2026-09-29); "+
			"candidates: uki-only=%s uki-and-kernel=%s",
			pcr4Variant, pcr4["uki-only"], pcr4["uki-and-kernel"]),
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		return err
	}
	log.Printf("PCR  4 (sha256, %s): %s", pcr4Variant, selected)
	log.Printf("PCR 11 (sha256):     %s", pcr11)
	log.Printf("wrote %s", out)
	return nil
}

func extend(pcr []byte, digest []byte) []byte {
	sum := sha256.Sum256(append(pcr, digest...))
	return sum[:]
}

func hashOf(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// predictPCR11 folds the systemd-stub section measurements.
func predictPCR11(uki []byte) (string, error) {
	f, err := pe.NewFile(&readerAt{data: uki})
	if err != nil {
		return "", fmt.Errorf("parsing UKI as PE: %w", err)
	}
	defer f.Close()

	sections := map[string]*pe.Section{}
	for _, s := range f.Sections {
		sections[s.Name] = s
	}

	pcr := make([]byte, sha256.Size)
	measured := 0
	for _, name := range stubSectionOrder {
		s, ok := sections[name]
		if !ok {
			continue
		}
		// Content as loaded: raw data truncated to VirtualSize, zero-padded
		// if VirtualSize exceeds the raw size.
		n := s.Size // raw size
		if s.VirtualSize < n {
			n = s.VirtualSize
		}
		data := make([]byte, s.VirtualSize)
		copy(data, uki[s.Offset:s.Offset+n])

		pcr = extend(pcr, hashOf(append([]byte(name), 0)))
		pcr = extend(pcr, hashOf(data))
		measured++
	}
	if measured == 0 {
		return "", fmt.Errorf("UKI contains no measurable sections")
	}
	return hex.EncodeToString(pcr), nil
}

// predictPCR4Variants folds the firmware boot-application measurements.
func predictPCR4Variants(uki []byte) (map[string]string, error) {
	ukiHash, err := measure.Authentihash(&fullReader{data: uki}, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("authentihash of UKI: %w", err)
	}

	base := make([]byte, sha256.Size)
	base = extend(base, hashOf([]byte("Calling EFI Application from Boot Option")))
	base = extend(base, hashOf([]byte{0, 0, 0, 0}))
	ukiOnly := extend(base, ukiHash)

	out := map[string]string{
		"uki-only": hex.EncodeToString(ukiOnly),
	}

	// Historical alternative (not what GCE does): a second authentihash
	// event for the embedded kernel PE, as some firmware/stub combinations
	// produce. Kept as a recorded candidate.
	if f, err := pe.NewFile(&readerAt{data: uki}); err == nil {
		if s := f.Section(".linux"); s != nil {
			n := s.Size
			if s.VirtualSize < n {
				n = s.VirtualSize
			}
			kernelHash, err := measure.Authentihash(&fullReader{data: uki[s.Offset : s.Offset+n]}, crypto.SHA256)
			if err == nil {
				out["uki-and-kernel"] = hex.EncodeToString(extend(ukiOnly, kernelHash))
			}
		}
		f.Close()
	}
	if _, ok := out["uki-and-kernel"]; !ok {
		out["uki-and-kernel"] = "(unavailable: no parseable .linux section)"
	}
	return out, nil
}

// readerAt adapts a byte slice to io.ReaderAt.
type readerAt struct{ data []byte }

func (r *readerAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// fullReader is a plain io.Reader over a byte slice.
type fullReader struct {
	data []byte
	pos  int
}

func (r *fullReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
