// predict-measurements computes the expected golden PCR values for a
// gc-tee-base measured image build, from the UKI alone — no boot required.
//
//	PCR 4:  firmware boot-application measurements (EV_EFI_ACTION,
//	        EV_SEPARATOR, then PE authentihashes)
//	PCR 11: systemd-stub UKI section measurements (the image masks all
//	        systemd-pcr* units, so nothing extends PCR 11 after the stub)
//
// PCR 4 has two candidate models until first-boot calibration decides:
// "uki-and-kernel" (the UKI's authentihash plus the embedded .linux PE's,
// measured when systemd-stub LoadImages it — uplosi's model for cloud UKI
// boots, the default) and "uki-only". Both are recorded in the output; the
// selected variant lands in .pcrs, which the verifier pins.
//
// Output feeds `verifier verify -expected expected-measurements.json`.
package main

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/edgelesssys/uplosi/measured-boot/extract"
	"github.com/edgelesssys/uplosi/measured-boot/measure"

	"github.com/davidcao20/gc-tee-base/internal/verify"
)

func main() {
	log.SetFlags(0)
	var (
		ukiPath     = flag.String("uki", "", "path to the UKI .efi file (required)")
		imageName   = flag.String("image", "", "GCE image name this build produces")
		roothash    = flag.String("roothash", "", "dm-verity root hash embedded in the UKI cmdline")
		pcr4Variant = flag.String("pcr4-variant", "uki-and-kernel",
			"which PCR 4 model to pin: uki-and-kernel | uki-only (set after calibration)")
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
	reader := &readerAt{data: uki}

	pcr11, err := predictPCR11(reader)
	if err != nil {
		return fmt.Errorf("predicting PCR 11: %w", err)
	}
	pcr4, err := predictPCR4Variants(reader)
	if err != nil {
		return fmt.Errorf("predicting PCR 4: %w", err)
	}
	selected, ok := pcr4[pcr4Variant]
	if !ok {
		return fmt.Errorf("unknown -pcr4-variant %q (have: uki-and-kernel, uki-only)", pcr4Variant)
	}

	m := verify.ExpectedMeasurements{
		Image:     imageName,
		UKISha256: hex.EncodeToString(ukiSha[:]),
		Roothash:  roothash,
		PCRs: map[string]map[int]string{
			"sha256": {4: selected, 11: pcr11},
		},
		Notes: fmt.Sprintf("pcr4 variant %q pinned; candidates: uki-and-kernel=%s uki-only=%s; "+
			"confirm against the TCG log on first boot (see image/README.md)",
			pcr4Variant, pcr4["uki-and-kernel"], pcr4["uki-only"]),
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

func predictPCR11(uki io.ReaderAt) (string, error) {
	sections, err := extract.PeFileSectionDigests(uki)
	if err != nil {
		return "", fmt.Errorf("extracting UKI sections: %w", err)
	}
	sim := measure.NewDefaultSimulator()
	if err := measure.PredictPCR11(sim, sections); err != nil {
		return "", err
	}
	v := sim.Bank[11]
	return hex.EncodeToString(v[:]), nil
}

func predictPCR4Variants(uki io.ReaderAt) (map[string]string, error) {
	ukiHash, err := authentihash(io.NewSectionReader(uki, 0, 1<<40))
	if err != nil {
		return nil, fmt.Errorf("authentihash of UKI: %w", err)
	}
	linuxReader, err := extract.PeSectionReader(uki, ".linux")
	if err != nil {
		return nil, fmt.Errorf("UKI has no .linux section: %w", err)
	}
	linuxHash, err := authentihash(linuxReader)
	if err != nil {
		return nil, fmt.Errorf("authentihash of embedded kernel: %w", err)
	}

	variants := map[string][]measure.EFIBootStage{
		"uki-only": {
			{Name: "UKI", Digest: ukiHash},
		},
		"uki-and-kernel": {
			{Name: "UKI", Digest: ukiHash},
			{Name: "Linux", Digest: linuxHash},
		},
	}
	out := map[string]string{}
	for name, stages := range variants {
		sim := measure.NewDefaultSimulator()
		if err := measure.PredictPCR4(sim, stages); err != nil {
			return nil, err
		}
		v := sim.Bank[4]
		out[name] = hex.EncodeToString(v[:])
	}
	return out, nil
}

func authentihash(r io.Reader) (measure.PCR256, error) {
	digest, err := measure.Authentihash(r, crypto.SHA256)
	if err != nil {
		return measure.PCR256{}, err
	}
	return measure.PCR256(digest), nil
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
