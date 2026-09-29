// dump-eventlog prints the TCG firmware event log carried in attestation
// evidence, filtered to the PCRs relevant for base-image calibration (4 and
// 11 by default). It also folds the events per PCR so the running digest can
// be compared against quoted values — the ground truth for fixing
// predict-measurements' PCR models.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"

	"github.com/davidcao20/gc-tee-base/internal/wire"
)

func main() {
	log.SetFlags(0)
	var (
		evidencePath = flag.String("evidence", "", "evidence file from 'verifier fetch' (required)")
		pcrList      = flag.String("pcrs", "4,11", "comma-separated PCR indices to dump")
	)
	flag.Parse()
	if *evidencePath == "" {
		flag.Usage()
		os.Exit(2)
	}

	wantPCR := map[int]bool{}
	for _, s := range strings.Split(*pcrList, ",") {
		idx, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			log.Fatalf("bad PCR index %q", s)
		}
		wantPCR[idx] = true
	}

	data, err := os.ReadFile(*evidencePath)
	if err != nil {
		log.Fatal(err)
	}
	att, err := wire.Decode(data)
	if err != nil {
		log.Fatal(err)
	}

	eventLog, err := tcg.ParseEventLog(att.GetEventLog(), tcg.ParseOpts{AllowPadding: true})
	if err != nil {
		log.Fatalf("parsing TCG event log: %v", err)
	}

	running := map[int][]byte{}
	for _, event := range eventLog.Events(register.HashSHA256) {
		if !wantPCR[event.Index] {
			continue
		}
		cur, ok := running[event.Index]
		if !ok {
			cur = make([]byte, sha256.Size)
		}
		next := sha256.Sum256(append(cur, event.Digest...))
		running[event.Index] = next[:]

		fmt.Printf("PCR %2d  %-28s digest=%s\n", event.Index,
			tcg.EventTypeNames[event.Type], hex.EncodeToString(event.Digest))
		if printable(event.Data) {
			fmt.Printf("        data: %q\n", string(event.Data))
		} else if len(event.Data) > 0 {
			fmt.Printf("        data: (%d bytes) %s\n", len(event.Data), previewHex(event.Data))
		}
		fmt.Printf("        running PCR: %s\n", hex.EncodeToString(next[:]))
	}

	fmt.Println("=== final folded values (sha256):")
	for idx, digest := range running {
		fmt.Printf("  PCR %2d: %s\n", idx, hex.EncodeToString(digest))
	}
}

func printable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	n := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			n++
		} else if c != 0 {
			return false
		}
	}
	return n*2 >= len(b)
}

func previewHex(b []byte) string {
	if len(b) > 48 {
		return hex.EncodeToString(b[:48]) + "..."
	}
	return hex.EncodeToString(b)
}
