// The launcher runs one attestable container on a confidential VM.
//
// It boots into provisioning mode: it generates a per-boot HPKE keypair,
// starts the attestation evidence server, and waits. A remote provisioner
// verifies the evidence (vTPM chain + hardware report binding the HPKE key)
// and then POSTs the workload spec encrypted to that key. The launcher
// decrypts it, measures a commitment (hash) of the exact payload bytes into
// vTPM PCR 13, and only then pulls and starts the workload. Post-launch
// evidence proves which payload runs without revealing its contents.
//
// For local development, -spec skips provisioning and supplies the payload
// from a file.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/davidcao20/gc-tee-base/internal/attestor"
	"github.com/davidcao20/gc-tee-base/internal/measure"
	"github.com/davidcao20/gc-tee-base/internal/provision"
	"github.com/davidcao20/gc-tee-base/internal/runtime"
	"github.com/davidcao20/gc-tee-base/internal/spec"
)

const version = "0.2.0"

func main() {
	if err := run(); err != nil {
		log.Fatalf("launcher: %v", err)
	}
}

func run() error {
	var (
		specPath = flag.String("spec", "",
			"path to a launch spec YAML file (DEV ONLY: skips encrypted provisioning)")
		attestAddr = flag.String("attest-addr", "",
			"attestation server listen address (default: tee-attest-addr metadata or "+spec.DefaultAttestAddr+")")
		akType = flag.String("ak", string(attestor.AKGceECC),
			"attestation key: gce-ecc | gce-rsa | owner-ecc (owner-ecc is for dev TPMs only)")
		socket    = flag.String("containerd-socket", runtime.DefaultSocket, "containerd socket path")
		namespace = flag.String("containerd-namespace", runtime.DefaultNamespace, "containerd namespace")
		linger    = flag.Bool("linger", false,
			"keep serving attestation evidence after a one-shot workload exits, until signaled")
		metadataBase = flag.String("metadata-base", spec.DefaultMetadataBase,
			"metadata server base URL (for testing)")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// TPM and attestation key first: fail before serving anything if the
	// attestation side cannot work.
	tpm, err := attestor.OpenTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	measurer, err := measure.New(tpm)
	if err != nil {
		return err
	}

	// The per-boot HPKE keypair. In provisioning mode its public key is
	// bound into every attestation; -spec mode needs no receiver.
	var receiver *provision.Receiver
	var hpkePub []byte
	if *specPath == "" {
		if receiver, err = provision.NewReceiver(); err != nil {
			return err
		}
		hpkePub = receiver.PublicKey()
	}

	att, err := attestor.New(tpm, measurer, attestor.AKType(*akType), attestor.DetectTEE(), hpkePub)
	if err != nil {
		return err
	}
	defer att.Close()
	log.Printf("hardware report device: %s", att.TEEKind())

	addr := *attestAddr
	if addr == "" {
		mdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		mdAddr, err := spec.AttestAddrFromMetadata(mdCtx, *metadataBase)
		cancel()
		if err != nil {
			log.Printf("no attest addr from metadata (%v); using default", err)
		}
		if addr = mdAddr; addr == "" {
			addr = spec.DefaultAttestAddr
		}
	}

	rt, err := runtime.NewContainerd(*socket, *namespace)
	if err != nil {
		return err
	}
	defer rt.Close()

	// Mutable state behind /v1/status.
	var (
		statusMu       sync.Mutex
		commitmentHex  string
		containerState = "provisioning"
	)
	setStatus := func(commitment, state string) {
		statusMu.Lock()
		defer statusMu.Unlock()
		if commitment != "" {
			commitmentHex = commitment
		}
		containerState = state
	}

	server := attestor.NewServer(addr, att, receiver, func() attestor.Status {
		statusMu.Lock()
		defer statusMu.Unlock()
		return attestor.Status{
			Provisioned:    commitmentHex != "",
			Commitment:     commitmentHex,
			ContainerState: containerState,
			CELRecords:     measurer.RecordCount(),
			TEEKind:        string(att.TEEKind()),
			Version:        version,
		}
	})
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()
	log.Printf("attestation evidence server listening on %s", addr)

	// Obtain the payload plaintext: encrypted provisioning, or the dev spec.
	var plaintext []byte
	if *specPath != "" {
		s, err := spec.Load(*specPath)
		if err != nil {
			return err
		}
		if plaintext, err = provision.EncodePayload(&provision.Payload{LaunchSpec: *s}); err != nil {
			return err
		}
		log.Printf("DEV MODE: payload from %s (no encrypted provisioning)", *specPath)
	} else {
		log.Printf("provisioning mode: waiting for an encrypted workload payload on POST /v1/workload")
		select {
		case plaintext = <-server.Payloads():
		case err := <-serverErr:
			return fmt.Errorf("attestation server failed while waiting for a payload: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	payload, err := provision.DecodePayload(plaintext)
	if err != nil {
		// The payload decrypted (the provisioner holds the transcript) but
		// does not parse; nothing was measured, so this stays fatal and the
		// unit restart gives the VM a fresh key.
		return err
	}
	commitment := provision.Commitment(plaintext)
	log.Printf("accepted workload payload, commitment %x", commitment)

	// Measure before anything about the workload can run.
	if err := measurer.MeasureCommitment(commitment); err != nil {
		return err
	}
	sealed, err := measurer.Seal()
	if err != nil {
		return err
	}
	setStatus(hex.EncodeToString(commitment), "preparing")

	log.Printf("pulling %s", payload.ImageRef)
	workload, err := rt.Prepare(ctx, &payload.LaunchSpec)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := workload.Close(cleanupCtx); err != nil {
			log.Printf("cleanup: %v", err)
		}
	}()

	claims := workload.Claims()
	log.Printf("resolved workload: image=%s digest=%s id=%s args=%v",
		claims.ImageRef, claims.ImageDigest, claims.ImageID, claims.Args)
	setStatus("", "starting")

	stateLoop := make(chan struct{})
	go func() {
		defer close(stateLoop)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
				setStatus("", workload.State())
			}
		}
	}()

	log.Printf("starting workload")
	runErr := make(chan error, 1)
	go func() { runErr <- workload.Run(ctx, sealed) }()

	select {
	case err := <-runErr:
		if err == nil && *linger && ctx.Err() == nil {
			log.Printf("workload finished; lingering to serve attestation evidence (ctrl-c to exit)")
			<-ctx.Done()
		}
		return err
	case err := <-serverErr:
		if err != nil {
			// The evidence server is the point of this launcher: treat its
			// failure as fatal and take the workload down with us.
			stop()
			<-runErr
			return fmt.Errorf("attestation server failed: %w", err)
		}
		return <-runErr
	}
}
