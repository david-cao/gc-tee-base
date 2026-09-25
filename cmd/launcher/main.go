// The launcher runs one attestable container on a GCP Confidential VM.
//
// It pulls the image, extends vTPM PCR 13 with the container's identity
// (image digest and runtime configuration) via a canonical event log, starts
// an attestation evidence server, and only then starts the workload. A remote
// verifier can then confirm exactly which container is running on which
// confidential machine.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/davidcao20/gc-tee-base/internal/attestor"
	"github.com/davidcao20/gc-tee-base/internal/measure"
	"github.com/davidcao20/gc-tee-base/internal/runtime"
	"github.com/davidcao20/gc-tee-base/internal/spec"
)

const version = "0.1.0"

type envFlags map[string]string

func (e envFlags) String() string { return fmt.Sprintf("%v", map[string]string(e)) }
func (e envFlags) Set(v string) error {
	name, value, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return fmt.Errorf("expected NAME=VALUE, got %q", v)
	}
	e[name] = value
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("launcher: %v", err)
	}
}

func run() error {
	var (
		specPath      = flag.String("spec", "", "path to a launch spec YAML file")
		image         = flag.String("image", "", "container image reference (overrides spec)")
		restartPolicy = flag.String("restart-policy", "", "Always | OnFailure | Never (overrides spec)")
		attestAddr    = flag.String("attest-addr", "", "attestation server listen address (overrides spec)")
		akType        = flag.String("ak", string(attestor.AKGceECC),
			"attestation key: gce-ecc | gce-rsa | owner-ecc (owner-ecc is for dev TPMs only)")
		socket    = flag.String("containerd-socket", runtime.DefaultSocket, "containerd socket path")
		namespace = flag.String("containerd-namespace", runtime.DefaultNamespace, "containerd namespace")
		linger    = flag.Bool("linger", false,
			"keep serving attestation evidence after a one-shot workload exits, until signaled")
		useMetadata = flag.Bool("metadata", false,
			"load the launch spec from GCE instance metadata (tee-image-reference, tee-cmd, tee-env-*, tee-restart-policy)")
		metadataBase = flag.String("metadata-base", spec.DefaultMetadataBase,
			"metadata server base URL (for testing)")
	)
	envs := envFlags{}
	flag.Var(envs, "env", "environment variable override NAME=VALUE (repeatable, overrides spec)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: launcher [flags] [-- CMD ARGS...]\n\nArgs after -- override the image CMD.\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Base spec source precedence: file > metadata; flags override fields on
	// top of either. With no explicit source and no -image, metadata is tried
	// as a fallback so a systemd unit can run plain "launcher --metadata" or
	// even bare "launcher" on a GCE VM.
	s := &spec.LaunchSpec{}
	switch {
	case *specPath != "":
		loaded, err := spec.Load(*specPath)
		if err != nil {
			return err
		}
		s = loaded
	case *useMetadata:
		loaded, err := spec.FromMetadata(context.Background(), *metadataBase)
		if err != nil {
			return fmt.Errorf("loading launch spec from instance metadata: %w", err)
		}
		s = loaded
	case *image == "":
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		loaded, err := spec.FromMetadata(ctx, *metadataBase)
		cancel()
		if err == nil {
			s = loaded
		} else {
			log.Printf("no -spec/-image and no metadata spec (%v); expecting flags", err)
		}
	}
	if *image != "" {
		s.ImageRef = *image
	}
	if *restartPolicy != "" {
		s.RestartPolicy = *restartPolicy
	}
	if *attestAddr != "" {
		s.AttestAddr = *attestAddr
	}
	if len(envs) > 0 {
		if s.Envs == nil {
			s.Envs = map[string]string{}
		}
		for k, v := range envs {
			s.Envs[k] = v
		}
	}
	if args := flag.Args(); len(args) > 0 {
		s.Cmd = args
	}
	s.ApplyDefaults()
	if err := s.Validate(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// TPM and attestation key first: fail before pulling anything if the
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
	att, err := attestor.New(tpm, measurer, attestor.AKType(*akType))
	if err != nil {
		return err
	}
	defer att.Close()

	rt, err := runtime.NewContainerd(*socket, *namespace)
	if err != nil {
		return err
	}
	defer rt.Close()

	log.Printf("pulling %s", s.ImageRef)
	workload, err := rt.Prepare(ctx, s)
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
	log.Printf("measuring workload: image=%s digest=%s id=%s args=%v",
		claims.ImageRef, claims.ImageDigest, claims.ImageID, claims.Args)
	if err := measurer.MeasureContainer(claims, s); err != nil {
		return err
	}
	sealed, err := measurer.Seal()
	if err != nil {
		return err
	}

	server := attestor.NewServer(s.AttestAddr, att, func() attestor.Status {
		return attestor.Status{
			ImageRef:       claims.ImageRef,
			ImageDigest:    claims.ImageDigest,
			RestartPolicy:  claims.RestartPolicy,
			ContainerState: workload.State(),
			CELRecords:     measurer.RecordCount(),
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
	log.Printf("attestation evidence server listening on %s", s.AttestAddr)

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
