package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/davidcao20/gc-tee-base/internal/measure"
	"github.com/davidcao20/gc-tee-base/internal/spec"
)

// DefaultSocket is the standard containerd socket path.
const DefaultSocket = "/run/containerd/containerd.sock"

// DefaultNamespace isolates our containers from other containerd users.
const DefaultNamespace = "gc-tee"

// Containerd talks to a containerd daemon.
type Containerd struct {
	client    *containerd.Client
	namespace string
}

// NewContainerd connects to the containerd daemon at socket.
func NewContainerd(socket, namespace string) (*Containerd, error) {
	if socket == "" {
		socket = DefaultSocket
	}
	if namespace == "" {
		namespace = DefaultNamespace
	}
	client, err := containerd.New(socket)
	if err != nil {
		return nil, fmt.Errorf("connecting to containerd at %s: %w", socket, err)
	}
	return &Containerd{client: client, namespace: namespace}, nil
}

// Close closes the daemon connection.
func (c *Containerd) Close() error {
	return c.client.Close()
}

func (c *Containerd) ctx(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, c.namespace)
}

// Prepare pulls the image, creates (but does not start) the container, and
// resolves the exact identity to measure. Overrides from the launch spec are
// applied docker-style: spec.Cmd replaces the image CMD (the ENTRYPOINT is
// kept), spec.Envs layer over the image environment.
func (c *Containerd) Prepare(ctx context.Context, s *spec.LaunchSpec) (Workload, error) {
	ctx = c.ctx(ctx)

	image, err := c.client.Pull(ctx, s.ImageRef, containerd.WithPullUnpack)
	if err != nil {
		return nil, fmt.Errorf("pulling image %q: %w", s.ImageRef, err)
	}
	manifestDigest := image.Target().Digest.String()

	configDesc, err := image.Config(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading image config descriptor: %w", err)
	}
	imageConfig, err := readImageConfig(ctx, image, configDesc)
	if err != nil {
		return nil, err
	}

	args := append([]string{}, imageConfig.Config.Entrypoint...)
	if len(s.Cmd) > 0 {
		args = append(args, s.Cmd...)
	} else {
		args = append(args, imageConfig.Config.Cmd...)
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("image %q has no entrypoint or cmd and none was provided", s.ImageRef)
	}

	var overrideEnvs []string
	for _, name := range s.SortedEnvNames() {
		overrideEnvs = append(overrideEnvs, name+"="+s.Envs[name])
	}

	suffix := make([]byte, 4)
	rand.Read(suffix)
	id := "gc-tee-" + hex.EncodeToString(suffix)

	container, err := c.client.NewContainer(ctx, id,
		containerd.WithNewSnapshot(id+"-snap", image),
		containerd.WithNewSpec(
			oci.WithImageConfig(image),
			oci.WithEnv(overrideEnvs),
			oci.WithProcessArgs(args...),
			// Host networking, matching the upstream Confidential Space
			// launcher: the workload shares the VM's network identity.
			oci.WithHostNamespace(runtimespec.NetworkNamespace),
			oci.WithHostHostsFile,
			oci.WithHostResolvconf,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating container: %w", err)
	}

	// Measure what will actually execute: read the final spec back from the
	// created container rather than trusting our own computation.
	finalSpec, err := container.Spec(ctx)
	if err != nil {
		container.Delete(ctx, containerd.WithSnapshotCleanup)
		return nil, fmt.Errorf("reading back container spec: %w", err)
	}

	return &containerdWorkload{
		rt:        c,
		container: container,
		launch:    s,
		state:     "created",
		claims: measure.ContainerClaims{
			ImageRef:      s.ImageRef,
			ImageDigest:   manifestDigest,
			ImageID:       configDesc.Digest.String(),
			Args:          finalSpec.Process.Args,
			EnvVars:       finalSpec.Process.Env,
			RestartPolicy: s.RestartPolicy,
		},
	}, nil
}

func readImageConfig(ctx context.Context, image containerd.Image, desc ocispec.Descriptor) (*ocispec.Image, error) {
	blob, err := content.ReadBlob(ctx, image.ContentStore(), desc)
	if err != nil {
		return nil, fmt.Errorf("reading image config blob: %w", err)
	}
	var config ocispec.Image
	if err := json.Unmarshal(blob, &config); err != nil {
		return nil, fmt.Errorf("parsing image config: %w", err)
	}
	return &config, nil
}

type containerdWorkload struct {
	rt        *Containerd
	container containerd.Container
	launch    *spec.LaunchSpec
	claims    measure.ContainerClaims

	mu    sync.Mutex
	state string
}

func (w *containerdWorkload) Claims() measure.ContainerClaims {
	return w.claims
}

func (w *containerdWorkload) State() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

func (w *containerdWorkload) setState(s string) {
	w.mu.Lock()
	w.state = s
	w.mu.Unlock()
}

// Run starts the container and applies the restart policy. Restarts reuse the
// same container and are intentionally not re-measured (identical identity),
// matching upstream launcher behavior.
func (w *containerdWorkload) Run(ctx context.Context, _ measure.Sealed) error {
	cctx := w.rt.ctx(ctx)
	for attempt := 0; ; attempt++ {
		exitCode, err := w.runOnce(cctx)
		if err != nil {
			w.setState("failed")
			return err
		}
		if ctx.Err() != nil {
			w.setState("stopped")
			return nil
		}

		restart := false
		switch w.launch.RestartPolicy {
		case spec.RestartAlways:
			restart = true
		case spec.RestartOnFailure:
			restart = exitCode != 0
		}
		if !restart {
			w.setState(fmt.Sprintf("exited (code %d)", exitCode))
			if exitCode != 0 {
				return fmt.Errorf("workload exited with code %d", exitCode)
			}
			return nil
		}
		log.Printf("workload exited with code %d; restarting (%s, attempt %d)",
			exitCode, w.launch.RestartPolicy, attempt+1)
		time.Sleep(time.Second)
	}
}

func (w *containerdWorkload) runOnce(cctx context.Context) (uint32, error) {
	task, err := w.container.NewTask(cctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return 0, fmt.Errorf("creating task: %w", err)
	}
	// Delete with context.Background(): cleanup must happen even when cctx
	// was canceled by a signal.
	defer task.Delete(namespaces.WithNamespace(context.Background(), w.rt.namespace))

	exitCh, err := task.Wait(cctx)
	if err != nil {
		return 0, fmt.Errorf("waiting on task: %w", err)
	}
	if err := task.Start(cctx); err != nil {
		return 0, fmt.Errorf("starting task: %w", err)
	}
	w.setState("running")

	select {
	case exitStatus := <-exitCh:
		code, _, err := exitStatus.Result()
		if err != nil {
			return 0, fmt.Errorf("reading exit status: %w", err)
		}
		return code, nil
	case <-cctx.Done():
		// Graceful stop: SIGTERM, then SIGKILL after a grace period.
		killCtx := namespaces.WithNamespace(context.Background(), w.rt.namespace)
		if err := task.Kill(killCtx, 15); err != nil {
			log.Printf("SIGTERM failed: %v", err)
		}
		select {
		case exitStatus := <-exitCh:
			code, _, _ := exitStatus.Result()
			return code, nil
		case <-time.After(10 * time.Second):
			task.Kill(killCtx, 9)
			exitStatus := <-exitCh
			code, _, _ := exitStatus.Result()
			return code, nil
		}
	}
}

func (w *containerdWorkload) Close(ctx context.Context) error {
	cctx := w.rt.ctx(ctx)
	return w.container.Delete(cctx, containerd.WithSnapshotCleanup)
}
