// Package runtime pulls and runs the workload container via containerd. It
// exists to give the measurement layer exact values: the manifest digest,
// image config digest, and final OCI process args/env all come from the same
// containerd objects that execute, so measured identity equals runtime
// reality.
package runtime

import (
	"context"

	"github.com/davidcao20/gc-tee-base/internal/measure"
)

// Workload is a pulled image with a created (not yet started) container.
type Workload interface {
	// Claims returns the resolved identity to measure. Valid before Run.
	Claims() measure.ContainerClaims
	// Run starts the container and blocks until it exits, applying the
	// restart policy. The Sealed token proves measurement completed first.
	Run(ctx context.Context, sealed measure.Sealed) error
	// State reports a short human-readable container state.
	State() string
	// Close deletes the container and releases runtime resources.
	Close(ctx context.Context) error
}
