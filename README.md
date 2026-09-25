# gc-tee-base

A base scaffold for running **attestable containers** on Google Cloud
Confidential VMs — launch any container image and let a remote party
cryptographically verify exactly which container is running, on which machine,
with no special development in the workload itself.

## How it works

Google's Confidential VM boot chain is measured by a Google-signed vTPM. This
scaffold **extends** those trusted base measurements with the container's
identity, then serves attestation evidence a remote verifier can check.

```
 CVM (Confidential VM with vTPM)                        anywhere
┌─────────────────────────────────────────┐   ┌───────────────────────────┐
│ launcher (root)                         │   │ verifier                  │
│  1. pull image via containerd           │   │  1. generate nonce        │
│  2. extend PCR 13 with image digest +   │◄──┤  2. GET /v1/attestation   │
│     runtime config (canonical event log)│   │  3. verify AK cert →      │
│  3. serve evidence on :8080             │   │     Google CA, quote,     │
│  4. start the container                 │   │     boot log, CEL replay  │
└─────────────────────────────────────────┘   │  4. evaluate policy       │
                                              └───────────────────────────┘
```

Trust chain (vTPM-only, identical on AMD SEV / SEV-SNP / Intel TDX):

1. **Google's GCE EK/AK CA** (roots bundled in go-tpm-tools) signs the vTPM's
   attestation key certificate — this is the "trust Google's base
   measurements" anchor, and the cert also names the exact GCE instance.
2. The **AK signs a quote** over all PCRs plus the verifier's nonce
   (freshness).
3. The **TCG boot log** replays against the quoted PCRs — proving boot state,
   secure boot, and *that the VM is actually confidential* (the confidential
   technology is an event on PCR 0; the AK cert alone doesn't prove it).
4. The **canonical event log (CEL)** replays against quoted PCR 13 — proving
   the container identity claims: image digest, image ID, args, env, restart
   policy. The log itself carries no trust; it is a "decompression" of the
   PCR value that the verifier re-derives.
5. A user **policy** is evaluated over the verified claims.

The launcher measures **before** the workload starts (enforced structurally:
starting a container requires the token returned by sealing the measurement),
and the launcher process — never the workload — owns the TPM and the evidence
server.

Measurement uses the same event schema, PCR (13), and ordering as Google's
Confidential Space launcher, so claims are directly comparable.

## Layout

- [cmd/launcher](cmd/launcher/main.go) — runs on the CVM
- [cmd/verifier](cmd/verifier/main.go) — runs anywhere; no CGO, cross-compiles freely
- [internal/measure](internal/measure/measure.go) — CEL construction + PCR 13 extension
- [internal/attestor](internal/attestor/attestor.go) — AK ownership, quote generation, HTTP evidence server
- [internal/runtime](internal/runtime/containerd.go) — containerd pull/create/run (digest + final OCI spec come from the same objects that execute)
- [internal/verify](internal/verify/verify.go) — full verification pipeline + [policy](internal/verify/policy.go)

## Deploying with the measured image (recommended)

The [image/](image/README.md) tree builds a **measured Confidential VM
image**: a minimal OS whose UKI (kernel + initrd + cmdline) is measured into
PCR 4/11 and whose dm-verity root hash — sealed in the UKI cmdline — covers
the read-only rootfs containing the launcher and containerd. Pinning PCR 4/11
in the verifier policy therefore pins the exact launcher that performed the
PCR 13 measurements, closing the unmeasured-userland gap of the stock-VM
quickstart below.

```bash
# build the image on a throwaway GCE builder VM (~10 min), emit golden PCRs
deploy/build-image.sh -p prod

# launch an attestable workload (spec via instance metadata, no SSH)
deploy/create-instance.sh -i gc-tee-base-prod-<ts> -w docker.io/library/busybox@sha256:...

# verify from anywhere: Google CA -> quote -> boot log -> PCR 4/11 pins -> CEL claims
go run ./cmd/verifier verify -host <IP>:8080 -policy examples/policy.yaml \
  -expected build-artifacts/<image>/expected-measurements.json
```

First boot of a new image shape needs the one-time calibration runbook in
[image/README.md](image/README.md) (confirms GCE boots the bare UKI and which
PCR 4 event set the firmware produces). Secure boot stays off by design:
`pcrs` pinning detects modified images, which for remote attestation is what
matters.

## Quickstart (stock VM, no measured base layer)

### 1. Create a Confidential VM

Prerequisites on the VM: vTPM enabled (default on Confidential VM), containerd
installed, launcher run as root (TPM event log and containerd both need it).

```bash
gcloud compute instances create my-cvm \
  --zone us-central1-a \
  --machine-type n2d-standard-2 \
  --confidential-compute-type SEV_SNP \
  --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 \
  --image-project ubuntu-os-cloud \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring
```

Open the evidence port to your verifier (evidence is public-verifiable, but
you may still prefer to restrict the source range):

```bash
gcloud compute firewall-rules create allow-attestation --allow tcp:8080
```

### 2. Run the launcher on the VM

```bash
sudo apt-get install -y containerd
```

Build `cmd/launcher` for linux/amd64, copy it and a launch spec (see
[examples/launchspec.yaml](examples/launchspec.yaml)) to the VM, then:

```bash
sudo ./launcher -spec launchspec.yaml
```

Or without a spec file:

```bash
sudo ./launcher -image docker.io/library/busybox@sha256:9ae97d36d26566ff84e8893c64a6dc4fe8ca6d1144bf5b87b2b85a32def253c7 -- sh -c 'sleep 3600'
```

The launcher pulls the image, measures it, starts the evidence server, and
starts the container. `-linger` keeps serving evidence after a one-shot
workload exits.

### 3. Verify from your laptop

Write a policy pinning the image digest (see
[examples/policy.yaml](examples/policy.yaml)), then:

```bash
go run ./cmd/verifier verify -host <VM_IP>:8080 -policy examples/policy.yaml
```

This generates a fresh nonce, fetches evidence, verifies the full chain
against Google's CA, and evaluates the policy. Exit code 0 means pass. Use
`verifier nonce` / `fetch` / `verify -evidence` for the split flow, and
`-json` for machine-readable output.

## Development without a CVM

Everything except the Google certificate chain runs locally against the
bundled TPM simulator:

```bash
go test ./...
```

The roundtrip test (`internal/attestor`) measures into a simulated TPM,
generates evidence with a dev (owner-hierarchy) AK, and verifies it with the
AK trusted directly. The launcher's `-ak owner-ecc` and the verifier's
`-trusted-ak-pub` flags support the same dev mode on any machine with a TPM —
with no anchor to Google, so dev mode proves nothing about where the code
runs.

## What verification proves — and what it doesn't

Proves: this exact image (by digest), with this exact config, was measured
into a Google-signed vTPM on that GCE instance before the workload started,
inside a VM whose boot chain and confidential technology replay correctly.

Does not prove (current scope, see below): workload behavior after launch,
kernel/userland integrity beyond what the boot log covers (the launcher and
containerd are part of the TCB but are not themselves measured into PCR 13 —
on a stock Ubuntu image they are covered only if you enforce something like
secure boot + IMA yourself), protection of the evidence port (run your own
TLS/proxy if you need transport privacy), or registry trust (pin digests, not
tags).

## Phase 2 ideas

- Bind SEV-SNP / TDX hardware reports (`client.AttestOpts.TEEDevice`) so trust
  roots in AMD/Intel rather than only Google.
- GCE metadata-driven launch spec (`tee-image-reference`) + Terraform module.
- Attestation-gated secret release (verify-then-release KBS flow).
- Registry auth for private images.
- systemd unit + minimal hardened host image.
