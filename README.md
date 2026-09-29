# gc-tee-base

A base scaffold for running **attestable containers** on Google Cloud
Confidential VMs — launch any container image and let a remote party
cryptographically verify exactly which container is running, on which machine,
with no special development in the workload itself.

## How it works

```
 CVM (Confidential VM with vTPM)                        anywhere
┌─────────────────────────────────────────┐   ┌───────────────────────────┐
│ measured NixOS image                    │   │ verifier                  │
│  UKI+dm-verity  → PCR 4/11              │   │  1. generate nonce        │
│ launcher (root)                         │   │  2. GET /v1/attestation   │
│  1. pull image via containerd           │◄──┤  3. verify AK cert →      │
│  2. extend PCR 13 with image digest +   │   │     Google CA, quote,     │
│     runtime config (canonical event log)│   │     boot log, PCR pins,   │
│  3. serve evidence on :8080             │   │     CEL replay            │
│  4. start the container                 │   │  4. evaluate policy       │
└─────────────────────────────────────────┘   └───────────────────────────┘
```

Trust chain (vTPM-only, identical on AMD SEV / SEV-SNP / Intel TDX):

1. **Google's GCE EK/AK CA** signs the vTPM's attestation key certificate —
   the "trust Google's base measurements" anchor; the cert also names the
   exact GCE instance. (Roots vendored in
   [internal/verify/roots.go](internal/verify/roots.go).)
2. The **AK signs a quote** over all PCRs plus the verifier's nonce
   (freshness).
3. The **TCG boot log** replays against the quoted PCRs — proving boot state
   and *that the VM is actually confidential* (the confidential technology
   is an event on PCR 0; the AK cert alone doesn't prove it).
4. **PCR 4/11 golden-value pins** identify the exact base image: the
   [measured NixOS appliance](nix/README.md) packs kernel + initrd + cmdline
   into a UKI (measured by firmware and systemd-stub), and the cmdline seals
   the dm-verity hash of the read-only layer holding the launcher and
   containerd. Pinning PCR 4/11 therefore pins the exact launcher that
   performs step 5. Expected values are computed offline from build
   artifacts, and the image build is reproducible from `flake.lock`, so
   anyone can rebuild and independently confirm them.
5. The **canonical event log (CEL)** replays against quoted PCR 13 — proving
   the container identity claims: image digest, image ID, args, env, restart
   policy. The log itself carries no trust; it is a "decompression" of the
   PCR value that the verifier re-derives.
6. A user **policy** is evaluated over the verified claims.

The launcher measures **before** the workload starts (enforced structurally:
starting a container requires the token returned by sealing the measurement),
and the launcher process — never the workload — owns the TPM and the evidence
server. Measurement uses the same event schema, PCR (13), and ordering as
Google's Confidential Space launcher, so claims are directly comparable.

## 1. Build the measured image

```bash
deploy/build-image.sh -p prod        # or -p dev for the debuggable variant
```

This creates a throwaway GCE builder VM, runs `nix build` there, uploads the
disk, registers the GCE image, and writes two things you keep:

- `build-artifacts/<image-name>/uki.efi` — the exact UKI the image boots
  (cross-checked byte-for-byte against the ESP during the build);
- `build-artifacts/<image-name>/expected-measurements.json` — the predicted
  golden PCR 4/11 values, computed from the UKI by
  [cmd/predict-measurements](cmd/predict-measurements/main.go). This file is
  what verifiers pin; publish it next to your image name.

Variants: `dev` has serial-console root autologin + tpm2-tools (for
debugging/calibration — its PCRs differ from prod's, so a prod policy
rejects dev images automatically); `prod` has no login path at all. Secure
boot stays off by design: PCR pinning *detects* modified images, which is
what remote attestation needs. The PCR 4/11 prediction models were
calibrated against GCE firmware once (see
[nix/README.md](nix/README.md#calibration-results)); recalibration is only
needed if the image shape changes fundamentally.

Anyone can reproduce the image from a clean checkout at the same commit and
compare `sha256sum uki.efi` — identical UKI means identical predicted PCRs
(see [nix/README.md](nix/README.md) for the reproducibility procedure and
its trust notes).

## 2. Run your own container

Any OCI image works, unmodified. **Always deploy by digest, not tag**:

```bash
deploy/create-instance.sh \
  -i <image-name-from-step-1> \
  -w registry.example.com/myapp@sha256:DIGEST \
  [-c '["myapp","--flag"]'] [-e KEY=VALUE]... [-r Always|OnFailure|Never]
```

The VM boots the measured image; the launcher reads the workload from
instance metadata (`tee-image-reference`, `tee-cmd`, `tee-env-*`,
`tee-restart-policy`), pulls it, measures it into PCR 13, starts serving
evidence on `:8080`, and only then starts the container. No SSH involved.
Open the evidence port once per project:
`gcloud compute firewall-rules create allow-attestation --allow tcp:8080`.

### Getting your container's expected measurement

What gets extended into PCR 13 is the canonical event log of the workload's
identity; what a verifier pins in the policy is primarily the **manifest
digest** of your image (the `sha256:...` after `@`). You do not need to
precompute a PCR 13 value — the verifier replays the event log against the
quoted PCR and checks the *claims*, which is what makes flexible policy
(e.g. "this digest, any allowed env override") possible.

The measured digest is exactly the digest of the reference you deploy, so
obtaining it means asking your registry (for multi-arch images this is the
index digest — also what containerd resolves):

```bash
# when pushing with docker (prints the digest at the end):
docker buildx build --push -t registry.example.com/myapp:v1 .
# or afterwards:
docker inspect --format '{{index .RepoDigests 0}}' registry.example.com/myapp:v1

# with crane or skopeo:
crane digest registry.example.com/myapp:v1
skopeo inspect --format '{{.Digest}}' docker://registry.example.com/myapp:v1
```

(No tools at all? A `HEAD` on
`/v2/<repo>/manifests/<tag>` with an `Accept:
application/vnd.oci.image.index.v1+json` header returns it in
`docker-content-digest` — see the registry HTTP API.)

Beyond the digest, the event log also records — and the verifier surfaces as
claims — the resolved image reference, the image config digest ("image ID"),
the final process args and env (after merging your image's ENTRYPOINT/CMD
with any `-c` override), and every operator override *separately*, so your
policy decides which overrides are acceptable. Deploying by tag instead of
digest still measures faithfully (whatever the tag resolved to at launch),
but then the digest in the evidence is chosen by the registry at boot time —
pin digests.

## 3. Write a policy and verify

A policy states everything the relying party requires. Full reference
(see also [examples/policy.yaml](examples/policy.yaml)):

```yaml
# REQUIRED: the exact manifest digest of the workload (step 2).
imageDigest: sha256:DIGEST

# Optional: anchored regex the image reference must match.
imageRefPattern: registry\.example\.com/myapp@sha256:.*

# Optional: which env vars the operator may override (default: none).
allowedEnvOverrides: [LOG_LEVEL]

# Optional: whether the operator may override the command (default: false).
allowArgOverrides: false

# Optional but recommended: acceptable confidential technologies.
# Omitting it accepts non-confidential VMs too.
confidentialTechs: [AMD_SEV_SNP, INTEL_TDX]

# Optional: pin the evidence to one VM (values come from the Google-issued
# AK certificate; empty fields are not checked).
# gceInstance: {projectId: my-project, zone: us-central1-a, instanceName: my-cvm}

# Base-image pinning. Either write the values inline...
# pcrs:
#   bank: sha256
#   values: {4: "<hex>", 11: "<hex>"}
# ...or (preferred) pass -expected on the command line, which fills this
# block from the build's expected-measurements.json.
# (requireSecureBoot exists but is not used with measured images: the UKI is
# unsigned and PCR pinning covers strictly more.)
```

Then verify — one shot, from anywhere:

```bash
go run ./cmd/verifier verify -host <VM_IP>:8080 \
  -policy policy.yaml \
  -expected build-artifacts/<image-name>/expected-measurements.json
```

This generates a fresh nonce, fetches evidence, verifies the full chain
(steps 1–5 above), and evaluates the policy. Exit code 0 = pass; violations
are listed with quoted-vs-expected values. `-json` gives machine-readable
output. For auditable/offline flows, split it:

```bash
go run ./cmd/verifier nonce                                   # challenge
go run ./cmd/verifier fetch -host <IP>:8080 -nonce N -out e.pb # collect
go run ./cmd/verifier verify -evidence e.pb -nonce N -policy p.yaml -expected em.json
```

`cmd/dump-eventlog -evidence e.pb` prints the firmware event log behind
PCR 4/11 when a pin mismatches and you need to see *why*.

## What verification proves — and what it doesn't

Proves: this exact container image (by digest), with this exact runtime
config, was measured by this exact base layer (launcher + OS, by PCR 4/11)
into a Google-signed vTPM on that GCE instance, before the workload started,
inside a VM whose boot chain and confidential technology replay correctly.

Does not prove: workload behavior after launch; transport privacy of the
evidence port (evidence is public-verifiable; add TLS/proxy if you care);
registry trust beyond the digest (pin digests, and remember `/var` —
containerd's cache — is deliberately outside the measurement, anchored
instead by the digest check in PCR 13); and the whole story trusts Google
(vTPM + CA) — hardware-rooted reports are the main phase-2 item.

## Development without a CVM

`go test ./...` runs the full measure → attest → verify roundtrip against a
bundled TPM simulator, including tamper cases. The launcher's
`-ak owner-ecc` and verifier's `-trusted-ak-pub` support the same dev mode
on any machine with a TPM — with no anchor to Google, so it proves nothing
about where the code runs. The launcher also still runs on a stock Ubuntu
CVM (`-spec`/`-image` flags, containerd required) — useful for iteration,
but without the measured base layer, PCR 4/11 pinning does not apply and the
launcher itself is unattested.

## Layout

- [cmd/launcher](cmd/launcher/main.go) — runs on the CVM
- [cmd/verifier](cmd/verifier/main.go) — runs anywhere; no CGO
- [cmd/predict-measurements](cmd/predict-measurements/main.go) — golden PCR 4/11 from a UKI
- [cmd/dump-eventlog](cmd/dump-eventlog/main.go) — firmware event-log inspection for calibration/debugging
- [internal/measure](internal/measure/measure.go) — CEL construction + PCR 13 extension
- [internal/attestor](internal/attestor/attestor.go) — AK ownership, quotes, HTTP evidence server
- [internal/runtime](internal/runtime/containerd.go) — containerd pull/create/run (digest + final OCI spec come from the same objects that execute)
- [internal/verify](internal/verify/verify.go) — verification pipeline, [policy](internal/verify/policy.go), [trust roots](internal/verify/roots.go)
- [flake.nix](flake.nix) + [nix/](nix/README.md) — the measured image (build internals, calibration results, reproducibility)
- [image/](image/README.md) — earlier mkosi-based image (superseded by the NixOS image)

## Phase 2 ideas

- Bind SEV-SNP / TDX hardware reports (`client.AttestOpts.TEEDevice`) so
  trust roots in AMD/Intel rather than only Google.
- Attestation-gated secret release (verify-then-release KBS flow).
- Registry auth for private images.
- Terraform module / multi-instance orchestration.
