# gc-tee-base

A base scaffold for running **attestable containers** on Google Cloud
Confidential VMs — boot a measured VM, verify it remotely (down to Intel's
or AMD's hardware root of trust), then deliver your workload as an **encrypted
payload** that only that verified VM can read. A remote party can later
confirm exactly which payload is running, without the payload's contents
ever appearing in metadata, on the wire, or in public evidence.

## The attestation flow

Workloads are delivered in two stages: first verify a *fresh* machine, then
hand it the workload encrypted to a key that only that verified machine
holds. Attestation is not just a report you read — it gates what the VM is
allowed to receive.

```
 CVM (Confidential VM with vTPM)                        anywhere
┌──────────────────────────────────────────┐   ┌──────────────────────────────┐
│ measured NixOS image                     │   │ verifier                     │
│  UKI+dm-verity  → PCR 4/11               │   │ stage 1: provision           │
│ launcher (root), per-boot HPKE key       │   │  1. nonce → GET /attestation │
│  1. serve evidence on :8080              │◄──┤  2. verify: Google CA, quote,│
│     (TDX/SNP quote binds nonce+AK+key)   │   │     boot log, PCR pins,      │
│  2. decrypt payload, latch first valid   │◄──┤     SNP report → AMD roots,  │
│  3. extend PCR 13 with sha256(payload)   │   │     PCR 13 == 0              │
│  4. pull image, start container          │   │  3. encrypt payload to the   │
│  5. keep serving evidence                │   │     attested key, POST it    │
└──────────────────────────────────────────┘   │ stage 2: verify (later)      │
                                               │  commitment == sha256(payload)│
                                               └──────────────────────────────┘
```

**Boot.** The VM boots the measured image: firmware measures the UKI into
PCR 4, systemd-stub measures its sections (kernel, initrd, cmdline — which
seals the dm-verity hash of the read-only system) into PCR 11. The
launcher starts, generates a **per-boot X25519 HPKE keypair** that never
leaves process memory, opens the hardware report device (TDX or SEV-SNP),
and serves evidence. PCR 13 is untouched; no workload exists yet. (On TDX
the firmware and stub have additionally measured the boot chain into the
RTMRs — hardware-signed registers; see the next section.)

**Stage 1 — verify the fresh machine.** The provisioner sends a random
nonce and gets back an evidence envelope: the AK certificate, quotes over
all PCR banks (signed over the nonce), the TCG boot log, the canonical
event log, the HPKE public key, and a hardware attestation report whose
`REPORT_DATA` is a transcript hash

```
SHA-512( "gc-tee-base/provision/v1" ‖ nonce ‖ AK-pubkey ‖ HPKE-pubkey )
```

(fields length-prefixed; see
[internal/provision](internal/provision/provision.go)) — computed *inside*
the guest and signed by the hardware (the Intel TDX module's quoting
chain, or the AMD Secure Processor). The
verifier checks the whole chain (see the next section), checks that
**PCR 13 is still zero** (nothing was ever measured on this boot), and
evaluates the platform half of the policy.

**Encrypted delivery.** Only if everything passes, the provisioner
HPKE-encrypts the payload — image digest, command, env (secrets welcome) —
to the attested public key, with the transcript baked into the HPKE `info`.
The ciphertext is useless anywhere else: a different VM, a different boot
of the same VM, or a different attestation session all derive a different
key or transcript. The launcher decrypts and **latches**: the first valid
payload wins, everything after (or malformed) is rejected.

**Measure, then launch.** The launcher extends PCR 13 with one event — the
**commitment**, `sha256` of the exact payload bytes (which include a random
salt, so the hash reveals nothing brute-forceable) — seals the event log,
and only then pulls the image by digest and starts the container.
Measure-before-launch is structural: the runtime refuses to start a
container without the token that sealing returns. The provisioner gets a
**receipt** (commitment + payload copy) — private, since it contains the
payload.

**Stage 2 — verify the running machine.** Anyone can challenge the VM
again at any time (a fresh nonce each time; the evidence server outlives
one-shot workloads). The quote now covers a nonzero PCR 13; replaying the
event log yields the commitment. The receipt holder checks it equals
`sha256` of the payload they sent — proving *their exact workload* is what
was measured on that machine. Third parties see everything else (platform,
base image, that *some* committed payload runs) but learn nothing about
the workload itself.

Lifecycle: the HPKE key, the latch, and PCR 13 all reset on reboot (PCRs
are volatile; the key is in memory) — a rebooted VM is a *fresh* machine
that must pass stage 1 again, and all old ciphertexts and evidence die
with the old key.

## How trust is rooted

Verification rests on **two independent roots, cross-bound to the same VM
and session**, plus one root you control:

**The CPU vendor's hardware root.** TDX quotes chain to Intel (PCK
certificate → Intel SGX Root CA); SEV-SNP reports chain to AMD's fused
root keys (VCEK → ASK → ARK). Either signature is one the cloud operator
cannot forge ([internal/verify/tee.go](internal/verify/tee.go) verifies
both). A valid quote proves, with no Google involvement: this VM runs on
genuine confidential hardware with encrypted memory; debug access is
forbidden (a TDX `TD_ATTRIBUTES.DEBUG` bit or an SNP debug/migration
policy is rejected outright); the initial guest was a specific firmware
image (`MRTD` / `MEASUREMENT` — on GCE, Google's guest firmware, for
which Google publishes signed endorsements in `gs://gce_tcb_integrity`,
verifiable with
[gce-tcb-verifier](https://github.com/google/gce-tcb-verifier); pin via
`hardware.tdx.mrTd` / `hardware.snp.measurement`); and that the 64-byte
`REPORT_DATA` — our transcript — was requested from inside this guest.

**The technologies are not symmetric, and this is why TDX is the primary
target.** TDX has four **runtime measurement registers (RTMRs)**: guest
software extends them after launch, and they ride inside the Intel-signed
quote. Calibrated on GCE (2026-10-07, see
[nix/README.md](nix/README.md#tdx-calibration-2026-10-07)): the firmware
and systemd-stub measure the boot chain into them, and **RTMR[2] is
exactly the stub's section fold of our UKI in SHA-384** — kernel, initrd,
and the cmdline that seals the dm-verity hash — predictable offline by
`predict-measurements` and pinned via `-expected`. On TDX, base-image
identity is therefore **Intel-rooted**. SNP has no runtime-extensible
registers: its hardware measurement freezes at launch (covering Google's
firmware only), so on SNP base-image identity rides entirely on the vTPM.

**What the measurements cover.** Neither launch measurement ever covers
the image you deploy: `MRTD` and SNP's `MEASUREMENT` are digests of the
*initial* guest (Google's firmware; for SNP also the initial vCPU state,
which is why endorsements are per vCPU count). On SNP that is the whole
story — your image appears nowhere in the AMD attestation; the only
guest-influenced report field is `REPORT_DATA`, a per-report value, not a
code measurement. On TDX your image enters the hardware attestation
through the RTMRs, as a measured-boot delegation chain: Google's firmware
(measured as `MRTD`) extends RTMR[0] with its configuration and RTMR[1]
with what it loads — including the authentihash of your UKI — and then
the systemd-stub *inside your UKI* (measured into RTMR[1]) extends
RTMR[2] with the sections it is about to execute. Each measuring agent is
measured by the previous one; only the first link is measured by silicon.

**Where the hardware guarantee ends.** Be precise about what Intel
enforces: the TDX module attests that *a TD whose initial contents
measured `MRTD=X` issued these RTMR extensions*. An extend records
whatever digest the caller supplies — the hardware does not check that it
corresponds to code actually loaded or run, and RTMRs are not privilege-
protected inside the TD. A malicious firmware could therefore extend
RTMR[1] *and* RTMR[2] with the expected golden values and boot something
else entirely; nothing above `MRTD` is hardware-enforced, only
hardware-*attributed*. The truthfulness of the RTMRs is a conditional
claim — *if the binary measuring `MRTD=X` faithfully measures before
executing, then the RTMRs reflect the real boot chain* — and the
condition names the one component the silicon itself measures. That
forces a lying Google into one of two moves: run a different firmware
(the `MRTD` pin fails closed), or put the lie inside the pinned binary —
the single published, endorsed, fleet-wide artifact anyone can hash,
archive, and reverse-engineer, making the attack non-targetable and
permanently attributable. Contrast SNP, where the lying component (the
vTPM) is unmeasured: forging one tenant's evidence changes no
measurement, ships no artifact, and leaves no trace.

**Corollary: pin the exact `MRTD`, not endorsement validity.** Google can
mint a signed endorsement for any build it ships — including a backdoored
one — so "this `MRTD` has a valid Google endorsement" only proves
*genuine Google firmware*, which is precisely the property the attack
above abuses. Pinning one specific value (ideally a build the whole fleet
has been running) is what forces a lie into the published artifact.
`hardware.tdx.mrTd` is an exact pin for this reason; use the endorsement
to *choose* the value, not as the check itself.

**Google's platform root.** Google's GCE EK/AK CA (vendored in
[internal/verify/roots.go](internal/verify/roots.go)) certifies the
vTPM's attestation key, and the certificate names the exact GCE instance
— something neither hardware quote carries. The AK signs the PCR quotes;
the boot log and event log replay against them. On SNP this chain carries
all software identity (PCR 4/11 base image, PCR 13 commitment). On TDX it
contributes the instance identity, PCR 11 corroboration, and PCR 13 — the
workload commitment still rides the vTPM today (moving it into the
userspace-extendable RTMR[3] would put the workload, too, under the Intel
root; it is the natural next step).

**Where the vTPM actually runs — documented versus inferred.** Google
does not document the vTPM's placement. What is documented:
[Google's attestation docs](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/attestation)
classify vTPM attestation as *software-based* and Google-managed (versus
the *hardware-based* TSM), and the
[firmware endorsements](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-firmware)
cover the UEFI binary only — significant because the SNP launch
measurement is precisely the initial guest memory, so an in-guest vTPM
would have to appear in it. Google's
[2018 Shielded VM vTPM post](https://cloud.google.com/blog/products/identity-security/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext)
describes the vTPM as protected *from the VM* by host paging, and
Canonical began adding SVSM-vTPM (in-guest, VMPL0) support to GCE kernels
in 2025 — implying the incumbent vTPM is not in-guest. Treat "host-side
vTPM" as well-supported inference, not Google documentation; it is
empirically testable via the SNP report's `VMPL` field (a guest reporting
at VMPL0 leaves no room for a more-privileged in-guest vTPM).

**Your own root.** The base image is reproducible from `flake.lock`:
rebuild at the same commit, get the bit-identical UKI, predict the same
PCR 11 / RTMR[2] golden values offline. You verify against numbers you
derived, not numbers someone published.

**The weld.** The transcript appears under both roots: the hardware signs
it inside `REPORT_DATA`, and its inputs (the nonce, the AK) are the same
ones the Google-rooted quote is verified against. Both chains therefore
speak about the same VM, the same boot, the same challenge — and the
encryption key inherits the hardware root: encrypting to the attested key
means only software inside that genuine TD (or SNP guest) can read the
payload.

What that means per adversary — the honest TCB statement:

| Adversary | Stopped by |
|---|---|
| Network attacker, other cloud tenants | Vendor-rooted quote + HPKE: can't forge evidence, can't read payloads. |
| Anyone with GCE project/console access | Nothing to see: no workload config in metadata, evidence reveals only a salted hash. |
| Google's hypervisor reading guest memory | TDX/SNP memory encryption (debug forbidden), proven by the vendor-signed quote. |
| Google forging the *software identity* story | **TDX: reduced to the firmware condition** — the base image is pinned by Intel-signed RTMRs, whose truthfulness rests on the one binary the silicon measures (see "Where the hardware guarantee ends"): a lie requires either a changed `MRTD` (fails closed) or a backdoor in the published fleet-wide firmware (non-targetable, attributable). The vTPM still carries the PCR 13 commitment, until it moves to RTMR[3]; PCR 11 cross-checks RTMR[2] through an independent (also Google-run) path. **SNP: not stopped** — the vTPM is Google software outside the launch measurement, carries all software identity, and can lie per-VM without artifact or trace. |

The general ladder, useful for writing the claim down precisely: (1)
trusting an *unmeasured, mutable Google service* — the SNP-era vTPM:
operational, continuous, per-VM-targetable trust; (2) trusting a
*hardware-identified, published Google binary* — the TDX firmware whose
`MRTD` every verifier pins and whose bytes sit in a public bucket:
static, auditable, and non-targetable, since subverting it means shipping
the backdoor fleet-wide in the one endorsed image; (3) trusting *firmware
you built from source* — bare metal. Rung 3 is never literally zero
(CPU microcode, the AMD Secure Processor, Intel's TDX module remain
vendor-signed); the achievable objective on rented hardware is rung 2 —
every layer measured, pinned, published, and non-targetable — which is
what the TDX path reaches today.

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
what remote attestation needs.

Anyone can reproduce the image from a clean checkout at the same commit and
compare `sha256sum uki.efi` — identical UKI means identical predicted PCRs
(see [nix/README.md](nix/README.md) for the procedure and its trust notes).
After changing Go sources or dependencies, resolve the launcher's
`vendorHash` with `nix build .#launcher` (works on any machine, including
macOS).

## 2. Boot a VM and provision your workload

Any OCI image works, unmodified. The VM boots **bare** — no workload
configuration anywhere in GCE metadata. The default is an Intel TDX
instance (c3; pass `-t SEV_SNP` for an AMD n2d — same image, weaker
trust chain per the previous section):

```bash
deploy/create-instance.sh -i <image-name-from-step-1>
gcloud compute firewall-rules create allow-attestation --allow tcp:8080  # once per project
```

Describe your workload in a payload file (see
[examples/payload.yaml](examples/payload.yaml)) — **always pin the image by
digest**, and feel free to put secrets in `env`: the payload is encrypted
end-to-end and never appears in public evidence.

```yaml
# payload.yaml
image: registry.example.com/myapp@sha256:DIGEST
cmd: ["myapp", "--flag"]        # optional
env: { API_TOKEN: secret }      # optional
restartPolicy: Never            # optional
```

Then provision — one command, from anywhere:

```bash
go run ./cmd/verifier provision -host <VM_IP>:8080 \
  -policy examples/policy.yaml \
  -payload payload.yaml \
  -expected build-artifacts/<image-name>/expected-measurements.json
```

This verifies the **fresh** VM first — full chain, PCR 13 still zero, and
(per policy) a hardware report proving genuine SEV-SNP with the VM's
encryption key bound into `REPORT_DATA` — and only then encrypts the
payload to that key (HPKE, X25519 + ChaCha20-Poly1305) and POSTs it. The
launcher decrypts, measures `sha256(payload)` into PCR 13, pulls the image,
and starts the container.

The command writes `receipt.json`: the commitment, the payload copy, and
the instance identity. **The receipt is as secret as the payload** (it
contains it); it is also your proof of *what* was provisioned.

Notes on the flow:

- The HPKE key lives only in launcher memory for one boot. A reboot or
  launcher restart discards it — old evidence and old ciphertexts become
  useless, and the VM waits fresh for provisioning again (nothing latches
  across boots).
- First valid payload wins. Anyone who can reach :8080 could race you for a
  *fresh* VM (they cannot read or replace your payload once accepted), so
  keep the firewall scoped to your verifier if that matters.
- A second `POST /v1/workload` is rejected; garbage posts don't latch.

## 3. Verify the running workload

Whoever holds the receipt (or just the commitment) can verify:

```bash
go run ./cmd/verifier verify -host <VM_IP>:8080 \
  -policy examples/policy.yaml \
  -receipt receipt.json \
  -expected build-artifacts/<image-name>/expected-measurements.json
```

Exit code 0 = pass; violations are listed with quoted-vs-expected values.
`-json` gives machine-readable output. Third parties without the receipt
can still verify everything up to the commitment — platform, hardware
report, base image — and see *that* a committed payload runs; pass
`-commitment HEX` if you choose to share the commitment itself. For
auditable/offline flows, split it:

```bash
go run ./cmd/verifier nonce                                     # challenge
go run ./cmd/verifier fetch -host <IP>:8080 -nonce N -out e.json # collect
go run ./cmd/verifier verify -evidence e.json -nonce N -policy p.yaml -receipt receipt.json
```

The full policy reference is annotated in
[examples/policy.yaml](examples/policy.yaml): `workloadCommitment`,
`confidentialTechs` (Google-asserted), `hardware.require` +
`hardware.snp.{productLine,measurement}` (AMD-rooted), `gceInstance`
pinning, and `pcrs` base-image pinning (usually via `-expected`).
`cmd/dump-eventlog -evidence e.json` prints the firmware event log behind
PCR 4/11 when a pin mismatches and you need to see *why*.

## What verification proves — and what it doesn't

Proves: a payload with this exact commitment — which the receipt holder can
open to image digest, args, and env — was measured by this exact base layer
(launcher + OS, by PCR 4/11) into a Google-signed vTPM on that GCE
instance, before the workload started; the VM runs under genuine Intel
TDX or AMD SEV-SNP (hardware-signed quote, debug forbidden) on Google's
endorsed firmware — on TDX with the base image additionally pinned by the
Intel-signed RTMRs; and the payload was encrypted so that only that
verified VM could read it.

Does not prove: workload behavior after launch; that the *container image
contents* behind the pinned digest are what you think (pin digests you
trust; `/var` — containerd's cache — is deliberately outside the
measurement, anchored by the digest in the payload); who else knows the
payload (anyone holding the receipt); and anything Google-forgeable — see
the adversary table in [How trust is rooted](#how-trust-is-rooted) for the
exact boundary between the hardware-proven and Google-vouched halves.

## Beyond GCE: bare metal

The protocol is anchor-agnostic; only trust anchors are configuration. On
your own SEV-SNP host, `/dev/sev-guest` and the AMD root chain work
identically (set `hardware.snp.measurement` to *your* OVMF's launch
measurement instead of Google's). A bare-metal TDX host additionally needs
Intel quote-generation infrastructure (QGS/DCAP) beside the guest; the
verifier side is the same code. For the TPM side, point the verifier at
your AK with `-trusted-ak-pub` (physical-TPM EK certificate chains are
future work), and calibrate PCR/RTMR values for your own firmware with
`cmd/predict-measurements` and `cmd/dump-eventlog` after a first boot.

## Development without a CVM

`go test ./...` runs the full provision → measure → attest → verify
roundtrip against a bundled TPM simulator and a fake, test-rooted SEV-SNP
device, plus Intel-signed TDX quote fixtures — including tamper cases
(debug-bit reports and TDs, substituted keys, cross-VM ciphertexts, stale
evidence). The launcher's `-ak owner-ecc` and
verifier's `-trusted-ak-pub` support the same dev mode on any machine with
a TPM; `-spec file.yaml` skips encrypted provisioning entirely (the payload
comes from the file, commitment-measured the same way).

## Layout

- [cmd/launcher](cmd/launcher/main.go) — runs on the CVM
- [cmd/verifier](cmd/verifier/main.go) — runs anywhere; provisions and verifies
- [cmd/predict-measurements](cmd/predict-measurements/main.go) — golden PCR 4/11 + RTMR[2] values from a UKI
- [cmd/dump-eventlog](cmd/dump-eventlog/main.go) — firmware event-log + TDX RTMR inspection
- [internal/provision](internal/provision/provision.go) — transcript, HPKE seal/open, payload commitment
- [internal/measure](internal/measure/measure.go) — CEL construction + PCR 13 extension
- [internal/attestor](internal/attestor/attestor.go) — AK + TEE device ownership, quotes, HTTP evidence server
- [internal/runtime](internal/runtime/containerd.go) — containerd pull/create/run
- [internal/verify](internal/verify/verify.go) — verification pipeline, [hardware report](internal/verify/tee.go), [policy](internal/verify/policy.go), [trust roots](internal/verify/roots.go)
- [flake.nix](flake.nix) + [nix/](nix/README.md) — the measured image (build internals, calibration results, reproducibility)
- [image/](image/README.md) — earlier mkosi-based image (superseded by the NixOS image)

## Phase 3 ideas

- Measure the workload commitment into RTMR[3] (userspace register), so
  the workload — not just the base image — sits under the Intel root.
- Reconstruct RTMR[0]/[1] from the CCEL
  (`/sys/firmware/acpi/tables/data/CCEL`) and check their cross-boot
  stability; today only RTMR[2] is predicted and pinned.
- TDX TCB-status collateral checking at verify time (Intel PCS) and
  automated Google firmware-endorsement fetching (gce-tcb-verifier).
- Empirically settle the SNP vTPM placement via the report VMPL field.
- Provisioner authentication (pin a provisioner public key at instance
  creation, recorded in the CEL).
- Bare-metal TPM EK-manufacturer certificate chains; registry auth for
  private images.
