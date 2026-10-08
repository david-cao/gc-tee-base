# gc-tee-base measured image (NixOS)

NixOS appliance image built via nixpkgs' `image.repart` + `verityStore`:
a UKI (kernel + initrd + cmdline, measured into PCR 4 by firmware and PCR 11
by systemd-stub) whose command line seals the dm-verity hash (`usrhash=`) of
the erofs partition holding `/nix/store`. On NixOS every measured-relevant
artifact — systemd, kernel modules, containerd, the launcher, every unit
file — is a store path, so pinning PCR 4/11 pins the entire base layer.

This image is the *content* half of the trust chain (see "How trust is
rooted" in the [root README](../README.md)): PCR 4/11 identify the exact
launcher binary — the process that holds the per-boot HPKE decryption key,
accepts the encrypted workload payload, and measures its commitment into
PCR 13. Trusting a payload delivery therefore reduces to trusting these
two PCR values, which anyone can re-derive from this reproducible build.
`/` is tmpfs; `/var` is writable ext4 for containerd state (outside the
measurement by design: workload integrity is anchored by the commitment
the launcher measures into PCR 13, and the image digest pinned inside the
payload it commits to). Secure boot stays off; the verifier *detects*
modified images via PCR pinning.

This replaces the earlier mkosi image (../image/, kept until this image
passes calibration). The measurement story is identical with
"roothash" → "usrhash".

## Why Nix: reproducibility

`flake.lock` pins every input — nixpkgs revision, and through it the exact
kernel, systemd/stub, containerd, Go toolchain, and mkfs tools. Anyone
cloning the repo at a commit rebuilds the **bit-identical UKI**, and
therefore derives the same predicted PCR 4/11 — the published
`expected-measurements.json` becomes independently checkable instead of
"trust whoever built the image".

Manual reproducibility check (no harness; do this once per release commit):

```sh
nix build .#uki-prod && sha256sum result/*.efi          # build 1
nix build --rebuild .#uki-prod && sha256sum result/*.efi # rebuild, compare
# stronger: repeat on a second machine / fresh builder VM at the same commit
```

Trust note: `nix build` substitutes prebuilt store paths from
cache.nixos.org by default — you are trusting the NixOS build farm built
those paths from the pinned sources. `--option substitute false` forces
building everything from source. This is a documented tradeoff, not solved
here.

## Layout

- [../flake.nix](../flake.nix) — outputs `image-{dev,prod}` (raw disk +
  `repart-output.json` containing the verity hash) and `uki-{dev,prod}`
  (the final UKI with `usrhash=`)
- [appliance.nix](appliance.nix) — the shared module: partitions, verity
  store, GCE hardware (gve/NVMe/ttyS0/MTU 1460 via networkd `UseMTU`),
  PCR-unit suppression (PCR 11 must stay frozen at the stub value),
  containerd, the launcher unit
- [variant-dev.nix](variant-dev.nix) — serial-console root autologin +
  tpm2-tools (calibration only); [variant-prod.nix](variant-prod.nix) — no
  login path at all
- [launcher.nix](launcher.nix) — `buildGoModule` from the in-repo sources.
  **vendorHash workflow**: when `go.mod`/`go.sum` or the import graph
  change, set `vendorHash = lib.fakeHash`, run `nix build .#launcher`
  (works on any system, including macOS — the vendor derivation is
  platform-independent), and copy the `got: sha256-...` value from the
  error into the file.

Build with [../deploy/build-image.sh](../deploy/build-image.sh) (installs
Nix on a throwaway GCE builder VM and runs `nix build`).

## Calibration runbook (first boot of a new image shape)

Things that cannot be fully predicted from documentation, confirmed once
against real GCE firmware and recorded below:

1. **Fallback-path UKI boot** — GCE UEFI firmware must boot
   `EFI/BOOT/BOOTX64.EFI` directly.
2. **PCR 4 composition** — whether the firmware log contains only the UKI's
   authentihash or also the embedded kernel's (`predict-measurements` emits
   both candidates: `uki-and-kernel`, the default, and `uki-only`).
3. **PCR 11 section model** — uplosi's `PredictPCR11` must match the section
   set the nixpkgs systemd-stub/ukify emits (section lists grew over
   systemd releases: `.uname`, `.sbat`, ...). The TCG log from the dev VM
   arbitrates; on mismatch, adjust `cmd/predict-measurements` or bump the
   uplosi dependency.

Steps:

1. `deploy/build-image.sh -p dev`, then
   `deploy/create-instance.sh -i <image>` (the VM boots bare, in
   provisioning mode).
2. Watch `gcloud compute instances get-serial-port-output <name>`: UKI
   boot, `/dev/mapper/usr` active, DHCP lease with MTU 1460, containerd up,
   launcher serving on :8080 and waiting for an encrypted payload
   (`hardware report device: sev-snp` in its log).
3. On the serial console (root autologin): confirm `usrhash=` in
   `/proc/cmdline` and `/nix/store` read-only;
   `tpm2_pcrread sha256:0,4,7,11,12,13`; compare PCR 4/11 against the
   candidates in `expected-measurements.json` (`notes` field). Copy
   `/sys/kernel/security/tpm0/binary_bios_measurements` off the VM for
   event-level debugging. Confirm PCR 13 is zero pre-provisioning.
4. If `uki-only` is the correct PCR 4 variant, re-run
   `predict-measurements -pcr4-variant uki-only ...` and record it below.
5. `verifier provision -host <ip>:8080 -policy <policy> -payload
   <payload.yaml> -expected <expected-measurements.json>` → provisions;
   then `verifier verify -host <ip>:8080 -policy <policy> -receipt
   receipt.json -expected ...` → PASS; rebuild the image with any change
   and confirm the old expected values now FAIL.
6. Rebuild `-p prod` and re-validate via the verifier alone (no console).

## Calibration results

Calibrated 2026-09-29 against `gc-tee-base-dev-20260929-174655` (SEV-SNP,
us-central1-c, nixpkgs `cf5e765` / NixOS 26.05, systemd-stub from that pin).
End-to-end `verifier verify -host ... -expected ...` → POLICY: PASS.

- **Fallback-path UKI boot: works.** GCE firmware boots
  `EFI/BOOT/BOOTX64.EFI` directly; verity store mounts; gVNIC DHCP +
  MTU 1460, containerd, launcher all come up.
- **PCR 4 variant: `uki-only`.** The firmware log is exactly EV_EFI_ACTION
  ("Calling EFI Application from Boot Option"), EV_SEPARATOR, then one
  EV_EFI_BOOT_SERVICES_APPLICATION whose digest is the standard PE
  authentihash of the UKI. No event for the embedded kernel.
- **PCR 11 rule (differs from uplosi's model, now implemented in
  predict-measurements):** per recognized section in systemd-stub's fixed
  order (`.linux .osrel .cmdline .initrd .uname .sbat` present in our UKI),
  two events: sha256(**ASCII** section name + NUL), then sha256(section
  content as loaded — raw data truncated/zero-padded to VirtualSize). The
  event log's *data* field shows UTF-16 names, but the *digest* is over the
  ASCII name.
- **Pitfall (root-caused during calibration): predict from the image's ESP
  UKI.** On the builder the repo is a path flake (no .git); an in-tree
  `result-*` out-link changed the source hash between the image and UKI
  builds, so the standalone UKI carried a different toplevel/usrhash in its
  .cmdline than the image's. build-image.sh now uses out-of-tree out-links
  and cmp-checks the ESP's BOOTX64.EFI against the standalone UKI.
- Tamper check: predictions from the stale (mismatched) UKI correctly
  produced POLICY: FAIL with the quoted-vs-expected values shown.
- Reproducibility double-build check: — (pending)

### Two-stage provisioning validation (2026-09-30)

Validated end-to-end against `gc-tee-base-dev-20260930-161730` on a fresh
SEV-SNP VM (n2d-standard-2, us-central1-c), with the launcher in
provisioning mode (`teeKind: sev-snp` auto-detected):

- `verifier provision` verified the fresh VM (PCR 4/11 pins, PCR 13 zero,
  **SNP report chained to AMD's real Milan roots** with the
  transcript-bound `REPORT_DATA`), delivered the encrypted busybox payload,
  and the workload ran; post-exit `verifier verify -receipt` → POLICY:
  PASS (the launcher unit passes `-linger`, added after the first attempt
  showed a one-shot workload taking the evidence server down with it).
- Google's live UEFI launch measurement (n2d-standard-2, 2 vCPUs,
  2026-09-30, deterministic across two VMs):
  `ccdc5cf01ba25526bd65503d95931b787b4385a3277cfe4448addf9c3e894948ae8cf7b099620e3e22717de2fb5d26fa`
  — pinned via `hardware.snp.measurement` it PASSes, and a wrong value
  FAILs. Note the measurement depends on vCPU count and Google's firmware
  release; retrieve the signed endorsement per the README before pinning
  in production.
- Negative paths: re-provisioning a provisioned VM is refused
  ("already provisioned"); a second `POST /v1/workload` → 409; stale
  expected-measurements from the previous image → PCR 4/11 FAIL;
  wrong `-commitment` → FAIL.

### TDX calibration (2026-10-07)

Validated end-to-end against the same image
(`gc-tee-base-dev-20260930-161730`, built before TDX work — no image
change needed) on a fresh TDX VM (c3-standard-4, us-central1-a):

- **Boots unchanged**: GCE's TDX firmware boots the fallback-path UKI;
  gVNIC/containerd/launcher come up; the NixOS kernel has configfs-tsm +
  TDX guest support out of the box, so the launcher reports
  `teeKind: tdx` and TDX quotes flow with no image modification.
- **PCR 4 differs from SNP — and is image-independent on TDX.** The TPM
  log holds only EV_EFI_ACTION + EV_SEPARATOR; there is NO
  EV_EFI_BOOT_SERVICES_APPLICATION event for the UKI. The boot-application
  measurement moved to the Intel-signed RTMRs. predict-measurements emits
  this as the `tdx` PCR 4 variant (the action+separator fold).
- **RTMR[2] = the stub section fold in SHA-384.** Exactly the PCR 11
  model (sha384(ASCII name + NUL), then sha384(content padded to
  VirtualSize), stub order, ending at `.sbat`) — systemd-stub emits the
  same events through the CC measurement protocol, and PCR 11 maps to
  RTMR[2]. Predicted offline from the UKI, matched the live quote
  bit-for-bit, and a wrong pin FAILs. **This is the Intel-rooted pin of
  the exact base image** (kernel, initrd, cmdline with `usrhash=`).
- PCR 11 (vTPM) is identical to the SNP boot — same UKI, same stub fold.
- RTMR[1] (bootloader per Google's docs) did not reproduce from the TPM
  log's SHA-384 bank (the CC-side log contains events the TPM log lacks,
  and PCR 5's GPT/boot-variable events may be instance-specific) —
  reconstructing it needs the CCEL
  (`/sys/firmware/acpi/tables/data/CCEL`); not needed for image pinning
  since RTMR[2] covers the full UKI contents. RTMR[3] is zero (userspace
  register — a future home for the workload commitment).
- Observed MRTD (Google TD firmware, c3-standard-4, 2026-10-07):
  `c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5`
  (pin via `hardware.tdx.mrTd` after checking Google's signed endorsement).
- E2E: `verifier provision` (Intel chain + REPORT_DATA transcript binding
  + RTMR[2]/PCR pins) → workload ran → post-exit `verify -receipt` →
  POLICY: PASS; wrong RTMR[2] pin → FAIL.
