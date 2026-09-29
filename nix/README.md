# gc-tee-base measured image (NixOS)

NixOS appliance image built via nixpkgs' `image.repart` + `verityStore`:
a UKI (kernel + initrd + cmdline, measured into PCR 4 by firmware and PCR 11
by systemd-stub) whose command line seals the dm-verity hash (`usrhash=`) of
the erofs partition holding `/nix/store`. On NixOS every measured-relevant
artifact — systemd, kernel modules, containerd, the launcher, every unit
file — is a store path, so pinning PCR 4/11 pins the entire base layer.
`/` is tmpfs; `/var` is writable ext4 for containerd state (outside the
measurement by design: workload integrity is anchored by the launcher's
PCR 13 image-digest measurement). Secure boot stays off; the verifier
*detects* modified images via PCR pinning.

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
  **vendorHash workflow**: when `go.mod`/`go.sum` change, set
  `vendorHash = lib.fakeHash`, build once, copy the `got: sha256-...` value
  from the error into the file.

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
   `deploy/create-instance.sh -i <image> -w <workload@sha256:...>`.
2. Watch `gcloud compute instances get-serial-port-output <name>`: UKI
   boot, `/dev/mapper/usr` active, DHCP lease with MTU 1460, containerd up,
   launcher pulling and serving on :8080.
3. On the serial console (root autologin): confirm `usrhash=` in
   `/proc/cmdline` and `/nix/store` read-only;
   `tpm2_pcrread sha256:0,4,7,11,12,13`; compare PCR 4/11 against the
   candidates in `expected-measurements.json` (`notes` field). Copy
   `/sys/kernel/security/tpm0/binary_bios_measurements` off the VM for
   event-level debugging. Confirm PCR 13 was zero before the launcher ran.
4. If `uki-only` is the correct PCR 4 variant, re-run
   `predict-measurements -pcr4-variant uki-only ...` and record it below.
5. `verifier verify -host <ip>:8080 -policy <policy> -expected
   <expected-measurements.json>` → PASS; rebuild the image with any change
   and confirm the old expected values now FAIL.
6. Rebuild `-p prod` and re-validate via the verifier alone (no console).

## Calibration results

_(fill in after first boot)_

- Date / image name / flake.lock nixpkgs rev:
- Fallback-path UKI boot: —
- PCR 4 variant confirmed: —
- PCR 11 matched prediction (stub section set): —
- Reproducibility double-build check: —
- Notes: —
