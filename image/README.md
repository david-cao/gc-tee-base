# gc-tee-base measured image

mkosi configuration for the measured Confidential VM image: a UKI
(kernel + initrd + cmdline, measured into PCR 4 by firmware and PCR 11 by
systemd-stub) whose command line seals the dm-verity root hash of the
read-only rootfs containing the launcher and containerd. Pinning PCR 4/11
therefore pins the entire base layer — this closes the "unmeasured
bookkeeper" gap of running the launcher on a stock OS image.

Build with [deploy/build-image.sh](../deploy/build-image.sh) (runs mkosi on a
throwaway GCE builder VM). Secure boot stays **off**: the UKI is unsigned and
the verifier detects (rather than blocks) modified images via PCR pinning.

## Layout

- `mkosi.conf` — Ubuntu noble, `Format=disk`, `Bootloader=uki`,
  `Verity=hash`, split artifacts (UKI / PCR prediction / roothash)
- `mkosi.repart/` — ESP, erofs root (`Verity=data`), verity hash partition,
  writable ext4 `/var` (containerd state; deliberately unmeasured — workload
  integrity is anchored by the launcher's PCR 13 image-digest measurement)
- `mkosi.extra/` — launcher systemd unit, networkd config (DHCP, `UseMTU`
  for GCE's 1460), containerd config; `usr/bin/gc-tee-launcher` is injected
  by the build script (cross-compiled, CGO-free)
- `mkosi.postinst` — masks all `systemd-pcr*` units so PCR 11 stays frozen
  at the stub-measured value; enables networkd/timesyncd/containerd/launcher
- `mkosi.profiles/dev` — serial-console autologin + tpm2-tools (calibration
  only); `prod` — no login path

## Calibration runbook (first boot of a new image shape)

Two things cannot be fully predicted from documentation and must be
confirmed once against real GCE firmware (then recorded here):

1. **Fallback-path UKI boot** — GCE UEFI firmware must boot
   `EFI/BOOT/BOOTX64.EFI` directly.
2. **PCR 4 composition** — whether the firmware log contains only the UKI's
   authentihash or also the embedded kernel's (systemd-stub LoadImage).
   `predict-measurements` emits both candidates (`uki-and-kernel`, default,
   and `uki-only`).

Steps:

1. `deploy/build-image.sh -p dev` then
   `deploy/create-instance.sh -i <image> -w <workload@sha256:...>`.
2. Watch `gcloud compute instances get-serial-port-output <name>`: UKI boot,
   verity root mount, DHCP lease (MTU 1460), containerd start, launcher
   pulling and serving on :8080.
3. On the serial console (root autologin):
   `tpm2_pcrread sha256:0,4,7,11,12,13` and compare PCR 4/11 with both
   candidates in `expected-measurements.json` (`notes` field). Copy
   `/sys/kernel/security/tpm0/binary_bios_measurements` off the VM if the
   values need event-level debugging. Confirm PCR 11 matches the prediction
   (all `systemd-pcr*` units masked) and PCR 13 was zero before the launcher
   ran (its value must replay from the canonical event log alone).
4. If `uki-only` is the correct PCR 4 variant, re-run
   `predict-measurements -pcr4-variant uki-only ...` and record the result
   here.
5. `verifier verify -host <ip>:8080 -policy <policy> -expected
   <expected-measurements.json>` → PASS. Rebuild the image with any change
   and confirm the old expected-measurements now FAIL against the new image.
6. Rebuild `-p prod` and re-validate via the verifier alone (no console).

## Calibration results

_(fill in after first boot)_

- Date / image name:
- Fallback-path UKI boot: works? —
- PCR 4 variant confirmed: —
- PCR 11 matched prediction: —
- Notes (event log oddities, extra PCR 4 events, etc.): —
