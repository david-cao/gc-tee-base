# The gc-tee-base measured appliance, shared by the dev and prod variants.
#
# Shape (NixOS-native equivalent of the earlier mkosi image):
#   - UKI (systemd-stub: kernel + initrd + cmdline) at EFI/BOOT/BOOTX64.EFI,
#     measured into PCR 4 (firmware) and PCR 11 (stub).
#   - dm-verity erofs partition holding /nix/store, its hash sealed into the
#     UKI cmdline as usrhash= by image.repart.verityStore. On NixOS every
#     measured-relevant artifact (systemd, kernel modules, containerd, the
#     launcher, all unit files) is a store path, so pinning PCR 4/11 pins the
#     entire base layer.
#   - tmpfs /, writable ext4 /var for containerd state (deliberately outside
#     the measurement: workload integrity is anchored by the launcher's
#     PCR 13 image-digest measurement).
#   - No secure boot (unsigned UKI); the verifier pins PCR values instead.
{ config, lib, pkgs, modulesPath, gcTeeSrc, variant, ... }:

let
  launcher = pkgs.callPackage ./launcher.nix { inherit gcTeeSrc; };
in
{
  imports = [
    "${modulesPath}/profiles/image-based-appliance.nix"
    # Not in the default module list; must be imported explicitly.
    "${modulesPath}/image/repart.nix"
    "${modulesPath}/image/repart-verity-store.nix"
  ];

  system.stateVersion = "26.05";
  networking.hostName = "gc-tee";

  ### Disk image: ESP + verity-protected store (auto-declared) + writable var

  image.repart = {
    name = "gc-tee-base-${variant}";
    verityStore = {
      enable = true;
      # GCE firmware boots the EFI fallback path directly; no bootloader.
      ukiPath = "/EFI/BOOT/BOOTX64.EFI";
    };
    partitions = {
      "00-esp".repartConfig = {
        Type = "esp";
        Format = "vfat";
        SizeMinBytes = "256M";
        SizeMaxBytes = "256M";
      };
      # 10-store-verity and 20-store are declared by verityStore.
      "30-var".repartConfig = {
        Type = "var";
        Label = "var";
        Format = "ext4";
        SizeMinBytes = "6G";
        SizeMaxBytes = "6G";
      };
    };
  };

  fileSystems."/" = {
    device = "none";
    fsType = "tmpfs";
    options = [ "mode=0755" ];
  };
  fileSystems."/var" = {
    device = "/dev/disk/by-partlabel/var";
    fsType = "ext4";
  };

  boot.loader.grub.enable = false;
  boot.initrd.systemd.enable = true;
  boot.initrd.systemd.dmVerity.enable = true;

  ### GCE hardware (deliberately NOT google-compute-config.nix: that drags in
  ### the guest agent, GRUB, and OS Login; we need exactly four facts)

  boot.kernelParams = [ "console=ttyS0,115200n8" ];
  boot.initrd.availableKernelModules = [ "nvme" "virtio_scsi" "virtio_pci" ];
  boot.kernelModules = [ "gve" ];

  networking.useNetworkd = true;
  networking.useDHCP = false;
  systemd.network.networks."10-gce" = {
    matchConfig.Name = "en* eth*";
    networkConfig = {
      DHCP = "ipv4";
      DNSDefaultRoute = true;
    };
    # GCE serves MTU 1460 via DHCP; UseMTU is not on by default.
    dhcpV4Config = {
      UseMTU = true;
      UseDomains = true;
    };
  };
  services.resolved.enable = true;
  services.timesyncd.enable = true;

  ### Freeze PCR 11 at the stub-measured value. NixOS defaults already leave
  ### the pcrphase units disabled; disabling the tpm2 wiring and suppressing
  ### the units entirely is belt and braces so a nixpkgs bump cannot silently
  ### start extending PCR 11 post-stub.

  systemd.tpm2.enable = false;
  boot.initrd.systemd.tpm2.enable = false;
  systemd.suppressedSystemUnits = [
    "systemd-pcrphase.service"
    "systemd-pcrphase-sysinit.service"
    "systemd-pcrmachine.service"
    "systemd-pcrfs-root.service"
    "systemd-pcrfs@.service"
    "systemd-pcrextend@.service"
    "systemd-pcrextend.socket"
    "systemd-pcrlock-make-policy.service"
  ];
  boot.initrd.systemd.suppressedUnits = [
    "systemd-pcrphase-initrd.service"
  ];

  ### Workload runtime

  virtualisation.containerd = {
    enable = true;
    settings = {
      version = 2;
      root = "/var/lib/containerd";
      state = "/run/containerd";
    };
  };

  systemd.services.gc-tee-launcher = {
    description = "gc-tee attestable container launcher";
    wantedBy = [ "multi-user.target" ];
    wants = [ "network-online.target" ];
    after = [ "network-online.target" "containerd.service" "systemd-timesyncd.service" ];
    requires = [ "containerd.service" ];
    serviceConfig = {
      # Launch spec comes from GCE instance metadata (tee-image-reference,
      # tee-cmd, tee-env-*, tee-restart-policy). Restart= covers launcher
      # failures only; the workload restart policy is the launcher's job.
      ExecStart = "${launcher}/bin/launcher -metadata";
      Restart = "on-failure";
      RestartSec = 5;
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
  };

  # No interactive users; root is locked (the dev variant layers autologin on
  # top, which bypasses authentication rather than adding a password).
  users.users.root.hashedPassword = "!";
  users.allowNoPasswordLogin = true;

  documentation.enable = lib.mkDefault false;
}
