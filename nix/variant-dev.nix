# Dev variant: serial-console root autologin and TPM debugging tools for the
# calibration runbook (nix/README.md). Never deploy this to anything that
# matters — the console login defeats the operator-lockout story, and its
# PCR values differ from prod's anyway.
{ pkgs, ... }:

{
  environment.systemPackages = [ pkgs.tpm2-tools ];

  # services.getty.autologinUser only reaches getty@, not serial-getty@, so
  # override the serial getty on the GCE serial port explicitly.
  systemd.services."serial-getty@ttyS0" = {
    serviceConfig.ExecStart = [
      "" # clear the upstream ExecStart
      "@${pkgs.util-linux}/sbin/agetty agetty --autologin root --keep-baud %I 115200,57600,38400,9600 $TERM"
    ];
  };
}
