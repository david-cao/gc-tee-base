# Prod variant: no login path at all. Root is locked (appliance.nix), there
# is no sshd, and even the serial login prompt is removed — the serial port
# still carries journal+console output for read-only debugging.
{ lib, ... }:

{
  systemd.services."serial-getty@ttyS0".enable = false;
  systemd.services."getty@tty1".enable = false;
}
