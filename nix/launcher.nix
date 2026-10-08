# The gc-tee launcher, built from the in-repo Go sources. buildGoModule
# passes -trimpath by default and the toolchain comes from the pinned
# nixpkgs, so the binary is reproducible from flake.lock alone.
{ lib, buildGoModule, gcTeeSrc }:

buildGoModule {
  pname = "gc-tee-launcher";
  version = "0.2.0";

  src = gcTeeSrc;
  subPackages = [ "cmd/launcher" ];

  # Update workflow: whenever go.mod/go.sum or the import graph change, set
  # this to lib.fakeHash, run `nix build .#launcher` (works on any system,
  # including macOS), and copy the "got: sha256-..." value from the error.
  vendorHash = "sha256-foB+MAyIWi6fRwwZydwysMv6qh9xg+GUIkXsnUi/NPw=";

  env.CGO_ENABLED = "0";

  meta = {
    description = "Attestable-container launcher for GCP Confidential VMs";
    mainProgram = "launcher";
  };
}
