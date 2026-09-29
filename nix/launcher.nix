# The gc-tee launcher, built from the in-repo Go sources. buildGoModule
# passes -trimpath by default and the toolchain comes from the pinned
# nixpkgs, so the binary is reproducible from flake.lock alone.
{ lib, buildGoModule, gcTeeSrc }:

buildGoModule {
  pname = "gc-tee-launcher";
  version = "0.1.0";

  src = gcTeeSrc;
  subPackages = [ "cmd/launcher" ];

  # Update workflow: whenever go.mod/go.sum change, set this to lib.fakeHash,
  # build once, and copy the "got: sha256-..." value from the error here.
  # (Precomputed via `go mod vendor` + `nix hash path`; if the first build
  # reports a mismatch, trust the build's "got:" value.)
  vendorHash = "sha256-oLzAGCd0XzS6o6U0yYJSJ/oby6aakaj+v+NbWurFnWo=";

  env.CGO_ENABLED = "0";

  meta = {
    description = "Attestable-container launcher for GCP Confidential VMs";
    mainProgram = "launcher";
  };
}
