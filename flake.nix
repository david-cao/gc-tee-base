{
  description = "gc-tee-base: reproducible measured Confidential VM image for GCP";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      mkSystem = variant:
        nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          specialArgs = {
            gcTeeSrc = self;
            inherit variant;
          };
          modules = [
            ./nix/appliance.nix
            ./nix/variant-${variant}.nix
          ];
        };

      # Per variant: the disk image (raw + repart-output.json with the verity
      # hash) and the final UKI (with usrhash= sealed in its cmdline) as
      # separately buildable outputs.
      forVariant = variant:
        let cfg = (mkSystem variant).config;
        in {
          "image-${variant}" = cfg.system.build.image;
          "uki-${variant}" = cfg.system.build.uki;
        };
      # The launcher on its own, buildable on any system. Its vendor
      # derivation is platform-independent, so `nix build .#launcher` (even
      # on a Mac) is the quick way to resolve nix/launcher.nix vendorHash
      # after go.mod or import changes.
      launcherFor = system:
        (import nixpkgs { inherit system; }).callPackage ./nix/launcher.nix {
          gcTeeSrc = self;
        };
      systems = [ "x86_64-linux" "aarch64-darwin" "x86_64-darwin" ];
    in {
      nixosConfigurations = {
        gc-tee-dev = mkSystem "dev";
        gc-tee-prod = mkSystem "prod";
      };

      packages = nixpkgs.lib.genAttrs systems (system:
        { launcher = launcherFor system; }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux")
          (forVariant "dev" // forVariant "prod"));
    };
}
