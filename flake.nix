{
  description = "Cardano standard canonical ledger state (SCLS) library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    cardano-cls.url = "github:tweag/cardano-cls";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      rust-overlay,
      cardano-cls,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "clippy"
            "rustfmt"
          ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common arguments for all crane builds
        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
        };

        # Build *just* the cargo dependencies, so we can reuse
        # all of that work (e.g. via Cachix) when running in CI
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual crate itself, reusing the dependency artefacts
        cardano-scrawls = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
          }
        );
      in
      {
        checks = {
          # Build the crate as part of `nix flake check`
          inherit cardano-scrawls;

          # Run Clippy (and deny all warnings) on the crate source
          cardano-scrawls-clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );

          # Check formatting
          cardano-scrawls-fmt = craneLib.cargoFmt {
            inherit (commonArgs) src;
          };

          # Run tests with cargo-nextest
          cardano-scrawls-nextest = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
              cargoNextestExtraArgs = "--no-fail-fast --success-output immediate --failure-output immediate";
            }
          );
        };

        packages = {
          default = cardano-scrawls;
          cardano-scrawls = cardano-scrawls;
        };

        devShells.default = craneLib.devShell {
          # Inherit inputs from checks
          checks = self.checks.${system};

          # Additional dev tools
          packages = [
            pkgs.rust-analyzer
            cardano-cls.packages.${system}."scls-util:exe:scls-util"
          ];

          # Environment variables
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };
      }
    );

  nixConfig = {
    extra-substituters = [
      "https://tweag-cardano-cls.cachix.org"
      "https://cache.iog.io"
    ];
    extra-trusted-public-keys = [
      "tweag-cardano-cls.cachix.org-1:4/Ger2Oe/TpXbV4RY45mvuFt6t4RFMiJXi1y4/YugIU="
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    ];
    allow-import-from-derivation = "true";
  };
}
