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

        # scls-util binary from the cardano-cls flake
        scls-util = cardano-cls.packages.${system}."scls-util:exe:scls-util";

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "clippy"
            "rustfmt"
          ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common arguments for all Crane builds
        commonArgs = {
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              (craneLib.fileset.commonCargoSources ./.)
              ./tests
              ./.config
            ];
          };
          strictDeps = true;
        };

        # Build *just* the Cargo dependencies, so we can reuse
        # all of that work (e.g. via Cachix) when running in CI
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual crate itself, reusing the dependency artefacts
        cardano-scrawls = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            doCheck = false; # We already run Nextest; this is redundant
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

          # Run unit tests with Nextest
          cardano-scrawls-nextest-unit-tests = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
              cargoNextestExtraArgs = "--profile unit";
            }
          );

          # Run integration tests with Nextest
          cardano-scrawls-nextest-integration-tests = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
              nativeBuildInputs = [ scls-util ];
              cargoNextestExtraArgs = "--profile integration";
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
            scls-util
          ];

          # Environment variables
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };
      }
    );

  nixConfig = {
    extra-substituters = [
      "https://tweag-cardano-cls.cachix.org"
    ];
    extra-trusted-public-keys = [
      "tweag-cardano-cls.cachix.org-1:4/Ger2Oe/TpXbV4RY45mvuFt6t4RFMiJXi1y4/YugIU="
    ];
  };
}
