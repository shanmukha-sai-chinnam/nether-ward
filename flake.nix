{
  description = "Nether Ward: Static security scanner and adversarial red team evaluation harness in Rust and Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
          };
        };
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "nether-ward";
          version = "0.2.0";
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = [
            pkgs.pkg-config
          ];

          buildInputs = [
            pkgs.openssl
          ];
        };

        packages.nether-ward = self.packages.${system}.default;

        formatter = pkgs.alejandra;

        devShells.default = pkgs.mkShell {
          name = "nether-ward-shell";

          buildInputs = [
            # Rust Compiler & Native Toolchain
            pkgs.cargo
            pkgs.rustc
            pkgs.rustfmt
            pkgs.clippy
            pkgs.rust-analyzer

            # Build dependencies
            pkgs.pkg-config
            pkgs.openssl

            # System inspection & utilities
            pkgs.jq
            pkgs.curl
            pkgs.ripgrep
          ];

          shellHook = ''
            export NETHER_WARD_SHELL=1
            export AI_INFRA_SHELL=1
            export RUST_BACKTRACE=1
            export NETHER_WARD_ROOT="$(pwd)"
          '';
        };
      }
    );
}
