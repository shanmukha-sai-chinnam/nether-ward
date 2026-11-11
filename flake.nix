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

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
            openssl
          ];
        };

        packages.nether-ward = self.packages.${system}.default;

        devShells.default = pkgs.mkShell {
          name = "nether-ward-shell";

          buildInputs = with pkgs; [
            # Rust Compiler & Native Toolchain
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer

            # Build dependencies
            pkg-config
            openssl

            # System inspection & utilities
            jq
            curl
            ripgrep
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
