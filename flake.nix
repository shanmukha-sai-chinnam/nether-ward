{
  description = "Nether Ward: Declarative AI Infrastructure & Autonomous Cybersecurity Sentinel";

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

        pythonEnv = pkgs.python312;
      in {
        devShells.default = pkgs.mkShell {
          name = "nether-ward-shell";

          buildInputs = with pkgs; [
            # AI & Local Inference Runtimes
            ollama

            # Python ecosystem
            pythonEnv
            uv
            ruff

            # Node & JavaScript runtime
            nodejs_22

            # System compilers & build tools
            gcc
            pkg-config
            gnumake

            # Data query & CLI utilities
            curl
            jq
            ripgrep
            fd
            bat
            eza
          ];

          shellHook = ''
            export NETHER_WARD_SHELL=1
            export AI_INFRA_SHELL=1
            export UV_PYTHON_PREFERENCE="only-system"
            export UV_PYTHON="${pythonEnv}/bin/python3"
            export NETHER_WARD_ROOT="$(pwd)"

            # Ensure local virtual environment is active if initialized
            if [ -d ".venv" ]; then
              source .venv/bin/activate
            fi

            echo -e "\033[1;33m--------------------------------------------------------\033[0m"
            echo -e "\033[1;32m Nether Ward — Autonomous AI Security & Infrastructure\033[0m"
            echo -e "\033[1;33m--------------------------------------------------------\033[0m"
            echo -e "  \033[1;34mPython:\033[0m       $(${pythonEnv}/bin/python3 --version 2>&1)"
            echo -e "  \033[1;34mUV:\033[0m           $(${pkgs.uv}/bin/uv --version 2>&1)"
            echo -e "  \033[1;34mNode.js:\033[0m      $(${pkgs.nodejs_22}/bin/node --version 2>&1)"
            echo -e "  \033[1;34mOllama:\033[0m       v$(${pkgs.ollama}/bin/ollama --version 2>&1 | awk '/client version/{print $NF}')"
            echo -e "  \033[1;34mArchitecture:\033[0m Intel Lunar Lake (8 cores, AVX-VNNI active)"
            echo -e "\033[1;33m--------------------------------------------------------\033[0m"
          '';
        };

        formatter = pkgs.alejandra;
      }
    );
}
