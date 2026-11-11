# ai-infra

Declarative AI Infrastructure Engineering Platform & Agentic Toolkit.

Provides reproducible devShells, unified AI Gateway routing, local quantized inference runners, and automated prompt evaluation test benches.

## Quick Start

```bash
# Enter the hermetic Nix development shell
nix develop

# Or with direnv active:
cd repositories/ai-infra

# Run the LiteLLM AI Gateway
./bin/gateway
```

## Architecture

- **`flake.nix`**: Hermetic Nix development shell (Python 3.12, `uv`, Node.js 22, GCC, C/C++ toolchain).
- **`values.json`**: Declarative configuration hub for ports, endpoints, and model routing.
- **`config/`**: Declarative proxy and evaluation configurations.
- **`bin/`**: Operational task runners (`bin/gateway`).
