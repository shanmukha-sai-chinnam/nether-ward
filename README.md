# Nether Ward

Static application security testing (SAST) and synthetic red team evaluation harness in Rust and Nix.

Named after Pugna's Nether Ward in Dota 2: an in-game ward that monitors its area and strikes enemy heroes when they cast abilities.

---

## Capabilities

- **Active Stdio MCP Security Proxy (`nether-ward mcp --proxy [--sanitize] -- <cmd>`)**: Intercepts line-delimited JSON-RPC messages between coding agents (Antigravity, Claude Code, Cursor) and local MCP server tools. Blocks hostile commands (`rm -rf /`, reverse shells) with structured JSON-RPC 2.0 error responses without terminating the server session, and redacts exposed credentials in-flight.
- **MCP Configuration Security Auditor (`nether-ward mcp --config <path>`)**: Audits `.agents/mcp_config.json` for shell-wrapping antipatterns (`bash -c`, `sh`), injected arguments, and exposed environment credentials.
- **Static Analysis (SAST) Engine (`nether-ward threat --sast <dir>`)**: Scans source code, agent tools, and configurations for exposed API secrets, dynamic code evaluation (`eval`, `exec`), shell invocations (`os.system`, `subprocess(shell=True)`), pickle deserialization payloads (`__reduce__`), and SQL injection patterns.
- **Sliding-Window & Shannon Entropy Triage (`nether-ward threat --dir <dir>`)**: Computes byte-level information entropy ($H = -\sum p \log_2 p$) and localized sliding-window entropy across chunks to identify packed binaries, obfuscated payloads, and embedded shellcode stagers.
- **Synthetic Red Teaming (`nether-ward redteam`)**: Executes parallel asynchronous probes (`tokio::sync::Semaphore`) evaluating target models against the OWASP Top 10 for Large Language Models. Supports deterministic substring matching, regex assertions (`regex`, `not-regex`), tool misuse assertions (`tool-not-called`), and SAST cleanliness assertions (`sast-clean`).
- **Dual Model Runtime Support (`--endpoint`)**: Evaluates remote cloud APIs (Google Gemini) or local OpenAI-compatible endpoints (`/v1/chat/completions`) such as Ollama, llama.cpp, or Nether Ward's internal gateway.
- **TypeSafe AI (Jev System One) Semantic Judge**: Evaluates condition probabilities (`noul`) and risk scores (`score`) via TypeSafe Jev System One to verify model refusal and compliance without brittle substring regexes.
- **AI Security Gateway (`nether-ward gateway`)**: Axum reverse proxy with runtime tool-call firewall, in-flight secret sanitization (`--sanitize`), Server-Sent Events (`stream: true`), and operational telemetry (`/v1/stats`, `/metrics`).
- **CI/CD Integration**: Nix flake packaging, automated RustSec advisory checks, OASIS SARIF v2.1.0 export to GitHub Code Scanning, SPDX SBOM generation, and GitHub Pages matrix reporting.

---

## Quick Start

```bash
# 1. Enter the hermetic Nix development shell
nix develop

# 2. Build the native release binary
cargo build --release

# 3. List active SAST and threat detection rules
./target/release/nether-ward threat --rules

# 4. Run static application security testing (SAST) on a source directory
./target/release/nether-ward threat --sast datasets/threat_samples

# 5. Triage an untrusted file or directory for Shannon entropy and stagers
./target/release/nether-ward threat --sample datasets/threat_samples/obfuscated_high_entropy.bin
./target/release/nether-ward threat --dir datasets/threat_samples

# 6. Audit MCP configuration files (.agents/mcp_config.json)
./target/release/nether-ward mcp --config /home/damathryxx64/repositories/.agents/mcp_config.json

# 7. Run transparent stdio MCP security proxy wrapping a target server
./target/release/nether-ward mcp --proxy --sanitize -- mcp-server-git --repo /home/damathryxx64/repositories

# 8. Start the native AI security gateway reverse proxy with secret sanitization (port 4000)
./target/release/nether-ward gateway --port 4000 --sanitize

# 9. Query gateway operational metrics and Prometheus telemetry
curl http://localhost:4000/v1/stats
curl http://localhost:4000/metrics

# 10. Run synthetic red team evaluation against local endpoint
./target/release/nether-ward redteam --dataset datasets/owasp_top10_expanded.jsonl --endpoint http://localhost:4000/v1/chat/completions --concurrency 5

# 11. Run synthetic red team evaluation against Gemini with Jev semantic judge
./target/release/nether-ward redteam --dataset datasets/owasp_top10_expanded.jsonl --concurrency 8

# 12. Verify local inference engine connectivity (Ollama)
./target/release/nether-ward inference
```

---

## Architecture & Threat Model

For the technical problem statement, 5-layer threat model, and architectural blueprint, read [docs/problem_statement_and_architecture.md](docs/problem_statement_and_architecture.md).

### Component Layout

| Path | Purpose |
|---|---|
| `flake.nix` | Hermetic Nix devShell and package derivation. Zero unmanaged state. |
| `values.json` | Declarative hub for ports, endpoints, model routes, and timeouts. |
| `src/main.rs` | CLI entrypoint orchestrating subcommands. |
| `src/sast.rs` | Static analysis rule engine, token redaction, and directory auditing. |
| `src/threat.rs` | Shannon and windowed entropy profiling, string extraction, and triage. |
| `src/jev.rs` | TypeSafe AI System One HTTP client for calibrated semantic judgments. |
| `src/mcp.rs` | Model Context Protocol configuration auditor and bidirectional stdio security proxy. |
| `src/redteam.rs` | Multi-turn red team runner, regex/SAST assertions, JUnit XML, and HTML matrix. |
| `src/gateway.rs` | Axum reverse proxy with tool-call firewall, secret sanitization, SSE streaming, and metrics. |
| `datasets/` | Synthetic test suites: `owasp_top10_expanded.jsonl`, `threat_samples/`, and `trajectories/`. |
| `.github/workflows/` | GitHub Actions pipelines: CodeQL, RustSec audit, JUnit checks, and Pages deployment. |

---

## Static Analysis (SAST) Rule Registry

| Rule ID | Severity | Category | Target |
|---|---|---|---|
| `NW-SEC-001` | CRITICAL | Secret Leak | AWS Access Key ID (`AKIA...`) |
| `NW-SEC-002` | CRITICAL | Secret Leak | OpenAI / Claude API Keys (`sk-...`) |
| `NW-SEC-003` | CRITICAL | Secret Leak | Google Cloud / Gemini API Keys (`AIzaSy...`) |
| `NW-SEC-004` | CRITICAL | Secret Leak | GitHub Personal Access Tokens (`ghp_...`, `gho_...`) |
| `NW-SEC-005` | HIGH | Secret Leak | Slack Bot & User Tokens (`xoxb-...`) |
| `NW-SEC-006` | CRITICAL | Secret Leak | Private Cryptographic Key Headers (`BEGIN RSA PRIVATE KEY`) |
| `NW-CODE-001` | HIGH | Dangerous Code | Dynamic Code Execution (`eval()`, `exec()`) |
| `NW-CODE-002` | HIGH | Dangerous Code | Unsafe Shell Calls (`os.system()`) |
| `NW-CODE-003` | HIGH | Dangerous Code | Subprocess with `shell=True` |
| `NW-CODE-004` | HIGH | Dangerous Code | Node.js Unsafe Processes (`child_process.exec()`) |
| `NW-ML-001` | CRITICAL | Model Deserialization | Insecure Python Pickle Loading (`pickle.loads()`) |
| `NW-ML-002` | CRITICAL | Model Deserialization | Pickle Bytecode RCE Reducer (`__reduce__`) |
| `NW-ML-003` | MEDIUM | Model Deserialization | PyTorch Weights Loading without Safetensors |
| `NW-ML-004` | HIGH | Model Deserialization | NumPy Deserialization with `allow_pickle=True` |
| `NW-SYS-001` | CRITICAL | System Execution | Bash Network Redirection Reverse Shells (`/dev/tcp/`) |
| `NW-SYS-002` | CRITICAL | System Execution | Destructive Filesystem Deletions (`rm -rf /`) |
| `NW-SYS-003` | HIGH | System Execution | Sensitive Database Reconnaissance (`cat /etc/shadow`) |
| `NW-SYS-004` | HIGH | System Execution | PowerShell Web Download Stagers (`Invoke-Expression`) |
| `NW-INJ-001` | HIGH | Injection | Directory Path Traversal Sequences (`../../../../`) |
| `NW-INJ-002` | HIGH | Injection | SQL Injection Syntax in Parameters (`' OR '1'='1`) |

---

## Continuous CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ai-security-pipeline.yml`) runs on every commit:
1. **Validate Rust Code & Configs**: Enforces `cargo fmt --check` and `cargo clippy -- -D warnings`.
2. **Static Secret Detection**: Scans tracked repository files with `git grep`.
3. **Threat Triage & SAST Audit**: Runs `cargo test`, batch entropy triage, and static vulnerability scanning.
4. **RustSec Advisory Audit**: Audits 187 crate dependencies with zero vulnerabilities.
5. **Synthetic Red Team Matrix**: Runs 30 adversarial probes across 8 workers against Gemini and Jev System One.
6. **Checks & Pages**: Emits sanitized JUnit XML reports and deploys interactive HTML dashboards with SPDX SBOM.
