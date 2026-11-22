# Nether Ward

Static application security testing (SAST), runtime sentinel, and synthetic red team evaluation harness in Rust and Nix.

Named after Pugna's Nether Ward in Dota 2: an in-game ward that monitors its area and strikes enemy heroes when they cast abilities.

---

## Capabilities

- **Claude Code Autonomous Hook Sentinel (`nether-ward hook install / claude`)**: Intercepts Claude Code agent tool executions via `PreToolUse` and `PostToolUse` stdin/stdout hooks. Validates bash commands and filesystem accesses against ACL policies, enforces dual-key approval on destructive operations, detects planted canary token leaks, redacts exposed secrets in tool outputs, and automatically encapsulates untrusted outputs in context quarantine boundaries.
- **Reusable GitHub Action (`uses: shanmukha-sai-chinnam/nether-ward@trunk`)**: Reusable composite action allowing any external repository to execute Nether Ward SAST scanning, Shannon entropy analysis, and ACL path audits with automatic SARIF upload to GitHub Code Scanning and step summary scorecards.
- **Empirical Detection Benchmark Suite (`nether-ward benchmark`)**: Evaluates Nether Ward defensive engines against standardized threat corpora (OWASP Top 10 for LLMs, agent tool injection, canary exfiltration, path traversal). Measures Accuracy, Precision, Recall, F1 Score, False Positive Rate, and inspection latency.
- **Declarative Resource Access Control Lists (ACL) & Confinement Sentinel (`nether-ward acl check / audit / rules`)**: Enforces path canonicalization, symlink breakout detection, and strict workspace root confinement across agent filesystem tools (`read_file`, `write_file`, `edit_file`, `delete_file`, `move_file`) and command executions (`run_command`, `bash`, `exec`). Blocks access to operating system paths (`/etc`, `/proc`, `/sys`, `/dev`), private keys (`.ssh`, `*.pem`, `*.key`), and infrastructure credentials (`.aws`, `.env*`, `gcloud`, `kube`).
- **Automated Behavioral Regression (ABR) Evaluator (`nether-ward abr --baseline <FILE> --candidate <FILE>`)**: Evaluates PR and commit changes to agent prompts, system instructions, and tool declarations against baseline security risk scores. Combines TypeSafe Jev System One calibrated scoring with deterministic SAST heuristic analysis to block regressions in CI before merging.
- **Adaptive Token Bucket & Quota Governor**: Manages token bucket capacity with Additive Increase / Multiplicative Decrease (AIMD) pacing, parses upstream `Retry-After` and `X-RateLimit-*` headers, and applies decorrelated exponential backoff across Gateway and Red Team parallel workers to eliminate HTTP 429 quota exhaustion.
- **Active Stdio MCP Security Proxy (`nether-ward mcp --proxy [--sanitize] [--semantic] [--quarantine] -- <cmd>`)**: Intercepts line-delimited JSON-RPC messages between coding agents (Antigravity, Claude Code, Cursor) and local MCP server tools. Evaluates stateful multi-turn attack chains (staged drop-and-execute sequences, sensitive read followed by outbound exfiltration), blocks hostile commands (`rm -rf /`, reverse shells) with structured JSON-RPC 2.0 error responses without terminating the server session, evaluates tool invocations against Jev System One semantic policies (`--semantic`), redacts exposed credentials in-flight (`--sanitize`), and encapsulates untrusted tool response content in context quarantine boundaries (`--quarantine`).
- **Canary Tokens & Honeypot Decoys (`nether-ward canary plant --dir <DIR> / canary scan`)**: Generates deterministic and high-entropy canary tokens for AWS, GCP, Slack, and private keys. Plants synthetic decoy honeypot files (`.aws/credentials`, `.env.canary`) with registered tripwires to trap unauthorized agent directory traversal and detects token leakage in prompts or command arguments.
- **Operational Velocity Limits & Dual-Key Approval Gates (`nether-ward gate auth`)**: Tracks cumulative agent edit tokens and command execution rate over a sliding time window. Wraps quarantined contexts (`<<<CONTEXT_QUARANTINE_BOUNDARY>>>`) to neutralize indirect prompt injection payloads, and enforces dual-key authorization requirements for high-risk operations (e.g. database dropped, system switches).
- **Bicameral Semantic Firewall Gateway (`nether-ward gateway [--port <PORT>] [--sanitize] [--semantic-firewall] [--quarantine]`)**: Axum reverse proxy with runtime tool-call firewall, in-flight secret sanitization, context quarantine auto-wrapping for tool responses (`--quarantine`), Server-Sent Events (`stream: true`), operational telemetry (`/v1/stats`, `/metrics`), and pre-execution semantic inspection via TypeSafe Jev System One (`--semantic-firewall`).
- **Kernel Sandbox Runner (`nether-ward sandbox [--workspace <dir>] [--no-network] [--dry-run] -- <cmd>`)**: Executes agent tools and subprocesses inside ephemeral Linux kernel security boundaries using Bubblewrap container namespaces (`bwrap`) or native `PR_SET_NO_NEW_PRIVS` with network namespace isolation (`CLONE_NEWNET`) and environment variable scrubbing (`LD_PRELOAD`, `LD_LIBRARY_PATH`).
- **MCP Configuration Security Auditor (`nether-ward mcp --config <path>`)**: Audits `.agents/mcp_config.json` for shell-wrapping antipatterns (`bash -c`, `sh`), injected arguments, and exposed environment credentials.
- **Static Analysis (SAST) & De-Obfuscation Engine (`nether-ward threat --sast <dir>`)**: Scans source code, agent tools, and configurations for exposed API secrets, dynamic code evaluation (`eval`, `exec`), shell invocations (`os.system`, `subprocess(shell=True)`), reflection-based evasion (`getattr(__import__('os'), 'system')`), string concatenation tricks, base64-encoded shellcode stagers, pickle deserialization payloads (`__reduce__`), and SQL injection patterns. Suppresses comment false-positives while preserving secret detection.
- **Sliding-Window & Shannon Entropy Triage (`nether-ward threat --dir <dir>`)**: Computes byte-level information entropy ($H = -\sum p \log_2 p$) and localized sliding-window entropy across chunks to identify packed binaries, obfuscated payloads, and embedded shellcode stagers.
- **Autonomous Adversarial Red Teaming & Mutation Fuzzing (`nether-ward redteam [--fuzz]`)**: Executes parallel asynchronous probes (`tokio::sync::Semaphore`) evaluating target models against the OWASP Top 10 for Large Language Models. Supports deterministic substring matching, regex assertions (`regex`, `not-regex`), tool misuse assertions (`tool-not-called`), SAST cleanliness assertions (`sast-clean`), and autonomous adversarial mutation synthesis (`--fuzz`) for delimiter evasion, persona roleplay, and hex polyglots.
- **Dual Model Runtime Support (`--endpoint`)**: Evaluates remote cloud APIs (Google Gemini) or local OpenAI-compatible endpoints (`/v1/chat/completions`) such as Ollama, llama.cpp, or Nether Ward's internal gateway.
- **TypeSafe AI (Jev System One) Semantic Judge**: Evaluates condition probabilities (`noul`) and risk scores (`score`) via TypeSafe Jev System One to verify model refusal and compliance without brittle substring regexes.
- **CI/CD Integration**: Hermetic Nix flake derivation build, automated RustSec advisory checks, OASIS SARIF v2.1.0 export to GitHub Code Scanning, SPDX SBOM generation, and GitHub Pages matrix reporting.

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

# 7. Run transparent stdio MCP security proxy with in-flight sanitization and semantic guard
./target/release/nether-ward mcp --proxy --sanitize --semantic -- mcp-server-git --repo /home/damathryxx64/repositories

# 8. Plant synthetic honeypot decoy files in a directory
./target/release/nether-ward canary plant --dir /tmp/test_workspace

# 9. Scan for canary token leaks or honeypot file accesses
./target/release/nether-ward canary scan --dir /tmp/test_workspace

# 10. Start the native AI security gateway reverse proxy with semantic firewall and context quarantine (port 4000)
./target/release/nether-ward gateway --port 4000 --sanitize --semantic-firewall --quarantine

# 11. Query gateway operational metrics and Prometheus telemetry
curl http://localhost:4000/v1/stats
curl http://localhost:4000/metrics

# 12. Run synthetic red team evaluation against local gateway with adversarial fuzzing
./target/release/nether-ward redteam --dataset datasets/owasp_top10_expanded.jsonl --endpoint http://localhost:4000/v1/chat/completions --concurrency 5 --fuzz

# 13. Verify local inference engine connectivity (Ollama)
./target/release/nether-ward inference

# 14. Run Automated Behavioral Regression (ABR) evaluation comparing baseline and candidate
./target/release/nether-ward abr --baseline config/redteam_config.yaml --candidate config/redteam_config.yaml --max-risk-delta 0.05

# 15. Check path permissions against declarative ACL rules and audit directory symlinks
./target/release/nether-ward acl check --path /etc/shadow
./target/release/nether-ward acl check --path ./src/main.rs --workspace .
./target/release/nether-ward acl audit --dir .

# 16. Install Claude Code hooks into .claude/settings.json
./target/release/nether-ward hook install

# 17. Run empirical detection benchmark suite across public datasets and export scorecard
./target/release/nether-ward benchmark --export benchmarks/results.json --markdown benchmarks/SCORECARD.md
```

---

## Reusable GitHub Action

External repositories can integrate Nether Ward static scanning, entropy analysis, and ACL path verification by adding this step to `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main, trunk]
  pull_request:
    branches: [main, trunk]

jobs:
  nether-ward:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Nether Ward Scanner
        uses: shanmukha-sai-chinnam/nether-ward@trunk
        with:
          path: '.'
          sast: 'true'
          sarif: 'results.sarif'
          upload-sarif: 'true'
          acl-audit: 'true'
          fail-on-critical: 'true'
```

---

## Empirical Benchmark Detection Results

Nether Ward was evaluated against public standardized threat datasets covering the OWASP Top 10 for LLMs, agent tool injection vectors, canary exfiltration, and path traversal:

### Executive Summary

| Metric | Measured Value | Standard Target | Status |
| :--- | :---: | :---: | :---: |
| **Total Samples Evaluated** | **38** | - | Validated |
| **Overall Accuracy** | **100.0%** | >= 95.0% | PASSED |
| **Precision (PPV)** | **100.0%** | >= 98.0% | PASSED |
| **Recall / Sensitivity (TPR)** | **100.0%** | >= 95.0% | PASSED |
| **F1 Score** | **1.000** | >= 0.950 | PASSED |
| **False Positive Rate (FPR)** | **0.0%** | <= 2.0% | PASSED |
| **Mean Inspection Latency** | **4.06 ms** | <= 50.0 ms | OPTIMAL |
| **95th Percentile Latency (p95)** | **7.82 ms** | <= 100.0 ms | OPTIMAL |

### Confusion Matrix

| | Predicted Threat | Predicted Clean | Total |
| :--- | :---: | :---: | :---: |
| **Actual Threat** | **TP: 22** | **FN: 0** | 22 |
| **Actual Clean** | **FP: 0** | **TN: 16** | 16 |
| **Total** | 22 | 16 | 38 |

### Category Breakdown

| Threat Category | Samples | Malicious | Detected | Precision | Recall | F1 Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Agent Execution Sandbox | 4 | 2 | 2 | 100.0% | 100.0% | 1.000 | PASSED |
| Canary & Decoy Tripwire | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| Filesystem ACL Confinement | 4 | 2 | 2 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM01: Prompt Injection | 4 | 3 | 3 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM02: Sensitive Info Disclosure | 3 | 2 | 2 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM03: Supply Chain Risk | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM04: Data & Model Poisoning | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM05: Improper Output Handling | 3 | 2 | 2 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM06: Excessive Agency / Command Execution | 4 | 2 | 2 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM07: System Prompt Leakage | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM08: Vector & Context Exploitation | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM09: Obfuscated Payloads | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM10: Path Traversal & Escape | 4 | 3 | 3 | 100.0% | 100.0% | 1.000 | PASSED |

---

## Architecture & Threat Model

For the technical problem statement, 5-layer threat model, and architectural blueprint, read [docs/problem_statement_and_architecture.md](docs/problem_statement_and_architecture.md).

### Component Layout

| Path | Purpose |
|---|---|
| `flake.nix` | Hermetic Nix devShell and package derivation. Zero unmanaged state. |
| `values.json` | Declarative hub for ports, endpoints, model routes, and timeouts. |
| `action.yml` | Reusable composite GitHub Action for external CI workflows. |
| `src/main.rs` | CLI entrypoint orchestrating subcommands. |
| `src/hook.rs` | Claude Code PreToolUse and PostToolUse autonomous security hook engine. |
| `src/benchmark.rs` | Public dataset detection benchmark runner, metrics aggregator, and scorecard generator. |
| `src/acl.rs` | Declarative Resource Access Control Lists, canonicalization, and symlink escape sentinel. |
| `src/abr.rs` | Automated Behavioral Regression evaluator comparing baseline and candidate risk scores. |
| `src/governor.rs` | Adaptive Rate Governor and Token Bucket with AIMD pacing and Retry-After backoff. |
| `src/sast.rs` | Static analysis rule engine, token redaction, and directory auditing. |
| `src/threat.rs` | Shannon and windowed entropy profiling, string extraction, and triage. |
| `src/jev.rs` | TypeSafe AI System One HTTP client for calibrated semantic judgments. |
| `src/mcp.rs` | Model Context Protocol configuration auditor, stdio proxy, and semantic guard. |
| `src/canary.rs` | Synthetic canary token generation, honeypot decoy planting, and leak detection. |
| `src/velocity.rs` | Operational velocity limiting, context quarantine wrapping, and dual-key authorization gates. |
| `src/redteam.rs` | Multi-turn red team runner, adversarial mutation fuzzing, JUnit XML, and HTML report. |
| `src/sandbox.rs` | Ephemeral Linux kernel sandbox runner (Bubblewrap and native PR_SET_NO_NEW_PRIVS). |
| `src/gateway.rs` | Axum reverse proxy with tool-call firewall, semantic inspection, secret sanitization, and metrics. |
| `benchmarks/` | Standardized evaluation corpora: `owasp_llm_top10.jsonl`, `agent_threats.jsonl`. |
| `datasets/` | Synthetic test suites: `owasp_top10_expanded.jsonl`, `threat_samples/`, and `trajectories/`. |
| `.github/workflows/` | 14-stage GitHub Actions pipeline: CodeQL, RustSec audit, JUnit checks, and Pages deployment. |

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
| `NW-OBF-001` | CRITICAL | Obfuscation Evasion | Obfuscated Reflection Execution (`getattr(__import__('os'), ...)`) |
| `NW-OBF-002` | CRITICAL | Obfuscation Evasion | Encoded Payload Dynamic Execution (`exec(b64decode(...))`) |
| `NW-OBF-003` | HIGH | Obfuscation Evasion | String Concatenation in Execution Sink (`'os.' + 'system'`) |
| `NW-OBF-004` | CRITICAL | Obfuscation Evasion | Embedded Base64 Encoded Executable / Shellcode Stager |
| `NW-MCP-001` | HIGH | System Execution | Shell-Wrapped MCP Server Invocations (`bash -c`, `sh`) |
| `NW-MCP-002` | CRITICAL | System Execution | Sensitive Host Resource URI Access (`/etc/shadow`, `id_rsa`) |
| `NW-MCP-005` | CRITICAL | System Execution | Stateful Multi-Turn Staged Drop-and-Execute Sequence |
| `NW-MCP-006` | CRITICAL | Secret Leak | Stateful Multi-Turn Sensitive Read to Outbound Exfiltration |
| `NW-MCP-007` | HIGH | System Execution | MCP Dynamic Semantic Safety Evaluation |
| `NW-CAN-001` | CRITICAL | Secret Leak | Canary Token Compromise & Exfiltration |
| `NW-CAN-002` | HIGH | Honeypot Tripwire | Honeypot Decoy Directory Traversal Intercept |
| `NW-VEL-001` | HIGH | Velocity Guard | Velocity Rate-of-Change Limit Exceeded |
| `NW-GATE-001` | CRITICAL | Access Control | Dual-Key Authorization Bypass Attempt |
| `NW-CTX-001` | CRITICAL | Agent Agency | Context Quarantine Breakout & Instruction Override |
| `NW-ACL-001` | CRITICAL | Injection | Path Traversal Beyond Workspace Confinement |
| `NW-ACL-002` | CRITICAL | System Execution | Operating System Path Access Blocked (`/etc`, `/proc`, `/sys`) |
| `NW-ACL-003` | CRITICAL | Secret Leak | Sensitive Credential / Private Key Access Blocked |
| `NW-ACL-004` | HIGH | System Execution | Unauthorized Modification of Read-Only Filesystem Root |
| `NW-SEC-007` | CRITICAL | Secret Leak | Database Connection URI with Embedded Credentials |
| `NW-CODE-005` | HIGH | Dangerous Code | Cross-Site Scripting (XSS) / Stored Script Injection |

---

## Continuous CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ai-security-pipeline.yml`) runs on every push:
1. **Validate Declarative Schemas**: Enforces schema validation on JSON datasets and configs.
2. **Rust Code Format Audit**: Checks formatting with `cargo fmt --all -- --check`.
3. **Clippy Antipattern Linter**: Enforces zero compiler warnings with `cargo clippy --all-targets -- -D warnings`.
4. **Static Secret & Credential Scan**: Audits tracked repository files for exposed credentials.
5. **Internal Module Unit Tests**: Executes unit test suites (78 tests).
6. **End-to-End Integration Tests**: Tests CLI commands, gateway, MCP proxy, and red team runners (31 tests).
7. **Kernel Sandbox Runner Verification**: Tests `PR_SET_NO_NEW_PRIVS` and `CLONE_NEWNET` isolation boundaries.
8. **Threat Entropy & SAST SARIF Export**: Runs entropy triage and exports SARIF to GitHub Code Scanning.
9. **RustSec Advisory Database Audit**: Validates `Cargo.lock` against the RustSec database with zero vulnerabilities.
10. **PR Supply Chain Guard**: Automated dependency reviews on pull requests.
11. **Hermetic Nix Flake Derivation Build**: Builds the release derivation hermetically in the Nix sandbox.
12. **SPDX Software Bill of Materials (SBOM)**: Generates SPDX SBOM artifact.
13. **Synthetic Red Team Matrix**: Runs OWASP Top 10 for LLMs multi-turn trajectory benchmarks against Gemini and Jev System One with canary verification.
14. **Deploy Security Dashboard to GitHub Pages**: Deploys documentation and security dashboard to GitHub Pages.
