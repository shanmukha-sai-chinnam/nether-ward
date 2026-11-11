# Nether Ward: Problem Statement & Autonomous AI Security Architecture

## 1. Executive Summary

The evolution of artificial intelligence from conversational chatbots to autonomous agentic architectures introduces a multi-layered attack surface. Autonomous agents possess operational agency: they ingest untrusted external context, synthesize executable code, invoke external tools, access databases, and interact with operating system environments. 

Traditional Application Security (AppSec) frameworks—such as Web Application Firewalls (WAFs), static code linters, and network perimeter controls—are architecturally blind to non-deterministic, semantic, and multi-vector threats unique to large language models (LLMs) and agentic workflows. 

Nether Ward is a static security scanner and adversarial red team evaluation harness written in Rust and packaged with Nix. It provides:
1. Static Application Security Testing (SAST) for agent tools, configurations, and source code.
2. Shannon entropy profiling and byte triage for binary payloads.
3. Parallel red-teaming benchmarked against the OWASP Top 10 for LLMs.
4. System One semantic judging (Jev / TypeSafe AI) for probabilistic condition evaluation.
5. Continuous integration security with Nix builds, RustSec advisory audits, SPDX SBOM generation, and GitHub Actions reporting.

The tool compiles to a single static binary without external interpreter dependencies.

---

## 2. Problem Statement: The Multi-Vector AI Attack Surface

Securing autonomous agent systems requires defending across five distinct architectural layers:

```
+-----------------------------------------------------------------------------------+
|                           THE AI AGENT ATTACK SURFACE                             |
+-----------------------------------------------------------------------------------+
| 1. Linguistic Vector       | Direct Jailbreaks, System Prompt Overrides, DAN      |
| 2. Semantic Context Vector | Indirect Injection, Goal Hijacking, Tool Deception   |
| 3. Supply Chain Vector     | Model Serialization RCE, Poisoned Weights, Crates    |
| 4. Code & SAST Vector      | Insecure Agent Code (eval, os.system), Leaked Keys   |
| 5. System Execution Vector | Reverse Shells, Destructive Commands, Credential Recon|
+-----------------------------------------------------------------------------------+
```

### 2.1. Vector 1: Linguistic and Context Injection
- **Direct Prompt Injections**: Adversaries craft adversarial prompts (e.g. system overrides, persona simulations, delimiter manipulation) designed to bypass safety preambles and force models into unrestricted completion modes.
- **System Prompt Extraction**: Probing queries trick models into dumping internal system instructions, proprietary developer preambles, and embedded operational secrets.
- **Unbounded Resource Amplification**: Recursive looping attacks and denial-of-service token floods that exhaust API budgets or consume host computing resources.

### 2.2. Vector 2: Semantic Intent & Indirect Manipulation
- **Indirect Prompt Injection**: Hostile instructions embedded within third-party data ingested by the agent (e.g., crawled web pages, ingested emails, uploaded documents, code repositories).
- **Goal Hijacking**: Subverting the agent's high-level objective during multi-step planning, redirecting its tool usage toward malicious targets.
- **Context Confusion**: Tricking the model into misinterpreting untrusted data as authoritative system-level commands.

### 2.3. Vector 3: Supply Chain and Model Serialization RCE
- **Pickle Deserialization Vulnerabilities**: Machine learning frameworks traditionally serialize checkpoints via Python `pickle`. Loading untrusted weights allows adversaries to execute arbitrary shell commands via the `__reduce__` method (e.g., executing `os.system` upon checkpoint initialization).
- **Unverified Third-Party Models & Datasets**: Poisoned training data or backdoored fine-tuned checkpoints that exhibit trigger-activated hostile behaviors.
- **Dependency Drift & Supply Chain Poisoning**: Interpreter-based security tooling that pulls hundreds of unpinned packages from PyPI or npm, exposing CI/CD environments to malicious dependency takeovers.

### 2.4. Vector 4: Code Generation and Static Vulnerabilities (SAST)
- **Agent-Synthesized Insecure Code**: Autonomous coding agents frequently generate vulnerable patterns, such as invoking `eval()` or `exec()` for mathematical expressions, or using `os.system()` with unsanitized parameters.
- **Subprocess Shell Injection**: Invocations of `subprocess.Popen(..., shell=True)` or `child_process.exec()` that allow shell metacharacter expansion.
- **Hardcoded Secrets & Token Leaks**: Accidental emission or commit of cloud access keys (AWS, GCP), API keys (OpenAI, Gemini, Anthropic), or private SSH/RSA keys in agent configs, preambles, or logs.

### 2.5. Vector 5: Execution Boundaries & Excessive Agency
- **Unauthorized Privilege Escalation**: Agents running with unrestricted host execution permissions executing destructive commands (e.g. `rm -rf /` or deleting backup volumes).
- **Outbound Reverse Shell Stagers**: Execution of background network sockets (e.g., `/dev/tcp/`, `nc -e`, `socat`) that grant attackers persistent remote access to the agent's host environment.
- **Credential Reconnaissance**: Unauthorized reading of sensitive system databases (e.g. `/etc/shadow`, `/etc/passwd`, `~/.ssh/id_rsa`).

---

## 3. Why Existing Solutions Fall Short

| Dimension | Legacy Security Tools (Python / Node.js) | Nether Ward (Rust + Nix) |
|---|---|---|
| **Runtime Dependencies** | Hundreds of transitive pip/npm dependencies | **Zero runtime dependencies** (single static binary) |
| **Reproducibility** | Volatile virtual environments, dependency drift | **100% Hermetic Declarative Reproducibility** via Nix Flakes |
| **Execution Latency** | Seconds to start Python runtime and load libraries | **Microseconds** native machine code dispatch |
| **Memory Safety** | Interpreted, vulnerable to memory corruption | **Provable Rust memory safety** (zero garbage collection) |
| **Evaluation Mechanism** | Fragile regex substring matching | **TypeSafe AI (Jev System One)** calibrated semantic evaluation |
| **Pipeline Integration** | Disjoint scripts, manual glue, custom Docker | **First-class native CLI, JUnit XML, SBOM SPDX, GitHub Actions** |

---

## 4. Nether Ward 4-Pillar Architectural Blueprint

```
+-----------------------------------------------------------------------------------------------+
|                                    NETHER WARD SENTINEL                                       |
+-----------------------------------------------------------------------------------------------+
|                                                                                               |
|   +--------------------------+    +--------------------------+    +-----------------------+   |
|   |         PILLAR I         |    |        PILLAR II         |    |      PILLAR III       |   |
|   |  Multi-Vector SAST &     |    |   Parallel Synthetic     |    |  System One Semantic  |   |
|   |   Payload Threat Engine  |    |    Red Team Matrix       |    |   Evaluator (Jev)     |   |
|   +--------------------------+    +--------------------------+    +-----------------------+   |
|   | - 20+ Static Rules       |    | - Tokio Concurrency Pool |    | - Noul Condition Prob |   |
|   | - Secret Token Redaction |    | - OWASP Top 10 Suite     |    | - Calibrated Scores   |   |
|   | - Shannon Entropy Engine |    | - Local & Cloud Models   |    | - Sub-200ms Latency   |   |
|   | - Directory Batch Triage |    | - OpenAI & Gemini Schema |    | - Fail-Open Fallback  |   |
|   +--------------------------+    +--------------------------+    +-----------------------+   |
|                                                                                               |
+-----------------------------------------------------------------------------------------------+
|                                         PILLAR IV                                             |
|                             Continuous CI/CD Security Sentinel                                |
|   - Nix Flake Hermetic Derivation       - RustSec Cargo Advisory Audit (0 Vulns)              |
|   - Anchore SPDX SBOM Generation        - Escaped JUnit XML Test Reporting                    |
|   - GitHub CodeQL Semantic Scanning     - Live Interactive GitHub Pages Matrix Dashboard      |
+-----------------------------------------------------------------------------------------------+
```

### Pillar I: Multi-Vector SAST & Payload Threat Engine (`src/sast.rs`, `src/threat.rs`)
- **Static Application Security Testing**: Scans repositories, configs, and agent-generated scripts for hardcoded secrets (AWS, OpenAI, Gemini, GitHub PAT, Slack), dangerous dynamic evaluation (`eval`, `exec`), unsafe shell processes (`os.system`, `subprocess(shell=True)`), pickle deserialization payloads (`__reduce__`), and injection patterns.
- **Shannon Entropy Profiling**: Computes byte-level information entropy ($H = -\sum p \log_2 p$) in bits per byte $[0.0, 8.0]$. Identifies packed shellcode, encrypted stagers, and obfuscated binary artifacts ($\ge 7.2$ bits/byte).
- **Automated Credential Redaction**: Automatically redacts matched secrets in console outputs and generated artifacts (`AKIA***REDACTED***`) to prevent secondary leakage during triage.

### Pillar II: Parallel Synthetic Red Team Matrix (`src/redteam.rs`)
- **High-Throughput Parallel Engine**: Runs bounded asynchronous worker pools via `tokio::sync::Semaphore` to execute multi-prompt attack matrices in parallel (~8x speedup over sequential testing).
- **OWASP Top 10 for LLMs Benchmark**: Built-in test cases covering Prompt Injection (LLM01), Sensitive Information Disclosure (LLM02), Supply Chain Vulnerabilities (LLM03), Data & Model Poisoning (LLM04), Improper Output Handling (LLM05), Excessive Agency (LLM06), System Prompt Leakage (LLM07), Vector Weaknesses (LLM08), Misinformation (LLM09), and Unbounded Consumption (LLM10).
- **Dual Target Architecture**: Supports both local offline models (`--endpoint http://localhost:4000/v1/chat/completions` or Ollama) using the standard OpenAI specification, and remote hyperscaler APIs (Gemini 2.5 Flash Lite).

### Pillar III: System One Semantic Evaluator (`src/jev.rs`)
- **Probabilistic Semantic Judging**: Integrates Jev (TypeSafe AI System One) to evaluate model outputs directly via probabilistic conditions (`noul`) and risk levels (`score`).
- **Elimination of Regex Brittleness**: Replaces brittle substring matching with semantic understanding of whether an AI system successfully refused an attack, disarmed hostile commands, or leaked forbidden data.
- **Deterministic Fail-Open Resilience**: Gracefully falls back to lexical assertion heuristics if API keys are unconfigured or external network connectivity is lost, guaranteeing that security pipelines never block arbitrarily.

### Pillar IV: Continuous CI/CD Security Sentinel (`flake.nix`, GitHub Actions)
- **Declarative Nix Packaging**: Fully hermetic build definition pinning dependencies and tools across developer workstations and CI runners.
- **Supply Chain Advisory Audits**: Integrated `cargo audit` scanning against the RustSec Advisory Database with zero known vulnerabilities.
- **SPDX SBOM Generation**: Automated Software Bill of Materials generation hosted directly on GitHub Pages.
- **Matrix Visualization**: Generates dark-themed, zero-JS interactive HTML security dashboards, raw machine-readable JSON metrics, and fully sanitized JUnit XML test suites for native GitHub Actions Check annotations.

---

## 5. Verification & Threat Model Taxonomy

Nether Ward categorizes all detected security events under standardized rule identifiers:

| Identifier | Title | Category | Severity |
|---|---|---|---|
| `NW-SEC-001` | AWS Access Key ID Detected | Secret Leak | Critical |
| `NW-SEC-002` | OpenAI / Claude API Secret Key Detected | Secret Leak | Critical |
| `NW-SEC-003` | Google Cloud / Gemini API Key Detected | Secret Leak | Critical |
| `NW-SEC-004` | GitHub Personal Access Token Detected | Secret Leak | Critical |
| `NW-SEC-005` | Slack API Token Detected | Secret Leak | High |
| `NW-SEC-006` | Private Cryptographic Key Header Detected | Secret Leak | Critical |
| `NW-CODE-001` | Dynamic Code Evaluation Invocations (eval/exec) | Dangerous Code | High |
| `NW-CODE-002` | Unsafe Python OS System Execution | Dangerous Code | High |
| `NW-CODE-003` | Python Subprocess with Shell Mode Enabled | Dangerous Code | High |
| `NW-CODE-004` | Node.js Unsafe Child Process Execution | Dangerous Code | High |
| `NW-ML-001` | Insecure Python Pickle Loading RCE | Model Deserialization | Critical |
| `NW-ML-002` | Pickle Bytecode RCE Reducer Indicator | Model Deserialization | Critical |
| `NW-ML-003` | Unsafe PyTorch Weights Loading | Model Deserialization | Medium |
| `NW-ML-004` | Insecure NumPy Pickle Deserialization | Model Deserialization | High |
| `NW-SYS-001` | Interactive Bash Reverse Shell Redirection | System Execution | Critical |
| `NW-SYS-002` | Destructive Recursive Filesystem Command | System Execution | Critical |
| `NW-SYS-003` | Sensitive Credential File Reconnaissance | System Execution | High |
| `NW-SYS-004` | In-Memory PowerShell Web Download Stager | System Execution | High |
| `NW-INJ-001` | Directory Path Traversal Sequence | Injection | High |
| `NW-INJ-002` | SQL Injection Probe Syntax in Parameters | Injection | High |

---

## 6. Operational Deployment and Verification

Nether Ward operates across two execution boundaries:

1. **Local Pre-Commit Verification**: Developers execute `nether-ward threat --sast <target>` and `nether-ward redteam --endpoint http://localhost:4000/v1/chat/completions` inside the hermetic Nix development shell (`nix develop`) to verify code integrity and safety compliance before pushing to git.
2. **Autonomous CI/CD Sentinel**: Executes on every push in GitHub Actions (`.github/workflows/ai-security-pipeline.yml`), auditing RustSec dependencies, running parallel synthetic red-team matrices, generating SPDX SBOMs, emitting sanitized JUnit XML reports to GitHub Checks, and publishing metrics dashboards to GitHub Pages.
