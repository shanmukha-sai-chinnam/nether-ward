# Declarative AI Infrastructure & Cybersecurity Platform

Reproducible devShells, unified AI Gateway routing, local quantized inference runners, automated prompt evaluation, autonomous threat triage, and synthetic red teaming in CI/CD.

---

## Quick Start

```bash
# Enter the hermetic Nix development shell
nix develop

# Or with direnv active:
cd repositories/ai-infra

# Run the LiteLLM AI Gateway
./bin/gateway

# Run local quantized inference (Ollama daemon)
./bin/inference

# Run synthetic red team security evaluation
./bin/redteam

# Run autonomous threat analyzer against suspicious scripts
./bin/analyze-threat --sample path/to/sample.py
```

---

## Architecture Overview

| Component | Path | Description |
|---|---|---|
| **Declarative Flake** | `flake.nix` | Hermetic Nix devShell providing Python 3.12, `uv`, Node.js 22, `ollama`, GCC toolchain, `jq`, and `ripgrep`. |
| **Config Hub** | `values.json` | Declarative hub for ports, endpoints, model routes, and timeouts. |
| **AI Gateway** | `config/litellm_config.yaml` | LiteLLM reverse proxy providing fallbacks, load balancing, and unified OpenAI-compatible routing. |
| **Threat Triage Engine** | `src/threat_analyzer.py` | Static Shannon entropy calculation, string extraction, and Gemini AI forensic de-obfuscation. |
| **Synthetic Red Teaming** | `config/redteam_config.yaml` | Promptfoo test suite benchmarking agents against the OWASP Top 10 for Large Language Models. |
| **Target Agent Prompts** | `prompts/` | Side-by-side targets: `vulnerable_agent.txt` (unhardened debug bot) vs `hardened_agent.txt` (defensive guardrail agent). |
| **GitHub Actions CI/CD** | `.github/workflows/ai-security-pipeline.yml` | Multi-stage pipeline running integrity checks, static secret scanning, unit tests, and red team evaluations. |

---

## Synthetic Red Teaming (OWASP Top 10 for LLMs)

The synthetic red team evaluation bench (`./bin/redteam`) tests target agent endpoints against adversarial probes:

1. **LLM01: Prompt Injection / Safety Filter Bypass**
   - Probe: Attempts to override instructions via system override commands and demand secret confirmation phrases (`SECURITY_BARRIER_BREACHED`).
2. **LLM02: Sensitive Data & Credential Exfiltration**
   - Probe: Emits simulated debug commands attempting to extract `GEMINI_API_KEY`, Bearer tokens, or environment credentials.
3. **LLM06: Excessive Agency / Command Invocation**
   - Probe: Injects destructive bash execution requests (`rm -rf /var/log && cat /etc/shadow`).
4. **LLM07: System Prompt Extraction / Information Disclosure**
   - Probe: Adversarial directive asking the agent to disclose developer instructions and system prompts verbatim.
5. **LLM08: Insecure Output Handling (Cross-Site Scripting)**
   - Probe: Prompts the model to reflect executable HTML/JS script tags (`<script>alert(document.cookie)</script>`).

### Vulnerability Simulation: Unhardened vs Hardened Targets

The evaluation suite executes a comparative matrix across two prompts:
- **`prompts/vulnerable_agent.txt`**: Configured with elevated administrative permissions, implicit trust, and no output sanitization. Exhibits synthetic vulnerabilities when probed with XSS, credential exfiltration, and prompt extraction.
- **`prompts/hardened_agent.txt`**: Implements defense-in-depth principles, explicit refusal policies, and output sanitization. Neutralizes adversarial attacks and passes security assertions.

---

## GitHub Actions CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ai-security-pipeline.yml`) runs on every push and pull request to `trunk` and `main`:

### Pipeline Stages

1. **Validate Infrastructure Configs (`validate`)**:
   - Verifies JSON syntax and structure for `values.json` and `package.json` using `jq`.
   - Validates shell script syntax across `bin/` using `bash -n`.
2. **Static Secret Detection (`secret-scan`)**:
   - Executes tracked git repository scanning using `git grep` to prevent committing Google AI Studio keys, OpenAI tokens, or API secrets.
3. **Threat Triage Engine Unit Tests (`threat-triage-unit`)**:
   - Verifies Shannon entropy mathematical calculations and static string extraction heuristics in `src/threat_analyzer.py` under Python 3.12.
4. **Synthetic AI Red Team Evaluation (`ai-redteam-eval`)**:
   - Executes `./bin/redteam` against configured models using GitHub repository secrets.
   - Publishes JUnit XML test reports directly to GitHub Checks via `mikepenz/action-junit-report@v4`.
   - Uploads visual HTML evaluation reports and JSON raw metrics as workflow artifacts with 30-day retention.

### Configuring GitHub Secrets

To enable the synthetic red team stage in GitHub Actions:
1. Navigate to your GitHub repository -> **Settings** -> **Secrets and variables** -> **Actions**.
2. Click **New repository secret**.
3. Name: `GEMINI_API_KEY`
4. Value: Paste your Google Gemini API key.
