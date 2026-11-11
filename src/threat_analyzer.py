"""Autonomous AI Threat Triage & Malware De-Obfuscator.

Analyzes suspicious scripts, quarantined binaries, and security audit logs using
entropy calculation, static feature extraction, and Gemini AI forensic reasoning.
"""

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

COLOR_GREEN = "\033[1;32m"
COLOR_YELLOW = "\033[1;33m"
COLOR_RED = "\033[1;31m"
COLOR_BLUE = "\033[1;34m"
COLOR_CYAN = "\033[1;36m"
COLOR_GRAY = "\033[0;90m"
COLOR_RESET = "\033[0m"


def load_env_key(key_name: str) -> Optional[str]:
    """Retrieve key from environment or .env file."""
    if key_name in os.environ and os.environ[key_name].strip():
        return os.environ[key_name].strip()

    env_paths = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent / ".env",
        Path.home() / "repositories" / ".env",
    ]
    for p in env_paths:
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith(f"{key_name}="):
                    val = line.split("=", 1)[1].strip().strip("\"'")
                    if val:
                        return val
    return None


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte content (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    total = len(data)
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract printable ASCII and UTF-8 strings from binary data."""
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    found = re.findall(pattern, data)
    return [s.decode("ascii", errors="ignore") for s in found[:100]]


def find_latest_quarantine_event(audit_log_path: Path) -> Optional[Dict]:
    """Find the most recent INFECTED event in ClamAV audit log."""
    if not audit_log_path.exists():
        return None
    last_infected = None
    with open(audit_log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("status") == "INFECTED":
                    last_infected = event
            except json.JSONDecodeError:
                continue
    return last_infected


def analyze_with_gemini(
    api_key: str,
    file_name: str,
    file_size: int,
    sha256: str,
    entropy: float,
    sample_text: str,
    virus_tag: Optional[str] = None,
) -> str:
    """Invoke Gemini API to produce a structured MITRE ATT&CK forensic analysis."""
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-flash-latest:generateContent?key={api_key}"
    )

    prompt = f"""You are a Lead Reverse Engineer and SOC Tier-3 Malware Analyst.
Analyze the following security sample and provide an evidence-based forensic report.

METADATA:
- File Name: {file_name}
- File Size: {file_size} bytes
- SHA-256: {sha256}
- Shannon Entropy: {entropy} (Entropy > 6.8 indicates packing or encryption)
- Antivirus Signature: {virus_tag or "Unknown / Unclassified"}

EXTRACTED CONTENT / STRINGS / SCRIPT SAMPLE:
```
{sample_text[:4000]}
```

Provide your analysis in the following strict markdown format:
# THREAT FORENSIC REPORT: {file_name}

## 1. Executive Summary & Verdict
- **Verdict**: [MALICIOUS / SUSPICIOUS / BENIGN / SECURITY TEST BENCH]
- **Threat Level**: [CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL]
- **Summary**: Concise explanation of what this payload does or attempts.

## 2. MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name | Evidence in Sample |
|---|---|---|---|
| ... | ... | ... | ... |

## 3. Behavioral Capabilities & Suspicious Indicators
- Detailed analysis of persistence, network callbacks, privilege escalation, obfuscation, or data exfiltration routines.

## 4. Indicators of Compromise (IOCs)
- **Hashes**: SHA-256: {sha256}
- **Network / URLs / IPs**: (if identified)
- **Registry / File Artifacts**: (if identified)

## 5. Recommended Remediation & Incident Response
1. Step-by-step remediation commands and security containment actions.
"""

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 2048,
        },
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", "No text generated.")
            return "No candidates returned by Gemini."
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        return f"Gemini API HTTP Error {e.code}: {err_msg}"
    except Exception as e:
        return f"Gemini API Request Failed: {e}"


def main():
    parser = argparse.ArgumentParser(description="Autonomous AI Threat Triage & Forensic Analyzer")
    parser.add_argument("file", nargs="?", default=None, type=Path, help="Path to suspicious file to analyze")
    parser.add_argument(
        "--latest-quarantine",
        action="store_true",
        help="Analyze the most recent infected payload from clamav-audit.jsonl",
    )
    parser.add_argument(
        "--audit-log",
        default=Path.home() / "repositories" / "clamav-audit.jsonl",
        type=Path,
        help="Path to ClamAV audit log",
    )
    parser.add_argument(
        "--output-dir",
        default=Path.cwd() / "reports",
        type=Path,
        help="Directory to save generated threat reports",
    )
    args = parser.parse_args()

    api_key = load_env_key("GEMINI_API_KEY")
    if not api_key:
        print(f"{COLOR_RED}Error: GEMINI_API_KEY not found in environment or .env file.{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)

    target_file: Optional[Path] = None
    virus_tag = None

    if args.latest_quarantine:
        event = find_latest_quarantine_event(args.audit_log)
        if not event:
            print(f"{COLOR_YELLOW}No quarantine events found in {args.audit_log}{COLOR_RESET}")
            sys.exit(0)
        q_path = event.get("quarantined_to") or event.get("file")
        if q_path and Path(q_path).exists():
            target_file = Path(q_path)
            virus_tag = event.get("virus_name")
        else:
            print(f"{COLOR_RED}Quarantined file not accessible at {q_path}{COLOR_RESET}")
            sys.exit(1)
    elif args.file:
        target_file = args.file.resolve()
        if not target_file.exists():
            print(f"{COLOR_RED}File not found: {target_file}{COLOR_RESET}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    print(f"{COLOR_BLUE}==>{COLOR_RESET} {COLOR_CYAN}Ingesting threat sample:{COLOR_RESET} {target_file}")
    try:
        raw_bytes = target_file.read_bytes()
    except PermissionError:
        # Quarantined files may have mode 000; attempt chmod read
        os.chmod(target_file, 0o400)
        raw_bytes = target_file.read_bytes()
        os.chmod(target_file, 0o000)

    size_bytes = len(raw_bytes)
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    entropy = calculate_entropy(raw_bytes)

    # Decode text or extract strings
    try:
        sample_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        sample_text = "\n".join(extract_strings(raw_bytes))

    print(f"  • Size: {size_bytes} bytes")
    print(f"  • SHA-256: {sha256}")
    print(f"  • Shannon Entropy: {entropy} {'(Packed/Encrypted)' if entropy > 6.8 else '(Normal/Plaintext)'}")
    if virus_tag:
        print(f"  • Antivirus Verdict: {COLOR_RED}{virus_tag}{COLOR_RESET}")

    print(f"{COLOR_BLUE}==>{COLOR_RESET} Querying Gemini Forensic Reasoner...")
    start_time = time.perf_counter()
    report = analyze_with_gemini(
        api_key=api_key,
        file_name=target_file.name,
        file_size=size_bytes,
        sha256=sha256,
        entropy=entropy,
        sample_text=sample_text,
        virus_tag=virus_tag,
    )
    latency_ms = (time.perf_counter() - start_time) * 1000.0
    print(f"{COLOR_GREEN}[OK]{COLOR_RESET} Forensic report generated in {latency_ms:.1f}ms\n")

    print(report)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    report_file = args.output_dir / f"threat_{time.strftime('%Y%m%d_%H%M%S')}_{target_file.name}.md"
    report_file.write_text(report, encoding="utf-8")
    print(f"\n{COLOR_CYAN}Saved forensic report to:{COLOR_RESET} {report_file}")


if __name__ == "__main__":
    main()
