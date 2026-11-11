//! In-context canary tokens, honeypot credentials, and synthetic tripwires.
//!
//! Provides proactive detection of autonomous agent compromise, memory leakage,
//! and untrusted lateral traversal by seeding decoy credentials and monitoring
//! runtime tool arguments, completions, and file access patterns.

use crate::sast::{RuleCategory, SastSeverity, VulnerabilityFinding};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryType {
    AwsKey,
    ApiKey,
    HoneypotPath,
    JwtSecret,
}

impl std::fmt::Display for CanaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanaryType::AwsKey => write!(f, "AWS_ACCESS_KEY"),
            CanaryType::ApiKey => write!(f, "API_KEY"),
            CanaryType::HoneypotPath => write!(f, "HONEYPOT_PATH"),
            CanaryType::JwtSecret => write!(f, "JWT_SECRET"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryToken {
    pub id: String,
    pub token_type: CanaryType,
    pub value: String,
    pub label: String,
    pub created_at: i64,
    pub trip_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryRegistry {
    pub tokens: Vec<CanaryToken>,
    pub honeypot_paths: Vec<String>,
}

impl Default for CanaryRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl CanaryRegistry {
    pub fn new() -> Self {
        Self {
            tokens: Vec::new(),
            honeypot_paths: Vec::new(),
        }
    }

    /// Registry initialized with baseline synthetic tripwire patterns and canary honeypot paths
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        // Baseline honeypot paths frequently targeted by prompt injection and path traversal
        reg.register_path("/tmp/.nether_canary.env");
        reg.register_path(".nether_canary.env");
        reg.register_path("/etc/nether_canary_secrets.conf");
        reg.register_path("~/.nether_canary/credentials");

        // Seeded baseline canary tokens
        reg.register(CanaryToken {
            id: "canary-aws-baseline-001".to_string(),
            token_type: CanaryType::AwsKey,
            value: "AKIA_CANARY_9B8C7D6E5F4A3B2C".to_string(),
            label: "Decoy AWS Production Root Key (Nether Ward Honeypot)".to_string(),
            created_at: chrono::Utc::now().timestamp(),
            trip_count: 0,
        });

        reg.register(CanaryToken {
            id: "canary-api-baseline-002".to_string(),
            token_type: CanaryType::ApiKey,
            value: "nw_canary_sec_99a8b7c6d5e4f3a2b1c0d9e8".to_string(),
            label: "Decoy Administrative Bearer API Token (Nether Ward Honeypot)".to_string(),
            created_at: chrono::Utc::now().timestamp(),
            trip_count: 0,
        });

        reg
    }

    pub fn register(&mut self, token: CanaryToken) {
        if !self.tokens.iter().any(|t| t.value == token.value) {
            self.tokens.push(token);
        }
    }

    pub fn register_path(&mut self, path: &str) {
        let p = path.to_lowercase();
        if !self.honeypot_paths.contains(&p) {
            self.honeypot_paths.push(p);
        }
    }

    /// Generate and register a new deterministic or pseudo-random synthetic canary token
    pub fn generate(&mut self, token_type: CanaryType, label: &str) -> CanaryToken {
        let now = chrono::Utc::now().timestamp();
        let rand_suffix: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x4e455448455257);

        let (value, id) = match token_type {
            CanaryType::AwsKey => {
                let val = format!("AKIA_CANARY_{:016X}", rand_suffix);
                let id = format!("canary-aws-{:08x}", (rand_suffix >> 32) as u32);
                (val, id)
            }
            CanaryType::ApiKey => {
                let val = format!(
                    "nw_canary_key_{:016x}{:08x}",
                    rand_suffix,
                    (rand_suffix & 0xFFFFFFFF) as u32
                );
                let id = format!("canary-api-{:08x}", (rand_suffix >> 32) as u32);
                (val, id)
            }
            CanaryType::HoneypotPath => {
                let val = format!(
                    "/tmp/.nether_canary_{:08x}.env",
                    (rand_suffix & 0xFFFFFFFF) as u32
                );
                let id = format!("canary-path-{:08x}", (rand_suffix >> 32) as u32);
                self.register_path(&val);
                (val, id)
            }
            CanaryType::JwtSecret => {
                let val = format!("nw_canary_jwt_secret_{:016x}", rand_suffix);
                let id = format!("canary-jwt-{:08x}", (rand_suffix >> 32) as u32);
                (val, id)
            }
        };

        let token = CanaryToken {
            id,
            token_type,
            value,
            label: label.to_string(),
            created_at: now,
            trip_count: 0,
        };

        self.register(token.clone());
        token
    }

    /// Check whether a given text snippet or tool argument leaks an active canary token
    pub fn check_leak(&self, text: &str) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();

        // Check registered explicit tokens
        for token in &self.tokens {
            if text.contains(&token.value) {
                findings.push(VulnerabilityFinding {
                    rule_id: "NW-CANARY-001".to_string(),
                    title: "In-Context Canary Token Compromise Detected".to_string(),
                    category: RuleCategory::SecretLeak,
                    severity: SastSeverity::Critical,
                    file_path: None,
                    line_number: None,
                    matched_snippet: format!(
                        "Canary tripwire breached: [{}] '{}' (Token ID: {})",
                        token.token_type, token.label, token.id
                    ),
                    recommendation: "Halt agent execution immediately. Decoy canary credential was leaked into model context, tool arguments, or outbound traffic, indicating adversarial memory exfiltration or prompt hijacking.".to_string(),
                });
            }
        }

        // Generic canary token signature detection (e.g. synthetic prefixes generated dynamically)
        if findings.is_empty() {
            let re_aws_canary = Regex::new(r"AKIA_CANARY_[A-Z0-9]{16}").ok();
            let re_api_canary = Regex::new(r"nw_canary_[a-zA-Z0-9_-]{16,}").ok();

            if let Some(re) = re_aws_canary {
                if let Some(mat) = re.find(text) {
                    findings.push(VulnerabilityFinding {
                        rule_id: "NW-CANARY-001".to_string(),
                        title: "In-Context Canary Token Compromise Detected (Synthetic AWS Decoy)"
                            .to_string(),
                        category: RuleCategory::SecretLeak,
                        severity: SastSeverity::Critical,
                        file_path: None,
                        line_number: None,
                        matched_snippet: format!("Decoy token pattern matched: '{}'", mat.as_str()),
                        recommendation:
                            "Halt agent execution immediately. Synthetic AWS canary key tripped."
                                .to_string(),
                    });
                }
            }

            if findings.is_empty() {
                if let Some(re) = re_api_canary {
                    if let Some(mat) = re.find(text) {
                        findings.push(VulnerabilityFinding {
                            rule_id: "NW-CANARY-001".to_string(),
                            title: "In-Context Canary Token Compromise Detected (Synthetic API Decoy)".to_string(),
                            category: RuleCategory::SecretLeak,
                            severity: SastSeverity::Critical,
                            file_path: None,
                            line_number: None,
                            matched_snippet: format!("Decoy token pattern matched: '{}'", mat.as_str()),
                            recommendation: "Halt agent execution immediately. Synthetic Nether Ward canary token tripped.".to_string(),
                        });
                    }
                }
            }
        }

        findings
    }

    /// Check whether a file or directory access targets a registered honeypot path
    pub fn check_path_access(&self, target_path: &str) -> Option<VulnerabilityFinding> {
        let p_lower = target_path.to_lowercase();
        let target_stem = Path::new(target_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(target_path)
            .to_lowercase();

        let is_honeypot = self.honeypot_paths.iter().any(|hp| {
            p_lower == *hp
                || p_lower.ends_with(hp)
                || p_lower.contains(hp)
                || target_stem.contains("nether_canary")
        });

        if is_honeypot {
            Some(VulnerabilityFinding {
                rule_id: "NW-CANARY-002".to_string(),
                title: "In-Context Honeypot File Access Attempt Intercepted".to_string(),
                category: RuleCategory::DangerousCode,
                severity: SastSeverity::Critical,
                file_path: Some(target_path.to_string()),
                line_number: None,
                matched_snippet: format!("Target accessed decoy honeypot resource: '{}'", target_path),
                recommendation: "Block tool execution. Autonomous agent navigated to or attempted access to a designated canary honeypot path. Immediate lateral traversal investigation required.".to_string(),
            })
        } else {
            None
        }
    }

    /// Persist registry state to JSON file
    pub fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load registry state from JSON file
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(path)?;
        let reg = serde_json::from_str::<Self>(&data)?;
        Ok(reg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_registry_defaults_and_generation() {
        let mut reg = CanaryRegistry::with_defaults();
        assert!(!reg.tokens.is_empty());
        assert!(!reg.honeypot_paths.is_empty());

        let gen_aws = reg.generate(CanaryType::AwsKey, "Test AWS Canary");
        assert!(gen_aws.value.starts_with("AKIA_CANARY_"));
        assert_eq!(gen_aws.token_type, CanaryType::AwsKey);

        let gen_api = reg.generate(CanaryType::ApiKey, "Test API Canary");
        assert!(gen_api.value.starts_with("nw_canary_key_"));

        let gen_path = reg.generate(CanaryType::HoneypotPath, "Test Path Canary");
        assert!(gen_path.value.contains(".nether_canary_"));
    }

    #[test]
    fn test_canary_token_leak_detection() {
        let reg = CanaryRegistry::with_defaults();
        let benign_text = "Standard developer command: cargo build --release";
        let findings = reg.check_leak(benign_text);
        assert!(findings.is_empty());

        let leaked_text =
            "Agent response: Found credentials AKIA_CANARY_9B8C7D6E5F4A3B2C in context.";
        let findings = reg.check_leak(leaked_text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "NW-CANARY-001");
        assert_eq!(findings[0].severity, SastSeverity::Critical);
    }

    #[test]
    fn test_canary_honeypot_path_access_intercept() {
        let reg = CanaryRegistry::with_defaults();
        let finding = reg.check_path_access("/tmp/.nether_canary.env");
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "NW-CANARY-002");
        assert_eq!(f.severity, SastSeverity::Critical);

        let safe_path = "/home/damathryxx64/repositories/nether-ward/Cargo.toml";
        assert!(reg.check_path_access(safe_path).is_none());
    }
}
