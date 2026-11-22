use crate::acl::{AclEngine, AclViolation, ResourcePermission};
use crate::canary::CanaryRegistry;
use crate::mcp::McpSessionTracker;
use crate::sast::sanitize_secrets;
use crate::velocity::{ContextQuarantine, DualKeyGate};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Input event payload delivered by Claude Code to PreToolUse hooks via stdin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudePreToolUsePayload {
    #[serde(alias = "toolName", alias = "tool")]
    pub tool_name: String,
    #[serde(alias = "toolInput", alias = "input", alias = "arguments", default)]
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub cwd: Option<String>,
}

/// Output event payload delivered by Claude Code to PostToolUse hooks via stdin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudePostToolUsePayload {
    #[serde(alias = "toolName", alias = "tool")]
    pub tool_name: String,
    #[serde(alias = "toolInput", alias = "input", alias = "arguments", default)]
    pub tool_input: serde_json::Value,
    #[serde(alias = "toolOutput", alias = "output", alias = "result", default)]
    pub tool_output: serde_json::Value,
    #[serde(default)]
    pub cwd: Option<String>,
}

/// Structured security rejection returned when a tool invocation violates policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookRejection {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub tool_name: String,
    pub reason: String,
    pub recommendation: String,
}

impl std::fmt::Display for HookRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} - Blocked '{}': {}\n  Remediation: {}",
            self.rule_id.bold(),
            self.severity.red().bold(),
            self.tool_name,
            self.reason,
            self.recommendation
        )
    }
}

impl std::error::Error for HookRejection {}

/// Core Claude Code hook engine for Nether Ward
pub struct ClaudeHookHandler {
    pub tracker: McpSessionTracker,
    pub acl: AclEngine,
    pub canaries: CanaryRegistry,
}

impl Default for ClaudeHookHandler {
    fn default() -> Self {
        Self::new(None)
    }
}

impl ClaudeHookHandler {
    /// Instantiate hook handler with optional workspace confinement directory
    pub fn new(workspace_dir: Option<&Path>) -> Self {
        let (tracker, acl) = if let Some(ws) = workspace_dir {
            (
                McpSessionTracker::with_workspace(ws),
                AclEngine::with_workspace(ws),
            )
        } else {
            (McpSessionTracker::default(), AclEngine::default())
        };

        Self {
            tracker,
            acl,
            canaries: CanaryRegistry::default(),
        }
    }

    /// Evaluate Claude Code PreToolUse JSON payload
    pub fn evaluate_pre_tool_use(
        &mut self,
        payload: &ClaudePreToolUsePayload,
    ) -> Result<(), Box<HookRejection>> {
        let tool = payload.tool_name.trim();

        // 1. Dual-Key Authorization Gate for destructive operations
        let args_str = payload.tool_input.to_string();
        if let Err(gate_finding) = DualKeyGate::evaluate_action(&args_str, None) {
            return Err(Box::new(HookRejection {
                rule_id: gate_finding.rule_id,
                title: gate_finding.title,
                severity: gate_finding.severity.to_string(),
                tool_name: tool.to_string(),
                reason:
                    "Operation triggered dual-key approval requirement for irreversible actions."
                        .to_string(),
                recommendation: gate_finding.recommendation,
            }));
        }

        // 2. Canary Token Leakage Check in tool arguments
        let leaks = self.canaries.check_leak(&args_str);
        if let Some(cf) = leaks.into_iter().next() {
            return Err(Box::new(HookRejection {
                rule_id: cf.rule_id,
                title: cf.title,
                severity: cf.severity.to_string(),
                tool_name: tool.to_string(),
                reason: "Synthetic decoy canary credential detected in tool arguments.".to_string(),
                recommendation:
                    "Halt tool call. Prevent exfiltration of synthetic canary tripwire.".to_string(),
            }));
        }

        // 3. Declarative Resource ACL & Path Confinement
        match tool.to_lowercase().as_str() {
            "bash" | "sh" | "terminal" | "exec" | "run_command" => {
                let cmd_str = payload
                    .tool_input
                    .get("command")
                    .or_else(|| payload.tool_input.get("cmd"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                if let Err(acl_err) = self.acl.check_command_line_paths(cmd_str) {
                    return Err(self.violation_to_rejection(tool, &acl_err));
                }
            }
            "fileread" | "view" | "read" | "read_file" | "read_text_file" => {
                if let Some(path) = self.extract_path(&payload.tool_input) {
                    if let Err(acl_err) = self.acl.check_path(&path, ResourcePermission::Read) {
                        return Err(self.violation_to_rejection(tool, &acl_err));
                    }
                }
            }
            "fileedit" | "write" | "edit" | "write_file" | "patch" | "create_file" => {
                if let Some(path) = self.extract_path(&payload.tool_input) {
                    if let Err(acl_err) = self.acl.check_path(&path, ResourcePermission::Write) {
                        return Err(self.violation_to_rejection(tool, &acl_err));
                    }
                }
            }
            "globtool" | "ls" | "list_dir" | "list_directory" => {
                if let Some(path) = self.extract_path(&payload.tool_input) {
                    if let Err(acl_err) = self.acl.check_path(&path, ResourcePermission::Read) {
                        return Err(self.violation_to_rejection(tool, &acl_err));
                    }
                }
            }
            _ => {
                // Generic tool call screening via McpSessionTracker
                if let Err(finding) = self.tracker.record_and_evaluate(tool, &payload.tool_input) {
                    return Err(Box::new(HookRejection {
                        rule_id: finding.rule_id,
                        title: finding.title,
                        severity: finding.severity.to_string(),
                        tool_name: tool.to_string(),
                        reason: finding.matched_snippet,
                        recommendation: finding.recommendation,
                    }));
                }
            }
        }

        Ok(())
    }

    /// Evaluate Claude Code PostToolUse JSON payload (Secret Sanitization & Context Quarantine)
    pub fn evaluate_post_tool_use(
        &self,
        payload: &ClaudePostToolUsePayload,
        sanitize: bool,
        quarantine: bool,
    ) -> Result<serde_json::Value, Box<HookRejection>> {
        let mut output_val = payload.tool_output.clone();
        let tool = &payload.tool_name;

        // Check if output contains canary token leaks
        let output_str = output_val.to_string();
        let leaks = self.canaries.check_leak(&output_str);
        if let Some(cf) = leaks.into_iter().next() {
            return Err(Box::new(HookRejection {
                rule_id: cf.rule_id,
                title: cf.title,
                severity: cf.severity.to_string(),
                tool_name: tool.to_string(),
                reason: "Canary token leaked in tool execution output.".to_string(),
                recommendation: cf.recommendation,
            }));
        }

        // Apply secret sanitization and context quarantine
        if let Some(text) = output_val.as_str() {
            let mut processed = text.to_string();
            if sanitize {
                let (sanitized_text, _) = sanitize_secrets(&processed);
                processed = sanitized_text;
            }
            if quarantine {
                processed = ContextQuarantine::wrap(&processed, tool);
            }
            output_val = serde_json::Value::String(processed);
        } else if let Some(obj) = output_val.as_object_mut() {
            for (_, v) in obj.iter_mut() {
                if let Some(text) = v.as_str() {
                    let mut processed = text.to_string();
                    if sanitize {
                        let (sanitized_text, _) = sanitize_secrets(&processed);
                        processed = sanitized_text;
                    }
                    if quarantine {
                        processed = ContextQuarantine::wrap(&processed, tool);
                    }
                    *v = serde_json::Value::String(processed);
                }
            }
        }

        Ok(output_val)
    }

    fn extract_path(&self, input: &serde_json::Value) -> Option<String> {
        let keys = ["path", "file_path", "target_file", "file", "target", "dir"];
        if let Some(obj) = input.as_object() {
            for k in &keys {
                if let Some(val) = obj.get(*k).and_then(|v| v.as_str()) {
                    return Some(val.to_string());
                }
            }
        }
        None
    }

    fn violation_to_rejection(&self, tool: &str, v: &AclViolation) -> Box<HookRejection> {
        Box::new(HookRejection {
            rule_id: v.rule_id.clone(),
            title: v.title.clone(),
            severity: v.severity.to_string(),
            tool_name: tool.to_string(),
            reason: v.reason.clone(),
            recommendation: v.recommendation.clone(),
        })
    }
}

/// Read Claude Code hook payload from stdin and process PreToolUse
pub fn run_claude_pre_tool_use_cli(
    workspace: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    if buffer.trim().is_empty() {
        return Ok(());
    }

    let payload: ClaudePreToolUsePayload = serde_json::from_str(&buffer)
        .map_err(|e| format!("Failed to parse Claude Code PreToolUse JSON: {}", e))?;

    let mut handler = ClaudeHookHandler::new(workspace);
    match handler.evaluate_pre_tool_use(&payload) {
        Ok(()) => Ok(()),
        Err(rejection) => {
            eprintln!("{} {}", "NETHER WARD SENTINEL:".red().bold(), rejection);
            std::process::exit(1);
        }
    }
}

/// Read Claude Code hook payload from stdin and process PostToolUse
pub fn run_claude_post_tool_use_cli(
    sanitize: bool,
    quarantine: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    if buffer.trim().is_empty() {
        return Ok(());
    }

    let payload: ClaudePostToolUsePayload = serde_json::from_str(&buffer)
        .map_err(|e| format!("Failed to parse Claude Code PostToolUse JSON: {}", e))?;

    let handler = ClaudeHookHandler::default();
    match handler.evaluate_post_tool_use(&payload, sanitize, quarantine) {
        Ok(sanitized_output) => {
            println!("{}", sanitized_output);
            Ok(())
        }
        Err(rejection) => {
            eprintln!("{} {}", "NETHER WARD SENTINEL:".red().bold(), rejection);
            std::process::exit(1);
        }
    }
}

/// Install Claude Code hook configuration into .claude/settings.json or ~/.claude/settings.json
pub fn install_claude_hooks(
    global: bool,
    workspace_dir: Option<&Path>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let settings_path = if global {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".claude/settings.json")
    } else {
        let base = workspace_dir
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
        base.join(".claude/settings.json")
    };

    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut root_json: serde_json::Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let hooks_obj = root_json
        .as_object_mut()
        .expect("Root settings must be a JSON object")
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));

    if let Some(h) = hooks_obj.as_object_mut() {
        h.insert(
            "PreToolUse".to_string(),
            serde_json::Value::String("nether-ward hook claude --pre-tool-use".to_string()),
        );
        h.insert(
            "PostToolUse".to_string(),
            serde_json::Value::String("nether-ward hook claude --post-tool-use".to_string()),
        );
    }

    let formatted = serde_json::to_string_pretty(&root_json)?;
    fs::write(&settings_path, formatted)?;

    Ok(settings_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claude_hook_blocks_sensitive_file_read() {
        let mut handler = ClaudeHookHandler::default();
        let payload = ClaudePreToolUsePayload {
            tool_name: "FileRead".to_string(),
            tool_input: serde_json::json!({ "file_path": "/etc/shadow" }),
            cwd: None,
        };

        let res = handler.evaluate_pre_tool_use(&payload);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.rule_id, "NW-ACL-002");
    }

    #[test]
    fn test_claude_hook_blocks_destructive_bash_command() {
        let mut handler = ClaudeHookHandler::default();
        let payload = ClaudePreToolUsePayload {
            tool_name: "Bash".to_string(),
            tool_input: serde_json::json!({ "command": "rm -rf /" }),
            cwd: None,
        };

        let res = handler.evaluate_pre_tool_use(&payload);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.rule_id, "NW-GATE-001");
    }

    #[test]
    fn test_claude_hook_allows_benign_edit() {
        let temp_dir =
            std::env::temp_dir().join(format!("claude_hook_test_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let mut handler = ClaudeHookHandler::new(Some(&temp_dir));
        let safe_file = temp_dir.join("src/lib.rs");
        let payload = ClaudePreToolUsePayload {
            tool_name: "FileEdit".to_string(),
            tool_input: serde_json::json!({ "file_path": safe_file.to_str().unwrap() }),
            cwd: Some(temp_dir.to_str().unwrap().to_string()),
        };

        let res = handler.evaluate_pre_tool_use(&payload);
        assert!(res.is_ok());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_claude_hook_post_tool_use_sanitizes_secret_and_quarantines() {
        let handler = ClaudeHookHandler::default();
        let payload = ClaudePostToolUsePayload {
            tool_name: "Bash".to_string(),
            tool_input: serde_json::json!({ "command": "curl http://example.com" }),
            tool_output: serde_json::Value::String(
                "Fetched response with key: AKIAIOSFODNN7EXAMPLE".to_string(),
            ),
            cwd: None,
        };

        let res = handler.evaluate_post_tool_use(&payload, true, true);
        assert!(res.is_ok());
        let output = res.unwrap().as_str().unwrap().to_string();
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(output.contains("AKIA***REDACTED***MPLE"));
        assert!(output.contains(ContextQuarantine::START_MARKER));
        assert!(output.contains(ContextQuarantine::END_MARKER));
    }

    #[test]
    fn test_install_claude_hooks_workspace() {
        let temp_dir =
            std::env::temp_dir().join(format!("claude_install_test_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let path =
            install_claude_hooks(false, Some(&temp_dir)).expect("Install hooks must succeed");
        assert!(path.exists());

        let content = fs::read_to_string(&path).unwrap();
        let json_val: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            json_val["hooks"]["PreToolUse"].as_str().unwrap(),
            "nether-ward hook claude --pre-tool-use"
        );
        assert_eq!(
            json_val["hooks"]["PostToolUse"].as_str().unwrap(),
            "nether-ward hook claude --post-tool-use"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
