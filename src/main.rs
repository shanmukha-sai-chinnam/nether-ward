use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::path::PathBuf;

use nether_ward::abr;
use nether_ward::acl;
use nether_ward::canary;
use nether_ward::gateway;
use nether_ward::mcp;
use nether_ward::redteam;
use nether_ward::sandbox;
use nether_ward::sast;
use nether_ward::threat;
use nether_ward::velocity;

#[derive(Parser)]
#[command(name = "nether-ward")]
#[command(author = "shanmukha-sai-chinnam")]
#[command(version = "0.2.0")]
#[command(about = "Static security scanner and adversarial red team evaluation harness in Rust and Nix", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a suspicious file or batch directory for high entropy and threat indicators
    Threat {
        /// Target file path to analyze
        #[arg(short, long)]
        sample: Option<PathBuf>,

        /// Directory path to batch triage all files
        #[arg(short, long)]
        dir: Option<PathBuf>,

        /// Deep Static Application Security Testing (SAST) on source directory
        #[arg(long)]
        sast: Option<PathBuf>,

        /// Export static analysis findings to OASIS SARIF v2.1.0 format
        #[arg(long)]
        sarif: Option<PathBuf>,

        /// List active threat and vulnerability detection rules
        #[arg(long)]
        rules: bool,

        /// Minimum printable string length
        #[arg(long, default_value_t = 4)]
        min_length: usize,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Run the AI security gateway reverse proxy (OpenAI compatible)
    Gateway {
        /// Port to listen on
        #[arg(short, long, default_value_t = 4000)]
        port: u16,

        /// Default upstream model target
        #[arg(short, long)]
        model: Option<String>,

        /// Upstream OpenAI-compatible API base URL (e.g. http://localhost:11434/v1)
        #[arg(long)]
        upstream: Option<String>,

        /// Enable in-flight secret sanitization and masking
        #[arg(long)]
        sanitize: bool,

        /// Enable Jev System One semantic safety verification on incoming requests
        #[arg(long)]
        semantic_firewall: bool,

        /// Enable automatic context quarantine boundary wrapping for untrusted tool outputs
        #[arg(long)]
        quarantine: bool,
    },

    /// Audit Model Context Protocol (MCP) servers or run bidirectional stdio security proxy
    Mcp {
        /// Path to MCP configuration file (e.g. .agents/mcp_config.json)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// JSON-RPC message payload string to inspect
        #[arg(short, long)]
        inspect: Option<String>,

        /// Enable in-flight secret sanitization and masking
        #[arg(long)]
        sanitize: bool,

        /// Enable Jev System One semantic verification during proxy execution
        #[arg(long)]
        semantic: bool,

        /// Enable automatic context quarantine boundary wrapping for tool outputs
        #[arg(long)]
        quarantine: bool,

        /// Run transparent bidirectional stdio security proxy wrapping target command
        #[arg(long)]
        proxy: bool,

        /// Target command and arguments for proxy execution
        #[arg(last = true)]
        target_command: Vec<String>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Run the synthetic AI red team security evaluation matrix
    Redteam {
        /// Path to red team configuration YAML
        #[arg(short, long, default_value = "config/redteam_config.yaml")]
        config: String,

        /// Override evaluation model target
        #[arg(short, long)]
        model: Option<String>,

        /// Worker concurrency limit for parallel probe execution
        #[arg(long, default_value_t = 5)]
        concurrency: usize,

        /// Optional external test dataset path (.jsonl, .json, .yaml)
        #[arg(short, long)]
        dataset: Option<PathBuf>,

        /// Optional local model endpoint (e.g. http://localhost:4000/v1/chat/completions)
        #[arg(long)]
        endpoint: Option<String>,

        /// Semantic AI judge to evaluate responses ('jev' or 'lexical')
        #[arg(long)]
        judge: Option<String>,

        /// Enable autonomous adversarial mutation fuzzing
        #[arg(long)]
        fuzz: bool,

        /// Regenerate HTML dashboard from existing JSON report
        #[arg(long)]
        render_from: Option<PathBuf>,
    },

    /// Check connection status of local Ollama quantized inference engine
    Inference {
        /// Ollama daemon base URL
        #[arg(short, long, default_value = "http://localhost:11434")]
        url: String,
    },

    /// Execute a tool or process inside an isolated ephemeral Linux kernel security sandbox
    Sandbox {
        /// Target workspace directory (defaults to current directory)
        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// Isolate and drop network access (CLONE_NEWNET)
        #[arg(long)]
        no_network: bool,

        /// Mount host filesystem root as read-only
        #[arg(long)]
        read_only_root: bool,

        /// Execution timeout in seconds
        #[arg(short, long, default_value_t = 30)]
        timeout: u64,

        /// Dry-run mode: prints sandbox security policy without executing
        #[arg(long)]
        dry_run: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// Command and arguments to execute inside sandbox
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Manage in-context canary tokens, honeypots, and active tripwires
    Canary {
        /// Action to perform: 'generate', 'list', 'scan', or 'plant'
        #[arg(default_value = "list")]
        action: String,

        /// Canary type to generate: 'aws', 'api', 'path', 'jwt'
        #[arg(short = 't', long, default_value = "api")]
        canary_type: String,

        /// Custom label for generated canary token
        #[arg(short, long)]
        label: Option<String>,

        /// Target string or payload to scan for canary leakage
        #[arg(short, long)]
        payload: Option<String>,

        /// Target directory for planting honeypot decoys
        #[arg(short, long)]
        dir: Option<String>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Evaluate operational velocity limits and dual-key authorization gates
    Gate {
        /// Command or tool argument string to evaluate against irreversible operations
        #[arg(short, long)]
        command: Option<String>,

        /// Dual-key cryptographic authorization token
        #[arg(short, long)]
        token: Option<String>,

        /// Generate an operator dual-key authorization token
        #[arg(long)]
        generate_token: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Run Automated Behavioral Regression (ABR) evaluation comparing baseline and candidate prompts/policies
    Abr {
        /// Baseline configuration or prompt file path
        #[arg(short, long)]
        baseline: PathBuf,

        /// Candidate configuration or prompt file path
        #[arg(short, long)]
        candidate: PathBuf,

        /// Maximum allowed risk score increase (default: 0.05)
        #[arg(long)]
        max_risk_delta: Option<f64>,

        /// Optional maximum allowed candidate risk ceiling (0.0 to 1.0)
        #[arg(long)]
        max_risk_ceiling: Option<f64>,

        /// Export results as JSON
        #[arg(long)]
        json: bool,

        /// Output Markdown evaluation table to GitHub step summary path
        #[arg(long)]
        step_summary: Option<PathBuf>,
    },

    /// Enforce Resource Access Control Lists (ACL) and path confinement
    Acl {
        /// Action to perform: 'check', 'audit', or 'rules'
        #[arg(default_value = "check")]
        action: String,

        /// Path to evaluate against ACL rules
        #[arg(short, long)]
        path: Option<String>,

        /// Resource permission to check: 'read', 'write', 'execute', 'any'
        #[arg(long, default_value = "read")]
        perm: String,

        /// Confine evaluation strictly to designated workspace root
        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// Directory to recursively audit for escaping symlinks or forbidden files
        #[arg(short, long)]
        dir: Option<PathBuf>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Threat {
            sample,
            dir,
            sast,
            sarif,
            rules,
            min_length: _,
            json,
        } => {
            if rules {
                sast::print_rules();
                return Ok(());
            }

            if let Some(sast_path) = sast {
                if !sast_path.exists() {
                    eprintln!(
                        "{}: Target path '{}' does not exist.",
                        "Error".red().bold(),
                        sast_path.display()
                    );
                    std::process::exit(1);
                }

                let report = if sast_path.is_dir() {
                    sast::scan_directory(&sast_path)?
                } else {
                    let findings = sast::scan_file(&sast_path)?;
                    let critical = findings
                        .iter()
                        .filter(|f| f.severity == sast::SastSeverity::Critical)
                        .count();
                    let high = findings
                        .iter()
                        .filter(|f| f.severity == sast::SastSeverity::High)
                        .count();
                    let medium = findings
                        .iter()
                        .filter(|f| f.severity == sast::SastSeverity::Medium)
                        .count();
                    let low = findings
                        .iter()
                        .filter(|f| f.severity == sast::SastSeverity::Low)
                        .count();
                    let info = findings
                        .iter()
                        .filter(|f| f.severity == sast::SastSeverity::Info)
                        .count();
                    sast::SastReport {
                        total_files_scanned: 1,
                        total_findings: findings.len(),
                        critical_count: critical,
                        high_count: high,
                        medium_count: medium,
                        low_count: low,
                        info_count: info,
                        duration_ms: 0,
                        findings,
                    }
                };

                if let Some(ref sarif_path) = sarif {
                    sast::export_sarif(&report, sarif_path)?;
                    println!(
                        "Exported SARIF v2.1.0 security report: {}",
                        sarif_path.display().to_string().green()
                    );
                }

                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    sast::print_sast_report(&report, sast_path.to_str().unwrap_or("."));
                }

                if report.critical_count > 0 || report.high_count > 0 {
                    std::process::exit(2);
                }
            } else if let Some(dir_path) = dir {
                if !dir_path.exists() || !dir_path.is_dir() {
                    eprintln!(
                        "{}: Target directory '{}' does not exist or is not a directory.",
                        "Error".red().bold(),
                        dir_path.display()
                    );
                    std::process::exit(1);
                }

                let report = threat::scan_directory(&dir_path)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    threat::print_batch_report(&report, dir_path.to_str().unwrap_or("."));
                }

                if report.critical_files > 0 || report.high_files > 0 {
                    std::process::exit(2);
                }
            } else if let Some(sample_path) = sample {
                if !sample_path.exists() {
                    eprintln!(
                        "{}: Target sample '{}' does not exist.",
                        "Error".red().bold(),
                        sample_path.display()
                    );
                    std::process::exit(1);
                }

                let data = fs::read(&sample_path)?;
                let report = threat::analyze_payload(&data);

                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    threat::print_report(&report, sample_path.to_str());
                }

                if report.severity == threat::ThreatSeverity::Critical
                    || report.severity == threat::ThreatSeverity::High
                {
                    std::process::exit(2);
                }
            } else {
                eprintln!(
                    "{}: Please provide --sast <dir>, --dir <dir>, --sample <file>, or --rules.",
                    "Error".red().bold()
                );
                std::process::exit(1);
            }
        }

        Commands::Gateway {
            port,
            model,
            upstream,
            sanitize,
            semantic_firewall,
            quarantine,
        } => {
            gateway::run_gateway(
                port,
                model,
                upstream,
                sanitize,
                semantic_firewall,
                quarantine,
            )
            .await?;
        }

        Commands::Mcp {
            config,
            inspect,
            sanitize,
            semantic,
            quarantine,
            proxy,
            target_command,
            json,
        } => {
            if proxy {
                if target_command.is_empty() {
                    eprintln!(
                        "{}: Proxy mode requires a target command. Syntax: nether-ward mcp --proxy [--sanitize] [--semantic] [--quarantine] -- <command> [args...]",
                        "Error".red().bold()
                    );
                    std::process::exit(1);
                }
                let cmd = &target_command[0];
                let args = &target_command[1..];
                mcp::run_mcp_proxy(cmd, args, sanitize, semantic, quarantine).await?;
            } else if let Some(config_path) = config {
                if !config_path.exists() {
                    eprintln!(
                        "{}: Configuration file '{}' does not exist.",
                        "Error".red().bold(),
                        config_path.display()
                    );
                    std::process::exit(1);
                }
                let report = mcp::audit_mcp_config(&config_path)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    mcp::print_mcp_report(&report, config_path.to_str().unwrap_or("."));
                }
                if !report.clean {
                    std::process::exit(2);
                }
            } else if let Some(payload) = inspect {
                match mcp::inspect_mcp_json_rpc(&payload) {
                    Ok(()) => {
                        if json {
                            println!(r#"{{"status":"clean","inspected":true}}"#);
                        } else {
                            println!(
                                "{}",
                                "MCP JSON-RPC Payload: Clean (No threat indicators detected)"
                                    .green()
                                    .bold()
                            );
                        }
                    }
                    Err(finding) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&finding)?);
                        } else {
                            eprintln!(
                                "{}: MCP JSON-RPC security violation detected!",
                                "BLOCKED".red().bold()
                            );
                            eprintln!("  Rule:    {} [{}]", finding.title, finding.rule_id);
                            eprintln!("  Snippet: {}", finding.matched_snippet);
                            eprintln!("  Fix:     {}", finding.recommendation);
                        }
                        std::process::exit(2);
                    }
                }
            } else {
                eprintln!(
                    "{}: Please specify either --config <path> or --inspect <json_rpc>.",
                    "Error".red().bold()
                );
                std::process::exit(1);
            }
        }

        Commands::Redteam {
            config,
            model,
            concurrency,
            dataset,
            endpoint,
            judge,
            fuzz,
            render_from,
        } => {
            if let Some(json_path) = render_from {
                println!(
                    "==> Rendering HTML dashboard from JSON report: {}",
                    json_path.display()
                );
                redteam::render_html_from_json(
                    json_path.to_str().unwrap_or("reports/redteam_report.json"),
                    "reports/redteam_report.html",
                )?;
                println!(
                    "{}",
                    "Successfully generated reports/redteam_report.html"
                        .green()
                        .bold()
                );
            } else {
                let all_passed = redteam::run_redteam(
                    &config,
                    model.as_deref(),
                    concurrency,
                    dataset.as_deref(),
                    endpoint.as_deref(),
                    judge.as_deref(),
                    fuzz,
                )
                .await?;
                if !all_passed {
                    // Exit with code 100 to signal caught vulnerabilities/assertion failures
                    std::process::exit(100);
                }
            }
        }

        Commands::Inference { url } => {
            println!(
                "{}",
                "================================================================================"
                    .blue()
            );
            println!(
                "{}",
                "            NETHER WARD: LOCAL INFERENCE ENGINE CHECK                          "
                    .bold()
                    .cyan()
            );
            println!(
                "{}",
                "================================================================================"
                    .blue()
            );
            println!("{:<24}: {}", "Ollama Daemon URL".bold(), url);

            let client = reqwest::Client::new();
            match client.get(format!("{url}/api/version")).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let version_json: serde_json::Value = resp.json().await.unwrap_or_default();
                    let ver = version_json["version"].as_str().unwrap_or("unknown");
                    println!(
                        "{:<24}: {}",
                        "Ollama Status".bold(),
                        "ONLINE (Connected)".green().bold()
                    );
                    println!("{:<24}: {}", "Version".bold(), ver);

                    // Check models
                    if let Ok(tags_resp) = client.get(format!("{url}/api/tags")).send().await {
                        let tags_json: serde_json::Value =
                            tags_resp.json().await.unwrap_or_default();
                        if let Some(models) = tags_json["models"].as_array() {
                            println!(
                                "{:<24}: {} models loaded",
                                "Local Models".bold(),
                                models.len()
                            );
                            for m in models {
                                if let Some(name) = m["name"].as_str() {
                                    println!("  - {}", name.cyan());
                                }
                            }
                        }
                    }
                }
                _ => {
                    println!(
                        "{:<24}: {}",
                        "Ollama Status".bold(),
                        "OFFLINE (Not Running)".yellow().bold()
                    );
                    println!("\nTo launch local inference daemon:\n  ollama serve");
                }
            }
            println!(
                "{}",
                "================================================================================"
                    .blue()
            );
        }

        Commands::Sandbox {
            workspace,
            no_network,
            read_only_root,
            timeout,
            dry_run,
            json,
            command,
        } => {
            if command.is_empty() {
                eprintln!(
                    "{}: No command specified for sandboxed execution.",
                    "Error".red().bold()
                );
                std::process::exit(1);
            }

            let ws = workspace
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let cfg = sandbox::SandboxConfig {
                workspace: ws,
                no_network,
                read_only_root,
                timeout_secs: timeout,
                dry_run,
                capture_output: json,
            };

            let prog = &command[0];
            let args = &command[1..];

            match sandbox::run_sandboxed(&cfg, prog, args).await {
                Ok(report) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else if !dry_run {
                        eprintln!(
                            "{} Completed in {}ms via engine '{}' (Exit Code: {:?})",
                            "NETHER WARD SANDBOX:".green().bold(),
                            report.duration_ms,
                            report.engine,
                            report.exit_code
                        );
                    }
                    if let Some(code) = report.exit_code {
                        if code != 0 {
                            std::process::exit(code);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{} Sandbox execution failed: {e}", "Error:".red().bold());
                    std::process::exit(1);
                }
            }
        }
        Commands::Canary {
            action,
            canary_type,
            label,
            payload,
            dir,
            json,
        } => {
            let mut reg = canary::CanaryRegistry::default();
            match action.as_str() {
                "plant" => {
                    let target_dir = PathBuf::from(dir.unwrap_or_else(|| ".".to_string()));
                    let planted = reg.plant_honeypots(&target_dir)?;
                    if json {
                        let entries: Vec<_> = planted
                            .iter()
                            .map(|(p, t)| serde_json::json!({ "path": p, "token": t }))
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&entries)?);
                    } else {
                        eprintln!(
                            "{} Planted {} decoy canary honeypots in '{}':",
                            "NETHER WARD CANARY:".green().bold(),
                            planted.len(),
                            target_dir.display()
                        );
                        for (path, token) in &planted {
                            println!(
                                "  - [{}] {} -> Decoy File: {}",
                                token.token_type,
                                token.value.yellow().bold(),
                                path.cyan()
                            );
                        }
                    }
                }
                "generate" => {
                    let c_type = match canary_type.to_lowercase().as_str() {
                        "aws" => canary::CanaryType::AwsKey,
                        "path" => canary::CanaryType::HoneypotPath,
                        "jwt" => canary::CanaryType::JwtSecret,
                        _ => canary::CanaryType::ApiKey,
                    };
                    let lbl = label
                        .as_deref()
                        .unwrap_or("Nether Ward In-Context Tripwire");
                    let token = reg.generate(c_type, lbl);

                    if json {
                        println!("{}", serde_json::to_string_pretty(&token)?);
                    } else {
                        eprintln!(
                            "{} Generated synthetic canary token:",
                            "NETHER WARD CANARY:".green().bold()
                        );
                        println!("  ID:         {}", token.id);
                        println!("  Type:       {}", token.token_type);
                        println!("  Value:      {}", token.value.yellow().bold());
                        println!("  Label:      {}", token.label);
                        println!("  Created At: {}", token.created_at);
                    }
                }
                "scan" => {
                    let target = payload.unwrap_or_default();
                    let findings = reg.check_leak(&target);
                    if json {
                        println!("{}", serde_json::to_string_pretty(&findings)?);
                    } else if findings.is_empty() {
                        eprintln!(
                            "{} No canary token compromise or honeypot tripwire detected.",
                            "CLEAN:".green().bold()
                        );
                    } else {
                        for f in findings {
                            eprintln!(
                                "{} [{}] {}",
                                "CANARY BREACH:".red().bold(),
                                f.rule_id,
                                f.title
                            );
                            eprintln!("  Snippet:        {}", f.matched_snippet);
                            eprintln!("  Recommendation: {}", f.recommendation);
                        }
                        std::process::exit(1);
                    }
                }
                _ => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&reg)?);
                    } else {
                        eprintln!(
                            "{} Active Canary Tokens ({} registered):",
                            "NETHER WARD CANARY:".cyan().bold(),
                            reg.tokens.len()
                        );
                        for t in &reg.tokens {
                            println!("  - [{}] {} (ID: {})", t.token_type, t.value.yellow(), t.id);
                        }
                        eprintln!(
                            "\n{} Active Honeypot Decoy Paths ({} registered):",
                            "NETHER WARD HONEYPOTS:".cyan().bold(),
                            reg.honeypot_paths.len()
                        );
                        for p in &reg.honeypot_paths {
                            println!("  - {}", p.yellow());
                        }
                    }
                }
            }
        }
        Commands::Gate {
            command,
            token,
            generate_token,
            json,
        } => {
            if generate_token {
                let tok = velocity::DualKeyGate::generate_gate_token("operator-action");
                if json {
                    println!("{}", serde_json::json!({ "token": tok }));
                } else {
                    eprintln!(
                        "{} Ephemeral Dual-Key Authorization Token:",
                        "NETHER WARD GATE:".green().bold()
                    );
                    println!("  Token:   {}", tok.yellow().bold());
                    println!("  Expires: 15 minutes");
                }
                return Ok(());
            }

            if let Some(cmd) = command {
                match velocity::DualKeyGate::evaluate_action(&cmd, token.as_deref()) {
                    Ok(()) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::json!({ "status": "approved", "command": cmd })
                            );
                        } else {
                            eprintln!(
                                "{} Command cleared by Dual-Key Gate.",
                                "GATE APPROVED:".green().bold()
                            );
                        }
                    }
                    Err(finding) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&finding)?);
                        } else {
                            eprintln!(
                                "{} [{}] {}",
                                "GATE BLOCKED:".red().bold(),
                                finding.rule_id,
                                finding.title
                            );
                            eprintln!("  Command:        {}", cmd);
                            eprintln!("  Recommendation: {}", finding.recommendation);
                        }
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!(
                    "{}: Specify --command <cmd> to evaluate or --generate-token to issue dual-key token.",
                    "Error".red().bold()
                );
                std::process::exit(1);
            }
        }

        Commands::Abr {
            baseline,
            candidate,
            max_risk_delta,
            max_risk_ceiling,
            json,
            step_summary,
        } => {
            abr::run_abr_cli(
                baseline,
                candidate,
                max_risk_delta,
                max_risk_ceiling,
                json,
                step_summary,
            )
            .await?;
        }

        Commands::Acl {
            action,
            path,
            perm,
            workspace,
            dir,
            json,
        } => {
            let acl_engine = if let Some(ws) = workspace {
                acl::AclEngine::with_workspace(ws)
            } else {
                acl::AclEngine::default()
            };

            let resource_perm = match perm.to_lowercase().as_str() {
                "write" => acl::ResourcePermission::Write,
                "exec" | "execute" => acl::ResourcePermission::Execute,
                "any" => acl::ResourcePermission::Any,
                _ => acl::ResourcePermission::Read,
            };

            match action.to_lowercase().as_str() {
                "audit" => {
                    let target_dir =
                        dir.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
                    let violations = acl_engine.audit_directory(&target_dir);
                    if json {
                        println!("{}", serde_json::to_string_pretty(&violations)?);
                    } else {
                        eprintln!(
                            "{} Directory ACL Symlink Audit for '{}':",
                            "NETHER WARD ACL:".cyan().bold(),
                            target_dir.display()
                        );
                        if violations.is_empty() {
                            println!(
                                "  {} Zero escaping symlinks or forbidden targets found.",
                                "[OK]".green().bold()
                            );
                        } else {
                            for v in &violations {
                                eprintln!("  - {}", v);
                            }
                        }
                    }
                    if !violations.is_empty() {
                        std::process::exit(1);
                    }
                }
                "rules" => {
                    if json {
                        let patterns: Vec<String> = acl_engine
                            .denied_patterns
                            .iter()
                            .map(|r| r.to_string())
                            .collect();
                        println!(
                            "{}",
                            serde_json::json!({
                                "denied_patterns": patterns,
                                "workspace_roots": acl_engine.workspace_roots,
                                "strict_confinement": acl_engine.strict_confinement
                            })
                        );
                    } else {
                        eprintln!(
                            "{} Active Declarative ACL Blocklist Patterns:",
                            "NETHER WARD ACL:".cyan().bold()
                        );
                        for r in &acl_engine.denied_patterns {
                            println!("  - {}", r.as_str().yellow());
                        }
                    }
                }
                _ => {
                    let target_path = path.unwrap_or_else(|| {
                        eprintln!(
                            "{}: Specify --path <PATH> to check against ACL rules.",
                            "Error".red().bold()
                        );
                        std::process::exit(1);
                    });

                    match acl_engine.check_path(&target_path, resource_perm) {
                        Ok(resolved) => {
                            if json {
                                println!(
                                    "{}",
                                    serde_json::json!({
                                        "status": "allowed",
                                        "requested_path": target_path,
                                        "resolved_path": resolved,
                                        "permission": resource_perm
                                    })
                                );
                            } else {
                                eprintln!(
                                    "{} [{}] Access to '{}' (resolved: '{}') is ALLOWED.",
                                    "ACL ALLOWED:".green().bold(),
                                    resource_perm,
                                    target_path,
                                    resolved.display()
                                );
                            }
                        }
                        Err(violation) => {
                            if json {
                                println!("{}", serde_json::to_string_pretty(&violation)?);
                            } else {
                                eprintln!("{} {}", "ACL FORBIDDEN:".red().bold(), violation);
                                eprintln!("  Recommendation: {}", violation.recommendation);
                            }
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
