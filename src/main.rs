use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::path::PathBuf;

mod gateway;
mod jev;
mod redteam;
mod sast;
mod threat;

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
        } => {
            gateway::run_gateway(port, model, upstream).await?;
        }

        Commands::Redteam {
            config,
            model,
            concurrency,
            dataset,
            endpoint,
            judge,
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
    }

    Ok(())
}
