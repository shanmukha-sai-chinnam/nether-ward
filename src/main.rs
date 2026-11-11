use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::path::PathBuf;

mod gateway;
mod redteam;
mod threat;

#[derive(Parser)]
#[command(name = "nether-ward")]
#[command(author = "shanmukha-sai-chinnam")]
#[command(version = "0.2.0")]
#[command(about = "Declarative AI Infrastructure Platform & Autonomous Cybersecurity Sentinel in Pure Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a suspicious file or payload for high entropy and threat indicators
    Threat {
        /// Target file path to analyze
        #[arg(short, long)]
        sample: PathBuf,

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
    },

    /// Run the synthetic AI red team security evaluation matrix
    Redteam {
        /// Path to red team configuration YAML
        #[arg(short, long, default_value = "config/redteam_config.yaml")]
        config: String,

        /// Override evaluation model target
        #[arg(short, long)]
        model: Option<String>,

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
            min_length: _,
            json,
        } => {
            if !sample.exists() {
                eprintln!(
                    "{}: Target sample '{}' does not exist.",
                    "Error".red().bold(),
                    sample.display()
                );
                std::process::exit(1);
            }

            let data = fs::read(&sample)?;
            let report = threat::analyze_payload(&data);

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                threat::print_report(&report, sample.to_str());
            }

            if report.severity == threat::ThreatSeverity::Critical
                || report.severity == threat::ThreatSeverity::High
            {
                std::process::exit(2);
            }
        }

        Commands::Gateway { port, model } => {
            gateway::run_gateway(port, model).await?;
        }

        Commands::Redteam {
            config,
            model,
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
                let all_passed = redteam::run_redteam(&config, model.as_deref()).await?;
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
