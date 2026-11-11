use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    pub sample_size_bytes: usize,
    pub entropy: f64,
    pub entropy_risk: String,
    pub extracted_strings_count: usize,
    pub detected_indicators: Vec<String>,
    pub severity: ThreatSeverity,
    pub verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatSeverity::Clean => write!(f, "CLEAN"),
            ThreatSeverity::Low => write!(f, "LOW"),
            ThreatSeverity::Medium => write!(f, "MEDIUM"),
            ThreatSeverity::High => write!(f, "HIGH"),
            ThreatSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Calculate Shannon entropy (H = -sum(p * log2(p))) in bits per byte [0.0, 8.0].
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    // Floating-point clamp to avoid -0.0
    if entropy.abs() < 1e-9 {
        0.0
    } else {
        entropy
    }
}

/// Extract printable ASCII strings (byte range 32..=126) of minimum length.
pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &b in data {
        if (32..=126).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_length {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(s);
                }
            }
            current.clear();
        }
    }

    if current.len() >= min_length {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(s);
        }
    }

    strings
}

/// Analyze raw byte payload against heuristics, indicators of compromise, and entropy thresholds.
pub fn analyze_payload(data: &[u8]) -> ThreatReport {
    let entropy = calculate_entropy(data);
    let strings = extract_strings(data, 4);

    let entropy_risk = if entropy >= 7.2 {
        "High (Packed, Encrypted, or Shellcode)".to_string()
    } else if entropy >= 6.0 {
        "Elevated (Compressed or Obfuscated)".to_string()
    } else {
        "Normal (Plaintext or Structured Code)".to_string()
    };

    let mut indicators = Vec::new();
    let joined_strings = strings.join(" \n ");

    // Suspicious pattern matching
    let suspicious_patterns = [
        ("/dev/tcp/", "Reverse shell bash network redirection"),
        ("sh -i", "Interactive shell spawn probe"),
        ("bash -i", "Interactive bash spawn probe"),
        ("cat /etc/shadow", "Sensitive shadow file access probe"),
        ("cat /etc/passwd", "User database reconnaissance probe"),
        ("rm -rf", "Destructive recursive file deletion invocation"),
        ("nc -e", "Netcat command execution probe"),
        ("curl -s", "Silent web retrieval probe"),
        ("wget -q", "Silent web retrieval probe"),
        ("Invoke-Expression", "PowerShell memory execution probe"),
        ("IEX(", "PowerShell abbreviated IEX execution probe"),
        (
            "SECURITY_BARRIER_BREACHED",
            "Simulated jailbreak confirmation token",
        ),
    ];

    for (pattern, desc) in suspicious_patterns {
        if joined_strings.contains(pattern) {
            indicators.push(format!("{desc} ({pattern})"));
        }
    }

    // Run multi-vector SAST analysis on text payload or extracted strings
    let text_for_sast = if let Ok(s) = std::str::from_utf8(data) {
        s.to_string()
    } else {
        joined_strings.clone()
    };

    let sast_findings = crate::sast::scan_content(&text_for_sast, None);
    let mut sast_critical = 0;
    let mut sast_high = 0;
    let mut sast_medium = 0;

    for f in sast_findings {
        indicators.push(format!("{}: {} [{}]", f.rule_id, f.title, f.category));
        match f.severity {
            crate::sast::SastSeverity::Critical => sast_critical += 1,
            crate::sast::SastSeverity::High => sast_high += 1,
            crate::sast::SastSeverity::Medium => sast_medium += 1,
            _ => {}
        }
    }

    // Determine severity
    let severity =
        if sast_critical > 0 || indicators.len() >= 2 || (entropy >= 7.2 && !indicators.is_empty())
        {
            ThreatSeverity::Critical
        } else if sast_high > 0 || !indicators.is_empty() {
            ThreatSeverity::High
        } else if sast_medium > 0 || entropy >= 7.2 {
            ThreatSeverity::Medium
        } else if entropy >= 6.5 {
            ThreatSeverity::Low
        } else {
            ThreatSeverity::Clean
        };

    let verdict = match severity {
        ThreatSeverity::Clean => {
            "Payload exhibits normal characteristics with zero threat indicators."
        }
        ThreatSeverity::Low => "Payload displays mild compression or entropy variance.",
        ThreatSeverity::Medium => {
            "Payload displays elevated entropy indicative of packing or obfuscation."
        }
        ThreatSeverity::High => "Hostile signatures or command execution probes detected.",
        ThreatSeverity::Critical => {
            "Multiple hostile indicators and high entropy detected. Immediate quarantine advised."
        }
    }
    .to_string();

    ThreatReport {
        sample_size_bytes: data.len(),
        entropy,
        entropy_risk,
        extracted_strings_count: strings.len(),
        detected_indicators: indicators,
        severity,
        verdict,
    }
}

pub fn print_report(report: &ThreatReport, filename: Option<&str>) {
    println!();
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!(
        "{}",
        "           NETHER WARD: AUTONOMOUS THREAT TRIAGE REPORT (RUST)                 "
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "================================================================================".blue()
    );
    if let Some(f) = filename {
        println!("{:<24}: {}", "Target File".bold(), f);
    }
    println!(
        "{:<24}: {} bytes",
        "Payload Size".bold(),
        report.sample_size_bytes
    );
    println!(
        "{:<24}: {:.4} bits/byte ({})",
        "Shannon Entropy".bold(),
        report.entropy,
        report.entropy_risk
    );
    println!(
        "{:<24}: {}",
        "Extracted Strings".bold(),
        report.extracted_strings_count
    );

    let sev_colored = match report.severity {
        ThreatSeverity::Clean => report.severity.to_string().green().bold(),
        ThreatSeverity::Low => report.severity.to_string().cyan().bold(),
        ThreatSeverity::Medium => report.severity.to_string().yellow().bold(),
        ThreatSeverity::High => report.severity.to_string().red().bold(),
        ThreatSeverity::Critical => report.severity.to_string().white().on_red().bold(),
    };
    println!("{:<24}: {}", "Threat Severity".bold(), sev_colored);

    if !report.detected_indicators.is_empty() {
        println!();
        println!("{}", "Detected Hostile Indicators:".yellow().bold());
        for ind in &report.detected_indicators {
            println!("  - {}", ind.red());
        }
    }

    println!();
    println!("{:<24}: {}", "Triage Verdict".bold(), report.verdict);
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchThreatReport {
    pub total_files: usize,
    pub clean_files: usize,
    pub low_files: usize,
    pub medium_files: usize,
    pub high_files: usize,
    pub critical_files: usize,
    pub total_bytes: usize,
    pub duration_ms: u128,
    pub file_reports: Vec<FileThreatSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileThreatSummary {
    pub filename: String,
    pub relative_path: String,
    pub size_bytes: usize,
    pub entropy: f64,
    pub severity: ThreatSeverity,
    pub indicators: Vec<String>,
}

pub fn scan_directory(dir_path: &std::path::Path) -> std::io::Result<BatchThreatReport> {
    let start = std::time::Instant::now();
    let mut file_reports = Vec::new();
    let mut total_bytes = 0;
    let mut clean_files = 0;
    let mut low_files = 0;
    let mut medium_files = 0;
    let mut high_files = 0;
    let mut critical_files = 0;

    let mut entries = Vec::new();
    collect_files_recursive(dir_path, &mut entries)?;

    for entry in entries {
        if let Ok(data) = std::fs::read(&entry) {
            total_bytes += data.len();
            let report = analyze_payload(&data);
            match report.severity {
                ThreatSeverity::Clean => clean_files += 1,
                ThreatSeverity::Low => low_files += 1,
                ThreatSeverity::Medium => medium_files += 1,
                ThreatSeverity::High => high_files += 1,
                ThreatSeverity::Critical => critical_files += 1,
            }
            let rel_path = entry
                .strip_prefix(dir_path)
                .unwrap_or(&entry)
                .to_string_lossy()
                .to_string();
            let filename = entry
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            file_reports.push(FileThreatSummary {
                filename,
                relative_path: rel_path,
                size_bytes: data.len(),
                entropy: report.entropy,
                severity: report.severity,
                indicators: report.detected_indicators,
            });
        }
    }

    Ok(BatchThreatReport {
        total_files: file_reports.len(),
        clean_files,
        low_files,
        medium_files,
        high_files,
        critical_files,
        total_bytes,
        duration_ms: start.elapsed().as_millis(),
        file_reports,
    })
}

fn collect_files_recursive(
    dir: &std::path::Path,
    files: &mut Vec<std::path::PathBuf>,
) -> std::io::Result<()> {
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files_recursive(&path, files)?;
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    Ok(())
}

pub fn print_batch_report(report: &BatchThreatReport, dir_name: &str) {
    println!();
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!(
        "{}",
        "        NETHER WARD: BATCH DIRECTORY THREAT TRIAGE REPORT (RUST)                "
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!("{:<24}: {}", "Target Directory".bold(), dir_name);
    println!(
        "{:<24}: {} files",
        "Total Files Scanned".bold(),
        report.total_files
    );
    println!(
        "{:<24}: {:.2} KB",
        "Total Scanned Volume".bold(),
        report.total_bytes as f64 / 1024.0
    );
    println!(
        "{:<24}: {} ms",
        "Execution Latency".bold(),
        report.duration_ms
    );
    println!();
    println!("{}", "--- SEVERITY BREAKDOWN ---".bold());
    println!(
        "{:<24}: {}",
        "Clean Files".bold(),
        report.clean_files.to_string().green()
    );
    println!(
        "{:<24}: {}",
        "Low Risk Files".bold(),
        report.low_files.to_string().cyan()
    );
    println!(
        "{:<24}: {}",
        "Medium Risk Files".bold(),
        report.medium_files.to_string().yellow()
    );
    println!(
        "{:<24}: {}",
        "High Risk Files".bold(),
        report.high_files.to_string().red().bold()
    );
    println!(
        "{:<24}: {}",
        "Critical Threat Files".bold(),
        report.critical_files.to_string().white().on_red().bold()
    );
    println!();
    println!(
        "{:<35} {:<12} {:<14} {:<16}",
        "FILE PATH", "SIZE", "ENTROPY", "SEVERITY"
    );
    println!(
        "{}",
        "--------------------------------------------------------------------------------".blue()
    );
    for f in &report.file_reports {
        let sev_str = match f.severity {
            ThreatSeverity::Clean => "CLEAN".green(),
            ThreatSeverity::Low => "LOW".cyan(),
            ThreatSeverity::Medium => "MEDIUM".yellow(),
            ThreatSeverity::High => "HIGH".red().bold(),
            ThreatSeverity::Critical => "CRITICAL".white().on_red().bold(),
        };
        println!(
            "{:<35} {:<12} {:<14.2} {:<16}",
            f.relative_path,
            format!("{} B", f.size_bytes),
            f.entropy,
            sev_str
        );
    }
    println!(
        "{}",
        "================================================================================".blue()
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy_homogeneous() {
        assert_eq!(calculate_entropy(b"AAAAAAA"), 0.0);
    }

    #[test]
    fn test_zero_entropy_empty() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_max_entropy_uniform_distribution() {
        let all_bytes: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&all_bytes);
        assert!(
            (entropy - 8.0).abs() < 1e-9,
            "Expected 8.0 bits of entropy for uniform byte distribution"
        );
    }

    #[test]
    fn test_string_extraction() {
        let sample = b"PayloadHeader\x00\x01\x02TargetCommand\x00";
        let extracted = extract_strings(sample, 4);
        assert!(extracted.contains(&"PayloadHeader".to_string()));
        assert!(extracted.contains(&"TargetCommand".to_string()));
    }

    #[test]
    fn test_threat_detection_indicators() {
        let malicious = b"#!/bin/bash\nrm -rf /var/log && cat /etc/shadow\n";
        let report = analyze_payload(malicious);
        assert!(
            report.severity == ThreatSeverity::High || report.severity == ThreatSeverity::Critical
        );
        assert!(report
            .detected_indicators
            .iter()
            .any(|i| i.contains("rm -rf")));
        assert!(report
            .detected_indicators
            .iter()
            .any(|i| i.contains("/etc/shadow")));
    }

    #[test]
    fn test_batch_directory_scan() {
        let temp_dir = std::env::temp_dir().join("nether_ward_test_batch");
        let _ = std::fs::create_dir_all(&temp_dir);
        let file1 = temp_dir.join("clean.txt");
        let file2 = temp_dir.join("malicious.sh");
        std::fs::write(&file1, b"hello world clean file").unwrap();
        std::fs::write(&file2, b"rm -rf /var/log && cat /etc/shadow").unwrap();

        let report = scan_directory(&temp_dir).unwrap();
        assert_eq!(report.total_files, 2);
        assert!(report.clean_files >= 1);
        assert!(report.high_files + report.critical_files >= 1);

        let _ = std::fs::remove_file(file1);
        let _ = std::fs::remove_file(file2);
        let _ = std::fs::remove_dir(temp_dir);
    }
}
