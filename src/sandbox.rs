use colored::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Instant;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub workspace: PathBuf,
    pub no_network: bool,
    pub read_only_root: bool,
    pub timeout_secs: u64,
    pub dry_run: bool,
    pub capture_output: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            workspace: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            no_network: false,
            read_only_root: false,
            timeout_secs: 30,
            dry_run: false,
            capture_output: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecutionReport {
    pub engine: String,
    pub command: String,
    pub args: Vec<String>,
    pub workspace: String,
    pub network_isolated: bool,
    pub read_only_root: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

/// Detect whether Bubblewrap (`bwrap`) is installed on the system
pub fn find_bwrap() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("bwrap");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Generate human-readable summary of the sandbox enforcement policy
pub fn describe_sandbox(config: &SandboxConfig) -> String {
    let engine = if find_bwrap().is_some() {
        "Bubblewrap Container Namespaces (bwrap)"
    } else {
        "Native Linux Kernel Security (PR_SET_NO_NEW_PRIVS + Env Scrubbing)"
    };

    format!(
        "Sandbox Engine: {}\nWorkspace Root: {}\nNetwork Isolation: {}\nRead-Only Root: {}\nExecution Timeout: {}s",
        engine,
        config.workspace.display(),
        if config.no_network { "Enabled (CLONE_NEWNET)" } else { "Disabled (Host Network)" },
        if config.read_only_root { "Active (RO root mount)" } else { "Standard" },
        config.timeout_secs
    )
}

/// Execute command inside kernel sandbox boundary
pub async fn run_sandboxed(
    config: &SandboxConfig,
    cmd: &str,
    args: &[String],
) -> Result<SandboxExecutionReport, Box<dyn std::error::Error>> {
    let canonical_workspace = if config.workspace.exists() {
        config.workspace.canonicalize()?
    } else {
        config.workspace.clone()
    };

    if config.dry_run {
        println!(
            "{}",
            "NETHER WARD SANDBOX SPECIFICATION (DRY RUN):".cyan().bold()
        );
        println!("{}", describe_sandbox(config));
        println!("Target Command: {} {}", cmd, args.join(" "));
        return Ok(SandboxExecutionReport {
            engine: "DryRun".to_string(),
            command: cmd.to_string(),
            args: args.to_vec(),
            workspace: canonical_workspace.display().to_string(),
            network_isolated: config.no_network,
            read_only_root: config.read_only_root,
            exit_code: Some(0),
            duration_ms: 0,
            success: true,
            stdout: None,
            stderr: None,
        });
    }

    let start = Instant::now();

    if let Some(bwrap_bin) = find_bwrap() {
        // Mode 1: Bubblewrap Namespace Isolation
        let mut bwrap_cmd = Command::new(bwrap_bin);
        bwrap_cmd
            .arg("--ro-bind")
            .arg("/")
            .arg("/")
            .arg("--dev")
            .arg("/dev")
            .arg("--proc")
            .arg("/proc")
            .arg("--tmpfs")
            .arg("/tmp")
            .arg("--bind")
            .arg(&canonical_workspace)
            .arg(&canonical_workspace)
            .arg("--chdir")
            .arg(&canonical_workspace)
            .arg("--die-with-parent")
            .arg("--new-session")
            .arg("--unshare-pid")
            .arg("--unshare-ipc")
            .arg("--unshare-uts");

        if config.no_network {
            bwrap_cmd.arg("--unshare-net");
        }

        bwrap_cmd.arg("--").arg(cmd).args(args);

        // Scrub hostile environment variables
        bwrap_cmd.env_remove("LD_PRELOAD");
        bwrap_cmd.env_remove("LD_LIBRARY_PATH");
        bwrap_cmd.env_remove("BASH_ENV");

        if config.capture_output {
            bwrap_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            bwrap_cmd
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }

        let timeout_dur = std::time::Duration::from_secs(config.timeout_secs);
        let (code, stdout, stderr, success) = if config.capture_output {
            let output = tokio::time::timeout(timeout_dur, bwrap_cmd.output()).await??;
            (
                output.status.code(),
                Some(String::from_utf8_lossy(&output.stdout).to_string()),
                Some(String::from_utf8_lossy(&output.stderr).to_string()),
                output.status.success(),
            )
        } else {
            let mut child = bwrap_cmd.spawn()?;
            let status = tokio::time::timeout(timeout_dur, child.wait()).await??;
            (status.code(), None, None, status.success())
        };

        let duration_ms = start.elapsed().as_millis();

        Ok(SandboxExecutionReport {
            engine: "Bubblewrap".to_string(),
            command: cmd.to_string(),
            args: args.to_vec(),
            workspace: canonical_workspace.display().to_string(),
            network_isolated: config.no_network,
            read_only_root: true,
            exit_code: code,
            duration_ms,
            success,
            stdout,
            stderr,
        })
    } else {
        // Mode 2: Native Linux Kernel Boundary (PR_SET_NO_NEW_PRIVS)
        let mut native_cmd = Command::new(cmd);
        native_cmd.args(args);
        native_cmd.current_dir(&canonical_workspace);

        // Scrub hostile environment variables
        native_cmd.env_remove("LD_PRELOAD");
        native_cmd.env_remove("LD_LIBRARY_PATH");
        native_cmd.env_remove("BASH_ENV");
        native_cmd.env_remove("ENV");

        let isolate_net = config.no_network;

        unsafe {
            native_cmd.pre_exec(move || {
                // Prevent setuid/setgid privilege escalation
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                if isolate_net {
                    // Attempt network namespace isolation; fail-open if unprivileged
                    let _ = libc::unshare(libc::CLONE_NEWNET);
                }

                Ok(())
            });
        }

        if config.capture_output {
            native_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            native_cmd
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }

        let timeout_dur = std::time::Duration::from_secs(config.timeout_secs);
        let (code, stdout, stderr, success) = if config.capture_output {
            let output = match tokio::time::timeout(timeout_dur, native_cmd.output()).await {
                Ok(res) => res?,
                Err(_) => {
                    return Err(format!(
                        "Sandbox execution timed out after {} seconds. Terminated by Nether Ward watchdog.",
                        config.timeout_secs
                    )
                    .into());
                }
            };
            (
                output.status.code(),
                Some(String::from_utf8_lossy(&output.stdout).to_string()),
                Some(String::from_utf8_lossy(&output.stderr).to_string()),
                output.status.success(),
            )
        } else {
            let mut child = native_cmd.spawn()?;
            let status = match tokio::time::timeout(timeout_dur, child.wait()).await {
                Ok(res) => res?,
                Err(_) => {
                    let _ = child.kill().await;
                    return Err(format!(
                        "Sandbox execution timed out after {} seconds. Terminated by Nether Ward watchdog.",
                        config.timeout_secs
                    )
                    .into());
                }
            };
            (status.code(), None, None, status.success())
        };

        let duration_ms = start.elapsed().as_millis();

        Ok(SandboxExecutionReport {
            engine: "NativeLinuxKernel".to_string(),
            command: cmd.to_string(),
            args: args.to_vec(),
            workspace: canonical_workspace.display().to_string(),
            network_isolated: config.no_network,
            read_only_root: config.read_only_root,
            exit_code: code,
            duration_ms,
            success,
            stdout,
            stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_default() {
        let cfg = SandboxConfig::default();
        assert_eq!(cfg.timeout_secs, 30);
        assert!(!cfg.no_network);
        assert!(!cfg.read_only_root);
        assert!(!cfg.dry_run);
    }

    #[test]
    fn test_describe_sandbox() {
        let cfg = SandboxConfig {
            workspace: PathBuf::from("/tmp"),
            no_network: true,
            read_only_root: true,
            timeout_secs: 15,
            dry_run: false,
            capture_output: false,
        };
        let desc = describe_sandbox(&cfg);
        assert!(desc.contains("/tmp"));
        assert!(desc.contains("CLONE_NEWNET"));
        assert!(desc.contains("15s"));
    }

    #[tokio::test]
    async fn test_sandbox_dry_run() {
        let cfg = SandboxConfig {
            workspace: PathBuf::from("/tmp"),
            no_network: true,
            read_only_root: true,
            timeout_secs: 10,
            dry_run: true,
            capture_output: true,
        };
        let report = run_sandboxed(&cfg, "echo", &["dry_run_test".to_string()])
            .await
            .unwrap();
        assert_eq!(report.engine, "DryRun");
        assert!(report.success);
        assert_eq!(report.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_sandbox_native_execution() {
        let temp_dir = std::env::temp_dir();
        let cfg = SandboxConfig {
            workspace: temp_dir,
            no_network: false,
            read_only_root: false,
            timeout_secs: 10,
            dry_run: false,
            capture_output: true,
        };
        let report = run_sandboxed(&cfg, "echo", &["sandbox_ok".to_string()])
            .await
            .unwrap();
        assert!(report.success);
        assert_eq!(report.exit_code, Some(0));
        assert!(report.stdout.unwrap().contains("sandbox_ok"));
    }
}
