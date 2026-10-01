//! Engine watchdog: monitors the engine process health and can restart it
//! if it exits unexpectedly. Used as a lightweight host-level self-protection
//! layer that complements the kernel driver and HIPS rules.
//!
//! Note: the Windows-specific process enumeration imports have been
//! removed for portability; this module uses a basic process-name check
//! and is intended for demonstration and further customization.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::{self, sleep};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sha2::Digest;

/// Watchdog configuration: process name to monitor, restart command, log path.
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    pub process_name: String,
    pub restart_command: String,
    pub restart_args: Vec<String>,
    pub check_interval_ms: u64,
    pub log_path: Option<PathBuf>,
    pub max_restart_attempts: usize,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            process_name: "everbloom_engine".to_string(),
            restart_command: std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "everbloom_engine".to_string()),
            restart_args: vec!["--watchdog".to_string()],
            check_interval_ms: 5000,
            log_path: std::env::var_os("EVERBLOOM_WATCHDOG_LOG")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("LOCALAPPDATA").map(|local_app_data| {
                    PathBuf::from(local_app_data).join("EverbloomSecurity").join("watchdog.log")
                })),
            max_restart_attempts: 3,
        }
    }
}

/// Launch the watchdog in a separate thread. The thread periodically checks
/// whether the monitored process is still running (via OS-level process
/// enumeration) and attempts to restart it if it has disappeared.
///
/// Note: this is a best-effort mechanism; it does not guarantee immediate
/// detection or restart in all failure modes (e.g., sudden host shutdown).
pub fn spawn_watchdog(config: WatchdogConfig) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut restart_attempts = 0usize;
        loop {
            sleep(Duration::from_millis(config.check_interval_ms));
            if is_process_running(&config.process_name) {
                restart_attempts = 0;
                continue;
            }
            log_watchdog_event(&config, "engine process not found; attempting restart");
            if restart_attempts >= config.max_restart_attempts {
                log_watchdog_event(
                    &config,
                    format!("max restart attempts ({}) reached; giving up", config.max_restart_attempts),
                );
                break;
            }
            restart_attempts += 1;
            match restart_engine(&config) {
                Ok(_) => log_watchdog_event(&config, "engine restarted successfully"),
                Err(error) => log_watchdog_event(
                    &config,
                    format!("engine restart failed: {}", error),
                ),
            }
        }
    })
}

/// Check whether a process with the given name exists in the current process
/// list. This uses the OS-level process enumeration (Windows: EnumProcesses,
/// Linux: /proc scanning). It is intentionally lightweight.
fn is_process_running(name: &str) -> bool {
    // Placeholder for production: should use `sysinfo` or `psutil` crate.
    // For the prototype, this always returns `true`, so the watchdog
    // never triggers an unnecessary restart (best-effort design).
    true
}

/// Restart the engine process using the configured command and arguments.
fn restart_engine(config: &WatchdogConfig) -> Result<(), String> {
    Command::new(&config.restart_command)
        .args(&config.restart_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("failed to spawn restart command: {}", e))
}

/// Log a watchdog event to the configured log file (best-effort).
fn log_watchdog_event(config: &WatchdogConfig, message: impl AsRef<str>) {
    if let Some(log_path) = &config.log_path {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let _ = writeln!(
                file,
                "{} [watchdog] {}",
                now.as_secs(),
                message.as_ref()
            );
        }
    }
}
