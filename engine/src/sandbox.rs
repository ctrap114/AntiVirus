#[cfg(target_family = "windows")]
use crate::layers::memory_snapshot::MemorySnapshotCollector;
use crate::layers::memory_snapshot::SandboxUnpackingReport;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

#[cfg(any(test, target_family = "windows"))]
use std::path::Path;
#[cfg(target_family = "windows")]
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::windows::ffi::OsStrExt,
    process::{Child, Command, Stdio},
    ptr::null_mut,
    sync::Mutex,
    thread,
    time::{Instant, SystemTime},
};

use serde::{Deserialize, Serialize};
#[cfg(target_family = "windows")]
use tempfile::TempDir;
use thiserror::Error;
#[cfg(target_family = "windows")]
use tokio::sync::Semaphore;
#[cfg(target_family = "windows")]
use tokio::task;

#[cfg(target_family = "windows")]
const MIN_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(target_family = "windows")]
const MAX_TIMEOUT: Duration = Duration::from_secs(10 * 60);
#[cfg(target_family = "windows")]
const MAX_SAMPLE_SIZE: u64 = 1024 * 1024 * 1024;
#[cfg(target_family = "windows")]
const COPY_BUFFER_BYTES: usize = 1024 * 1024;
#[cfg(target_family = "windows")]
const COPY_FREE_SPACE_HEADROOM: u64 = 64 * 1024 * 1024;
#[cfg(target_family = "windows")]
const DEFAULT_COPY_RATE_LIMIT_BYTES_PER_SEC: u64 = 256 * 1024 * 1024;

/// Bump when isolation policy, guest collection limits, or the fallback
/// contract changes. Scan-cache entries must not cross this boundary.
pub const SANDBOX_POLICY_VERSION: u64 = 3;

#[cfg(target_family = "windows")]
static WINDOWS_SANDBOX_LOCK: Mutex<()> = Mutex::new(());
#[cfg(target_family = "windows")]
static SANDBOX_SLOTS: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
#[cfg(target_family = "windows")]
static APPCONTAINER_CLEANUP_ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();

#[cfg(target_family = "windows")]
const APPCONTAINER_ORPHAN_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// High-level summary of an isolated sample execution.
///
/// Both the local AppContainer backend and the Windows Sandbox fallback avoid
/// mapping the original sample location into the execution environment. The
/// local backend uses an AppContainer profile directory and the VM backend
/// uses a read-only mapped input directory.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SandboxReport {
    pub target: PathBuf,
    pub exit_code: Option<i32>,
    pub target_pid: Option<u32>,
    pub files_changed: Vec<PathBuf>,
    pub registry_writes: Vec<String>,
    pub network_connections: Vec<String>,
    pub processes: Vec<String>,
    pub api_calls: Vec<String>,
    pub timed_out: bool,
    pub isolation_backend: String,
    pub isolation_verified: bool,
    pub cleanup_verified: bool,
    pub resource_limits: Vec<String>,
    pub unpacking: SandboxUnpackingReport,
    pub duration_ms: u128,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sandbox launch failed: {0}")]
    Spawn(String),
    #[error("secure isolation is unavailable: {0}")]
    IsolationUnavailable(String),
    #[error("unsupported sandbox target: {0}")]
    UnsupportedTarget(String),
    #[error("sandbox execution cancelled")]
    Cancelled,
}

/// Run an untrusted executable in the strongest available disposable sandbox.
///
/// Windows first tries the self-contained AppContainer + Job Object backend.
/// That backend is host-restricted rather than a VM, so the report records a
/// different backend name. If its prerequisites are unavailable, execution
/// falls back to Windows Sandbox. There is no unrestricted host-process path.
pub async fn run_sandbox(
    target: PathBuf,
    timeout: Duration,
) -> Result<SandboxReport, SandboxError> {
    run_sandbox_with_cancel(target, timeout, Arc::new(AtomicBool::new(false))).await
}

/// Run the sandbox while honoring the caller's cancellation token. Native
/// sandbox backends cannot be interrupted cooperatively from inside the sample,
/// so cancellation terminates the containing Job Object or Windows Sandbox
/// process tree and returns `SandboxError::Cancelled`.
pub async fn run_sandbox_with_cancel(
    target: PathBuf,
    timeout: Duration,
    cancelled: Arc<AtomicBool>,
) -> Result<SandboxReport, SandboxError> {
    #[cfg(target_family = "windows")]
    {
        if cancelled.load(Ordering::Relaxed) {
            return Err(SandboxError::Cancelled);
        }
        let permit = SANDBOX_SLOTS
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| SandboxError::Spawn(format!("sandbox queue closed: {error}")))?;
        task::spawn_blocking(move || {
            let _permit = permit;
            run_with_fallback(target, timeout, cancelled)
        })
        .await
        .map_err(|error| SandboxError::Spawn(format!("sandbox worker join failed: {error}")))?
    }

    #[cfg(not(target_family = "windows"))]
    {
        let _ = target;
        let _ = timeout;
        let _ = cancelled;
        Err(SandboxError::IsolationUnavailable(
            "no secure sandbox backend is implemented for this platform".to_string(),
        ))
    }
}

#[cfg(target_family = "windows")]
fn appcontainer_manifest_path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|root| root.join("EverbloomSecurity").join("appcontainer_profiles.tsv"))
}

#[cfg(target_family = "windows")]
fn appcontainer_profile_name(name: &[u16]) -> String {
    let length = name
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(name.len());
    String::from_utf16_lossy(&name[..length])
}

#[cfg(target_family = "windows")]
fn rewrite_appcontainer_manifest(entries: &[(u64, String)]) {
    let Some(path) = appcontainer_manifest_path() else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    if entries.is_empty() {
        let _ = fs::remove_file(path);
        return;
    }
    let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
    else {
        return;
    };
    for (created_at, name) in entries {
        let _ = writeln!(file, "{created_at}\t{name}");
    }
}

#[cfg(target_family = "windows")]
fn record_appcontainer_profile(name: &[u16]) {
    let Some(path) = appcontainer_manifest_path() else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    let profile_name = appcontainer_profile_name(name);
    if profile_name.is_empty()
        || profile_name
            .chars()
            .any(|value| matches!(value, '\t' | '\r' | '\n'))
    {
        return;
    }
    let created_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{created_at}\t{profile_name}");
    }
}

#[cfg(target_family = "windows")]
fn remove_appcontainer_profile_record(name: &[u16]) {
    let Some(path) = appcontainer_manifest_path() else {
        return;
    };
    let Ok(file) = fs::File::open(&path) else {
        return;
    };
    let target = appcontainer_profile_name(name);
    let entries = BufReader::new(file)
        .lines()
        .filter_map(Result::ok)
        .filter_map(|line| {
            let (timestamp, profile) = line.split_once('\t')?;
            Some((timestamp.parse::<u64>().ok()?, profile.to_string()))
        })
        .filter(|(_, profile)| profile != &target)
        .collect::<Vec<_>>();
    rewrite_appcontainer_manifest(&entries);
}

#[cfg(target_family = "windows")]
fn cleanup_stale_appcontainer_profiles() {
    APPCONTAINER_CLEANUP_ONCE.get_or_init(|| {
        let Some(path) = appcontainer_manifest_path() else {
            return;
        };
        let Ok(file) = fs::File::open(&path) else {
            return;
        };
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut retained = Vec::new();
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let Some((timestamp, profile)) = line.split_once('\t') else {
                continue;
            };
            let Ok(created_at) = timestamp.parse::<u64>() else {
                continue;
            };
            let age = Duration::from_secs(now.saturating_sub(created_at));
            if age < APPCONTAINER_ORPHAN_MAX_AGE || !profile.starts_with("EverbloomSecurity.Sandbox.") {
                retained.push((created_at, profile.to_string()));
                continue;
            }
            let profile_wide = to_wide_str(profile);
            let result = unsafe {
                windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile(
                    profile_wide.as_ptr(),
                )
            };
            if result >= 0 {
                log::info!(
                    "SANDBOX_ORPHAN_PROFILE_CLEANED profile={} age_hours={}",
                    profile,
                    age.as_secs() / 3600
                );
            } else {
                retained.push((created_at, profile.to_string()));
                log::warn!(
                    "SANDBOX_ORPHAN_PROFILE_CLEANUP_FAILED profile={} hresult=0x{:08x}",
                    profile,
                    result as u32
                );
            }
        }
        rewrite_appcontainer_manifest(&retained);
    });
}

#[cfg(target_family = "windows")]
#[derive(Debug)]
enum LocalSandboxError {
    Unavailable(String),
    Failed(SandboxError),
}

#[cfg(target_family = "windows")]
fn run_with_fallback(
    target: PathBuf,
    timeout: Duration,
    cancelled: Arc<AtomicBool>,
) -> Result<SandboxReport, SandboxError> {
    cleanup_stale_appcontainer_profiles();
    log::info!(
        "SANDBOX_BACKEND_ATTEMPT backend=appcontainer target={} timeout_ms={}",
        target.display(),
        timeout.as_millis()
    );
    match run_local_sandbox(target.clone(), timeout, cancelled.as_ref()) {
        Ok(report) => {
            log::info!(
                "SANDBOX_CHILD_EXITED backend=appcontainer target={} exit_code={:?} timed_out={} duration_ms={}",
                report.target.display(),
                report.exit_code,
                report.timed_out,
                report.duration_ms
            );
            Ok(report)
        }
        Err(LocalSandboxError::Failed(error)) => {
            log::error!(
                "SANDBOX_CHILD_FAILED backend=appcontainer target={} error={}",
                target.display(),
                error
            );
            Err(error)
        }
        Err(LocalSandboxError::Unavailable(reason)) => {
            if cancelled.load(Ordering::Relaxed) {
                return Err(SandboxError::Cancelled);
            }
            log::warn!(
                "SANDBOX_FALLBACK backend=windows_sandbox target={} reason={}",
                target.display(),
                reason
            );
            let mut report = run_windows_sandbox(target, timeout, cancelled.as_ref()).map_err(|error| {
                SandboxError::IsolationUnavailable(format!(
                    "self-contained backend unavailable ({reason}); Windows Sandbox fallback failed: {error}"
                ))
            })?;
            report
                .api_calls
                .push(format!("fallback:local_backend_unavailable:{reason}"));
            Ok(report)
        }
    }
}

#[cfg(target_family = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalFileStamp {
    length: u64,
    modified: Option<SystemTime>,
}

#[cfg(target_family = "windows")]
fn snapshot_local_tree(root: &Path) -> Result<BTreeMap<PathBuf, LocalFileStamp>, String> {
    let mut snapshot = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("unable to enumerate sandbox directory: {error}"))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("unable to read sandbox entry: {error}"))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("unable to inspect sandbox entry: {error}"))?;
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let metadata = entry
                .metadata()
                .map_err(|error| format!("unable to stat sandbox entry: {error}"))?;
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("unable to normalize sandbox entry: {error}"))?
                .to_path_buf();
            snapshot.insert(
                relative,
                LocalFileStamp {
                    length: metadata.len(),
                    modified: metadata.modified().ok(),
                },
            );
        }
    }
    Ok(snapshot)
}

#[cfg(target_family = "windows")]
fn detect_anti_sandbox_indicators(target: &Path) -> Vec<String> {
    const MAX_INSPECTION_BYTES: u64 = 16 * 1024 * 1024;
    let Ok(metadata) = fs::metadata(target) else {
        return Vec::new();
    };
    if !metadata.is_file() || metadata.len() > MAX_INSPECTION_BYTES {
        return Vec::new();
    }
    let Ok(bytes) = fs::read(target) else {
        return Vec::new();
    };
    let contains = |needle: &str| {
        let ascii = needle.as_bytes();
        let ascii_match = !ascii.is_empty()
            && bytes.windows(ascii.len()).any(|window| {
                window
                    .iter()
                    .zip(ascii)
                    .all(|(left, right)| left.eq_ignore_ascii_case(right))
            });
        let utf16: Vec<u8> = needle
            .encode_utf16()
            .flat_map(|unit| [unit as u8, (unit >> 8) as u8])
            .collect();
        let utf16_match = !utf16.is_empty()
            && bytes.windows(utf16.len()).any(|window| {
                window
                    .chunks_exact(2)
                    .zip(needle.encode_utf16())
                    .all(|(pair, expected)| {
                        pair[0].eq_ignore_ascii_case(&(expected as u8))
                            && pair[1] == (expected >> 8) as u8
                    })
            });
        ascii_match || utf16_match
    };

    let mut indicators = Vec::new();
    if contains("VirtualAllocExNuma") {
        indicators.push("virtual_alloc_ex_numa".to_string());
    }
    if contains("NtQuerySystemInformation") || contains("GetSystemInfo") {
        indicators.push("system_topology_query".to_string());
    }
    if contains("RDTSC") || contains("QueryPerformanceCounter") {
        indicators.push("timing_environment_probe".to_string());
    }
    if contains("IsDebuggerPresent") || contains("CheckRemoteDebuggerPresent") {
        indicators.push("debugger_probe".to_string());
    }
    if contains("VirtualAlloc") && (contains("HeapAlloc") || contains("VirtualProtect")) {
        indicators.push("large_or_executable_memory_probe".to_string());
    }
    let mut push_if_contains = |indicator: &str, needles: &[&str]| {
        if needles.iter().any(|needle| contains(needle)) {
            indicators.push(indicator.to_string());
        }
    };
    push_if_contains(
        "browser_credential_theft_probe",
        &[
            "Login Data",
            "Web Data",
            "Local State",
            "Cookies",
            "Network\\Cookies",
            "key4.db",
            "logins.json",
            "CryptUnprotectData",
            "sqlite3_open",
        ],
    );
    push_if_contains(
        "wallet_or_messenger_theft_probe",
        &["wallet.dat", "tdata", "Telegram", "discord", "LevelDB"],
    );
    push_if_contains(
        "process_injection_probe",
        &[
            "OpenProcess",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtCreateThreadEx",
            "QueueUserAPC",
            "SetWindowsHookEx",
            "NtUnmapViewOfSection",
        ],
    );
    push_if_contains(
        "persistence_probe",
        &[
            "RunOnce",
            "CurrentVersion\\Run",
            "schtasks",
            "TaskCache",
            "Startup",
            "WScript.Shell",
        ],
    );
    push_if_contains(
        "ransomware_recovery_tamper_probe",
        &[
            "vssadmin",
            "delete shadows",
            "wbadmin",
            "bcdedit",
            "recoveryenabled",
            "wmic shadowcopy delete",
        ],
    );
    indicators.sort();
    indicators.dedup();
    indicators
}

#[cfg(target_family = "windows")]
fn diff_local_tree(
    root: &Path,
    before: &BTreeMap<PathBuf, LocalFileStamp>,
    after: &BTreeMap<PathBuf, LocalFileStamp>,
) -> Vec<PathBuf> {
    let mut changed = after
        .iter()
        .filter(|(path, stamp)| before.get(*path) != Some(*stamp))
        .map(|(path, _)| root.join(path))
        .collect::<Vec<_>>();
    changed.extend(
        before
            .keys()
            .filter(|path| !after.contains_key(*path))
            .map(|path| root.join(path)),
    );
    changed.sort();
    changed.dedup();
    changed
}

#[cfg(target_family = "windows")]
fn stage_decoy_surface(root: &Path) -> Result<Vec<PathBuf>, String> {
    const DECOYS: &[(&str, &str, &str)] = &[
        (
            "Documents",
            "accounts.xlsx",
            "EverbloomSecurity sandbox decoy: spreadsheet contents are synthetic.\n",
        ),
        (
            "Documents",
            "wallet.dat",
            "EverbloomSecurity sandbox decoy: wallet contents are synthetic.\n",
        ),
        (
            "Browser/Chrome/User Data/Default",
            "Login Data",
            "EverbloomSecurity sandbox decoy: browser password database placeholder.\n",
        ),
        (
            "Browser/Chrome/User Data/Default/Network",
            "Cookies",
            "EverbloomSecurity sandbox decoy: cookie database placeholder.\n",
        ),
        (
            "Browser/Chrome/User Data",
            "Local State",
            "{\"os_crypt\":{\"encrypted_key\":\"EverbloomSecuritySandboxDecoy\"}}\n",
        ),
        (
            "Telegram/tdata",
            "map0",
            "EverbloomSecurity sandbox decoy: messenger profile placeholder.\n",
        ),
    ];
    let mut staged = Vec::new();
    for (directory, file, content) in DECOYS {
        let directory_path = root.join(directory);
        fs::create_dir_all(&directory_path)
            .map_err(|error| format!("unable to create sandbox decoy directory: {error}"))?;
        let file_path = directory_path.join(file);
        fs::write(&file_path, content)
            .map_err(|error| format!("unable to write sandbox decoy file: {error}"))?;
        staged.push(file_path);
    }
    Ok(staged)
}

#[cfg(target_family = "windows")]
fn detect_decoy_modifications(decoys: &[PathBuf], changed: &[PathBuf]) -> Vec<String> {
    let mut hits = Vec::new();
    for decoy in decoys {
        if changed.iter().any(|path| path == decoy) {
            hits.push(format!("decoy_modified:{}", decoy.display()));
        }
    }
    hits
}

#[cfg(target_family = "windows")]
fn sandbox_copy_rate_limit_bytes_per_sec() -> Option<u64> {
    match std::env::var("EVERBLOOM_SANDBOX_COPY_RATE_MBPS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        Some(0) => None,
        Some(mbps) => Some(mbps.saturating_mul(1024 * 1024)),
        None => Some(DEFAULT_COPY_RATE_LIMIT_BYTES_PER_SEC),
    }
}

#[cfg(target_family = "windows")]
fn ensure_sandbox_free_space(directory: &Path, required_bytes: u64) -> Result<(), SandboxError> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let directory = directory.canonicalize().map_err(SandboxError::Io)?;
    let wide = to_wide_os(directory.as_os_str());
    let mut available = 0u64;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available as *mut u64,
            null_mut(),
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(SandboxError::Io(std::io::Error::last_os_error()));
    }
    let needed = required_bytes.saturating_add(COPY_FREE_SPACE_HEADROOM);
    if available < needed {
        return Err(SandboxError::Spawn(format!(
            "insufficient sandbox staging disk space: available={} required={}",
            available, needed
        )));
    }
    Ok(())
}

#[cfg(target_family = "windows")]
fn copy_sample_to_sandbox(
    source: &Path,
    destination: &Path,
    expected_len: u64,
    cancelled: &AtomicBool,
) -> Result<(), SandboxError> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(SandboxError::Cancelled);
    }
    let parent = destination.parent().ok_or_else(|| {
        SandboxError::Spawn("sandbox destination has no parent directory".to_string())
    })?;
    ensure_sandbox_free_space(parent, expected_len)?;

    let mut input = fs::File::open(source).map_err(SandboxError::Io)?;
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(SandboxError::Io)?;
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    let rate_limit = sandbox_copy_rate_limit_bytes_per_sec();
    let started = Instant::now();
    let mut copied = 0u64;
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return Err(SandboxError::Cancelled);
        }
        let read = input.read(&mut buffer).map_err(SandboxError::Io)?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(SandboxError::Io)?;
        copied = copied.saturating_add(read as u64);
        if let Some(bytes_per_sec) = rate_limit.filter(|value| *value > 0) {
            let expected_elapsed = Duration::from_secs_f64(copied as f64 / bytes_per_sec as f64);
            if expected_elapsed > started.elapsed() {
                thread::sleep(
                    (expected_elapsed - started.elapsed()).min(Duration::from_millis(250)),
                );
            }
        }
    }
    output.flush().map_err(SandboxError::Io)?;
    if copied != expected_len {
        return Err(SandboxError::Spawn(format!(
            "staged sample size changed during copy: expected={} copied={}",
            expected_len, copied
        )));
    }
    Ok(())
}

#[cfg(target_family = "windows")]
#[derive(Default)]
struct LocalTelemetryReport {
    api_calls: Vec<String>,
    registry_writes: Vec<String>,
    network_connections: Vec<String>,
}

#[cfg(target_family = "windows")]
struct LocalTelemetrySession {
    stop: Arc<AtomicBool>,
    events: Arc<Mutex<Vec<String>>>,
    registry_writes: Arc<Mutex<Vec<String>>>,
    network_connections: Arc<Mutex<Vec<String>>>,
    worker: Option<thread::JoinHandle<()>>,
}

#[cfg(target_family = "windows")]
impl LocalTelemetrySession {
    fn start(target_pid: u32, snapshot_trigger: Arc<AtomicBool>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::new()));
        let registry_writes = Arc::new(Mutex::new(Vec::new()));
        let network_connections = Arc::new(Mutex::new(Vec::new()));
        let worker_stop = stop.clone();
        let worker_events = events.clone();
        let worker_registry = registry_writes.clone();
        let worker_network = network_connections.clone();
        let worker_trigger = snapshot_trigger.clone();
        let worker = thread::spawn(move || {
            collect_local_etw_events(
                target_pid,
                worker_events,
                worker_registry,
                worker_network,
                worker_stop,
                worker_trigger,
            );
        });
        Self {
            stop,
            events,
            registry_writes,
            network_connections,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> LocalTelemetryReport {
        self.stop.store(true, Ordering::SeqCst);
        let mut api_calls = Vec::new();
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                api_calls.push("etw:collector_join_failed".to_string());
            }
        }
        let raw_events = self
            .events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default();
        let raw_target_events = raw_events
            .iter()
            .filter(|event| event.starts_with("etw:event "))
            .count();
        if raw_target_events > 0 {
            api_calls.push(format!("telemetry:etw_target_events:{raw_target_events}"));
        } else if raw_events
            .iter()
            .any(|event| event == "etw:session_started")
        {
            api_calls.push("telemetry:etw_no_target_events".to_string());
        }
        api_calls.extend(raw_events.into_iter().take(128));
        let registry_writes = self
            .registry_writes
            .lock()
            .map(|values| values.clone())
            .unwrap_or_default();
        let network_connections = self
            .network_connections
            .lock()
            .map(|values| values.clone())
            .unwrap_or_default();
        if !registry_writes.is_empty() {
            api_calls.push(format!(
                "telemetry:registry_writes_decoded:{}",
                registry_writes.len()
            ));
        }
        if !network_connections.is_empty() {
            api_calls.push(format!(
                "telemetry:network_connections_decoded:{}",
                network_connections.len()
            ));
        }
        LocalTelemetryReport {
            api_calls,
            registry_writes,
            network_connections,
        }
    }
}

#[cfg(target_family = "windows")]
struct EtwCallbackContext {
    target_pid: u32,
    events: Arc<Mutex<Vec<String>>>,
    registry_writes: Arc<Mutex<Vec<String>>>,
    network_connections: Arc<Mutex<Vec<String>>>,
    snapshot_trigger: Arc<AtomicBool>,
}

#[cfg(target_family = "windows")]
fn collect_local_etw_events(
    target_pid: u32,
    events: Arc<Mutex<Vec<String>>>,
    registry_writes: Arc<Mutex<Vec<String>>>,
    network_connections: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    snapshot_trigger: Arc<AtomicBool>,
) {
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Diagnostics::Etw::{
        CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE,
        EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_FILE_IO, EVENT_TRACE_FLAG_NETWORK_TCPIP,
        EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_FLAG_REGISTRY, EVENT_TRACE_LOGFILEW,
        EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE,
        PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    };

    unsafe {
        let session_name = format!("EverbloomSecuritySandboxSession{target_pid}\0")
            .encode_utf16()
            .collect::<Vec<_>>();
        let mut properties: EVENT_TRACE_PROPERTIES = std::mem::zeroed();
        properties.Wnode.BufferSize = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        properties.EnableFlags = EVENT_TRACE_FLAG_PROCESS
            | EVENT_TRACE_FLAG_FILE_IO
            | EVENT_TRACE_FLAG_NETWORK_TCPIP
            | EVENT_TRACE_FLAG_REGISTRY;

        let mut session_handle: CONTROLTRACE_HANDLE = std::mem::zeroed();
        let status = StartTraceW(&mut session_handle, session_name.as_ptr(), &mut properties);
        if status != ERROR_SUCCESS {
            if let Ok(mut guard) = events.lock() {
                guard.push(format!("etw:start_failed:{status}"));
            }
            return;
        }

        if let Ok(mut guard) = events.lock() {
            guard.push("etw:session_started".to_string());
        }

        let context = Arc::new(EtwCallbackContext {
            target_pid,
            events: events.clone(),
            registry_writes,
            network_connections,
            snapshot_trigger,
        });
        let raw_context = Arc::into_raw(context.clone()) as usize;
        let mut log = std::mem::zeroed::<EVENT_TRACE_LOGFILEW>();
        log.LoggerName = session_name.as_ptr() as _;
        log.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log.Anonymous2.EventRecordCallback = Some(local_etw_event_record_callback);
        log.Context = raw_context as *mut core::ffi::c_void;

        let trace_handle = OpenTraceW(&mut log);
        if trace_handle.Value == 0 {
            drop(Arc::from_raw(raw_context as *const EtwCallbackContext));
            let _ = ControlTraceW(
                session_handle,
                session_name.as_ptr(),
                &mut properties,
                EVENT_TRACE_CONTROL_STOP,
            );
            if let Ok(mut guard) = events.lock() {
                guard.push("etw:open_trace_failed".to_string());
            }
            return;
        }

        let process_worker = thread::spawn(move || {
            let handles: [PROCESSTRACE_HANDLE; 1] = [trace_handle];
            let status = ProcessTrace(handles.as_ptr(), 1, ptr::null_mut(), ptr::null_mut());
            if status != ERROR_SUCCESS {
                let context = &*(raw_context as *const EtwCallbackContext);
                if let Ok(mut guard) = context.events.lock() {
                    guard.push(format!("etw:process_trace_failed:{status}"));
                }
            }
            let _ = CloseTrace(trace_handle);
            drop(Arc::from_raw(raw_context as *const EtwCallbackContext));
        });

        while !stop.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
        }

        let _ = ControlTraceW(
            session_handle,
            session_name.as_ptr(),
            &mut properties,
            EVENT_TRACE_CONTROL_STOP,
        );
        let _ = process_worker.join();
        if let Ok(mut guard) = events.lock() {
            guard.push("etw:session_stopped".to_string());
        }
    }
}

#[cfg(target_family = "windows")]
unsafe extern "system" fn local_etw_event_record_callback(
    record: *mut windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD,
) {
    if record.is_null() {
        return;
    }
    let context = (*record).UserContext as *const EtwCallbackContext;
    if context.is_null() {
        return;
    }
    let context = &*context;
    let header = &(*record).EventHeader;
    // Kernel network events are often attributed to the System process in the
    // header; the real socket owner lives in the first payload field. Registry
    // and process events keep the header PID.
    if header.ProcessId != context.target_pid {
        let payload_owns =
            is_kernel_network_provider(&header.ProviderId) && (*record).UserDataLength >= 4
                && !(*record).UserData.is_null();
        if !payload_owns {
            return;
        }
        let pid_bytes = unsafe {
            std::slice::from_raw_parts((*record).UserData as *const u8, 4)
        };
        let pid_bytes: [u8; 4] = pid_bytes.try_into().unwrap_or([0u8; 4]);
        if u32::from_le_bytes(pid_bytes) != context.target_pid {
            return;
        }
    }
    let descriptor = header.EventDescriptor;
    let entry = format!(
        "etw:event pid={} tid={} provider={} id={} opcode={} flags={}",
        header.ProcessId,
        header.ThreadId,
        format_guid(&header.ProviderId),
        descriptor.Id,
        descriptor.Opcode,
        header.Flags
    );
    if let Ok(mut guard) = context.events.lock() {
        guard.push(entry);
        let len = guard.len();
        if len > 256 {
            guard.drain(..len - 256);
        }
    }

    // Decode classic kernel-logger payloads in place so registry writes and
    // network tuples stop being dropped on the floor. Both decoders run strict
    // bounds/format validation: malformed or mis-identified payloads produce
    // nothing instead of a guessed value.
    let payload = if !(*record).UserData.is_null() && (*record).UserDataLength > 0 {
        let length = (*record).UserDataLength as usize;
        let base = (*record).UserData as *const u8;
        std::slice::from_raw_parts(base, length)
    } else {
        &[]
    };
    if payload.is_empty() {
        // ETW records are used as a low-cost trigger. The memory collector owns
        // its own rate limit and budget, so bursts of events collapse into one
        // bounded snapshot rather than creating an unbounded work queue.
        context.snapshot_trigger.store(true, Ordering::Release);
        return;
    }
    let provider = &header.ProviderId;
    if is_registry_provider(provider) {
        if let Some(key) = decode_registry_key(payload, descriptor.Id as u32) {
            if let Ok(mut guard) = context.registry_writes.lock() {
                if !guard.iter().any(|existing| existing == &key) && guard.len() < 128 {
                    guard.push(key);
                }
            }
        }
    } else if is_kernel_network_provider(provider)
        && is_network_event_id(descriptor.Id)
    {
        if let Some(connection) = decode_network_connection(payload, descriptor.Id as u16) {
            if let Ok(mut guard) = context.network_connections.lock() {
                if !guard.iter().any(|existing| existing == &connection)
                    && guard.len() < 128
                {
                    guard.push(connection);
                }
            }
        }
    }
    // ETW records are used as a low-cost trigger. The memory collector owns
    // its own rate limit and budget, so bursts of events collapse into one
    // bounded snapshot rather than creating an unbounded work queue.
    context.snapshot_trigger.store(true, Ordering::Release);
}

#[cfg(target_family = "windows")]
fn format_guid(guid: &windows_sys::core::GUID) -> String {
    let data4 = guid.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        data4[0],
        data4[1],
        data4[2],
        data4[3],
        data4[4],
        data4[5],
        data4[6],
        data4[7]
    )
}

/// Registry kernel-logger MOF class GUID {AE53722E-C863-11D2-8659-00C04FA321A1}.
#[cfg(target_family = "windows")]
fn is_registry_provider(guid: &windows_sys::core::GUID) -> bool {
    guid.data1 == 0xae53722e
        && guid.data2 == 0xc863
        && guid.data3 == 0x11d2
        && guid.data4 == [0x86, 0x59, 0x00, 0xc0, 0x4f, 0xa3, 0x21, 0xa1]
}

/// Microsoft-Windows-Kernel-Network provider GUID
/// {9D55B53D-449B-4DBC-BCE2-BA69F4B2FF38}, the source of NETWORK_TCPIP events
/// on modern Windows.
#[cfg(target_family = "windows")]
fn is_kernel_network_provider(guid: &windows_sys::core::GUID) -> bool {
    guid.data1 == 0x9d55b53d
        && guid.data2 == 0x449b
        && guid.data3 == 0x4dbc
        && guid.data4 == [0xbc, 0xe2, 0xba, 0x69, 0xf4, 0xb2, 0xff, 0x38]
}

/// Registry write/delete operations that justify a rollback entry. Pure opens
/// (11), closes (27) and handle-based creates (22) are excluded so rollback
/// never tries to undo a key the sample merely read.
#[cfg(target_family = "windows")]
fn is_registry_write_opcode(opcode: u32) -> bool {
    matches!(opcode, 10 | 12 | 14 | 15 | 20 | 23)
}

/// Kernel event codes for network data at various points in a connection
/// lifetime. 10..=18 are IPv4, 26..=33 are IPv6.
#[cfg(target_family = "windows")]
fn is_network_event_id(id: u16) -> bool {
    matches!(id, 10..=18 | 26..=33)
}

/// Decode a Registry_TypeGroup1 payload into a normalized key path. The modern
/// layout starts with an 8-byte InitialTime, a Status/Index/KeyHandle triplet,
/// then a MOF UNICODE_STRING at offset 20 whose data follows inline. Offsets
/// and string shape are validated before anything is returned.
#[cfg(target_family = "windows")]
fn decode_registry_key(payload: &[u8], opcode: u32) -> Option<String> {
    if !is_registry_write_opcode(opcode) || payload.len() < 32 {
        return None;
    }
    // InitialTime is a 100ns clock value since 1601 (~1.3e17); a small first
    // DWORD here means a legacy layout we do not attempt to parse.
    let initial_time = u64::from_le_bytes(payload[0..8].try_into().ok()?);
    if initial_time < (1u64 << 40) {
        return None;
    }
    let length = u16::from_le_bytes(payload[20..22].try_into().ok()?);
    let max_length = u16::from_le_bytes(payload[22..24].try_into().ok()?);
    if length == 0 || length > max_length || length > 1024 || length % 2 != 0 {
        return None;
    }
    let length = length as usize;
    // The key string is emitted inline right after the UNICODE_STRING struct.
    let key_offset = 32usize;
    if key_offset + length > payload.len() {
        return None;
    }
    let raw = &payload[key_offset..key_offset + length];
    let mut units = Vec::with_capacity(length / 2);
    for chunk in raw.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16(&units).ok().filter(|key| is_key_plausible(key))
}

/// Reject strings that were never Unicode key data: require a printable
/// character set and reject control/empty content.
#[cfg(target_family = "windows")]
fn is_key_plausible(key: &str) -> bool {
    if key.is_empty() || key.len() > 512 {
        return false;
    }
    let printable = key
        .chars()
        .filter(|ch| {
            ch.is_ascii_graphic()
                || ch.is_ascii_whitespace()
                || *ch == '\\'
                || *ch == ':'
                || ch.is_ascii_alphanumeric()
        })
        .count();
    printable as f32 / key.chars().count() as f32 >= 0.7
}

/// Decode an IPv4/IPv6 network data event into a normalized connection tuple.
/// Layout (packed, little-endian): PID u32@0, size u32@4, dest addr, source
/// addr, dest port u16, source port u16 — addresses differ by family; ports
/// are network (big-endian) byte order.
#[cfg(target_family = "windows")]
fn decode_network_connection(payload: &[u8], id: u16) -> Option<String> {
    let (dest, source, min_len) = if id <= 18 {
        (
            payload.get(8..12)?,
            payload.get(12..16)?,
            20usize,
        )
    } else {
        (
            payload.get(8..24)?,
            payload.get(24..40)?,
            44usize,
        )
    };
    if payload.len() < min_len {
        return None;
    }
    if dest.iter().all(|byte| *byte == 0) && source.iter().all(|byte| *byte == 0) {
        return None;
    }
    let dest_port = u16::from_be_bytes(payload.get(16..18)?.try_into().ok()?);
    let source_port = u16::from_be_bytes(payload.get(18..20)?.try_into().ok()?);
    if dest_port == 0 || source_port == 0 {
        return None;
    }
    let dest_text = if id <= 18 {
        format!(
            "{}.{}.{}.{}",
            dest[0], dest[1], dest[2], dest[3]
        )
    } else {
        format_ipv6(dest)
    };
    Some(format!("{dest_text}:{dest_port}"))
}

/// Compact RFC-5952-style IPv6 formatting (longest all-zero group run of two
/// or more elided with "::", otherwise plain colon-joined hex).
#[cfg(target_family = "windows")]
fn format_ipv6(address: &[u8]) -> String {
    let groups: Vec<u16> = address
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    let mut best_start = groups.len();
    let mut best_len = 0usize;
    let mut index = 0usize;
    while index < groups.len() {
        if groups[index] == 0 {
            let start = index;
            while index < groups.len() && groups[index] == 0 {
                index += 1;
            }
            let len = index - start;
            if len >= 2 && len > best_len {
                best_start = start;
                best_len = len;
            }
        } else {
            index += 1;
        }
    }
    let mut result = String::new();
    let mut cursor = 0usize;
    while cursor < groups.len() {
        if cursor == best_start && best_len >= 2 {
            result.push_str("::");
            cursor += best_len;
        } else {
            if !result.is_empty() && !result.ends_with(':') {
                result.push(':');
            }
            result.push_str(&format!("{:x}", groups[cursor]));
            cursor += 1;
        }
    }
    result
}

#[cfg(target_family = "windows")]
#[cfg(test)]
mod etw_decode_tests {
    use super::*;

    fn registry_payload(key: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        let byte_length = key.encode_utf16().count() * 2;
        payload.extend_from_slice(&(1u64 << 48).to_le_bytes());
        payload.extend_from_slice(&[0u8; 12]);
        payload.extend_from_slice(&(byte_length as u16).to_le_bytes());
        payload.extend_from_slice(&(byte_length as u16).to_le_bytes());
        payload.extend_from_slice(&[0u8; 8]);
        for unit in key.encode_utf16() {
            payload.extend_from_slice(&unit.to_le_bytes());
        }
        payload
    }

    #[test]
    fn decodes_registry_set_value_key() {
        let payload = registry_payload(
            "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        );
        let key = decode_registry_key(&payload, 14).unwrap();
        assert!(key.contains("CurrentVersion\\Run"));
    }

    #[test]
    fn rejects_open_key_events() {
        let payload = registry_payload("\\Registry\\Machine\\SOFTWARE");
        assert!(decode_registry_key(&payload, 11).is_none());
    }

    #[test]
    fn rejects_short_payloads() {
        assert!(decode_registry_key(&[0u8; 16], 14).is_none());
    }

    #[test]
    fn decodes_ipv4_connection() {
        let mut payload = vec![0u8; 24];
        payload[0..4].copy_from_slice(&1001u32.to_le_bytes());
        payload[4..8].copy_from_slice(&(-1i32 as u32).to_le_bytes());
        payload[8..12].copy_from_slice(&[9, 9, 9, 9]);
        payload[12..16].copy_from_slice(&[192, 168, 1, 40]);
        payload[16..18].copy_from_slice(&443u16.to_be_bytes());
        payload[18..20].copy_from_slice(&49152u16.to_be_bytes());
        let connection = decode_network_connection(&payload, 10).unwrap();
        assert_eq!(connection, "9.9.9.9:443");
    }

    #[test]
    fn rejects_zero_address_connections() {
        let payload = vec![0u8; 24];
        assert!(decode_network_connection(&payload, 10).is_none());
    }

    #[test]
    fn rejects_short_network_payload() {
        let payload = vec![0u8; 16];
        assert!(decode_network_connection(&payload, 10).is_none());
    }

    #[test]
    fn formats_ipv6_compactly() {
        let mut address = [0u8; 16];
        address[0] = 0x20;
        address[1] = 0x01;
        address[14] = 0x12;
        address[15] = 0x34;
        let text = format_ipv6(&address);
        assert_eq!(text, "2001::1234");
    }

    #[test]
    fn formats_ipv6_leading_zero_run() {
        let mut address = [0u8; 16];
        address[14] = 0xab;
        address[15] = 0x01;
        assert_eq!(format_ipv6(&address), "::ab01");
    }
}

#[cfg(target_family = "windows")]
fn run_local_sandbox(
    target: PathBuf,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<SandboxReport, LocalSandboxError> {
    let packer = static_packer_family(&target);
    let strong_packer_hint = matches!(
        packer,
        Some(crate::layers::unpacking::PackerFamily::Themida
            | crate::layers::unpacking::PackerFamily::VmProtect)
    );
    let first = run_local_sandbox_once(target.clone(), timeout, cancelled)?;
    // Replay with a doubled budget when the first pass was cut short, or when
    // a packer was recognized up-front but the run produced no memory image
    // yet (packed stages commonly unfold late). The static prior makes the
    // replay decision independent of what the sample already leaked early.
    let should_replay = first.timed_out
        || (packer.is_some() && first.unpacking.candidate_images == 0);
    let replay_timeout = timeout.saturating_mul(2).min(MAX_TIMEOUT);
    if !should_replay || replay_timeout <= timeout || cancelled.load(Ordering::Relaxed) {
        return Ok(first);
    }

    log::info!(
        "SANDBOX_ADAPTIVE_REPLAY backend=appcontainer target={} first_timeout_ms={} replay_timeout_ms={} strong_packer_hint={}",
        target.display(),
        timeout.as_millis(),
        replay_timeout.as_millis(),
        strong_packer_hint
    );
    match run_local_sandbox_once(target, replay_timeout, cancelled) {
        Ok(second) => Ok(merge_adaptive_reports(first, second)),
        Err(LocalSandboxError::Unavailable(reason)) => {
            log::warn!("SANDBOX_ADAPTIVE_REPLAY_UNAVAILABLE reason={reason}");
            Ok(first)
        }
        Err(LocalSandboxError::Failed(error)) => {
            log::warn!("SANDBOX_ADAPTIVE_REPLAY_FAILED error={error}");
            Ok(first)
        }
    }
}

#[cfg(target_family = "windows")]
fn run_local_sandbox_once(
    target: PathBuf,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<SandboxReport, LocalSandboxError> {
    use tempfile::Builder;

    let _single_session = WINDOWS_SANDBOX_LOCK.lock().map_err(|_| {
        LocalSandboxError::Unavailable("sandbox session lock was poisoned".to_string())
    })?;
    let target = target
        .canonicalize()
        .map_err(SandboxError::Io)
        .map_err(LocalSandboxError::Failed)?;
    let metadata = fs::metadata(&target)
        .map_err(SandboxError::Io)
        .map_err(LocalSandboxError::Failed)?;
    if !metadata.is_file() {
        return Err(LocalSandboxError::Failed(SandboxError::UnsupportedTarget(
            "the selected target is not a regular file".to_string(),
        )));
    }
    if metadata.len() > MAX_SAMPLE_SIZE {
        return Err(LocalSandboxError::Failed(SandboxError::UnsupportedTarget(
            format!(
                "sample exceeds the {} MiB safety limit",
                MAX_SAMPLE_SIZE / 1024 / 1024
            ),
        )));
    }
    let extension = supported_extension(&target).map_err(LocalSandboxError::Failed)?;
    if !matches!(extension.as_str(), "exe" | "com" | "scr") {
        return Err(LocalSandboxError::Unavailable(
            "the local AppContainer backend only accepts PE executable targets".to_string(),
        ));
    }

    let mut profile = AppContainerProfile::create().map_err(LocalSandboxError::Unavailable)?;
    let session = Builder::new()
        .prefix("everbloom-local-")
        .tempdir_in(&profile.folder)
        .map_err(|error| {
            LocalSandboxError::Unavailable(format!("AppContainer storage is unavailable: {error}"))
        })?;
    let isolated_sample = session.path().join(format!("sample.{extension}"));
    copy_sample_to_sandbox(&target, &isolated_sample, metadata.len(), cancelled)
        .map_err(LocalSandboxError::Failed)?;
    let staged_metadata = fs::metadata(&isolated_sample)
        .map_err(SandboxError::Io)
        .map_err(LocalSandboxError::Failed)?;
    if staged_metadata.len() != metadata.len() {
        return Err(LocalSandboxError::Failed(SandboxError::Spawn(
            "staged sample size changed during copy".to_string(),
        )));
    }
    let mut permissions = staged_metadata.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&isolated_sample, permissions)
        .map_err(SandboxError::Io)
        .map_err(LocalSandboxError::Failed)?;
    let decoy_files =
        stage_decoy_surface(session.path()).map_err(LocalSandboxError::Unavailable)?;
    let baseline_snapshot =
        snapshot_local_tree(session.path()).map_err(LocalSandboxError::Unavailable)?;

    let restricted_token = RestrictedToken::create().map_err(LocalSandboxError::Unavailable)?;
    let job = LocalJob::create().map_err(LocalSandboxError::Unavailable)?;
    let process = create_local_process(
        &restricted_token,
        &profile,
        &job,
        &isolated_sample,
        session.path(),
    )
    .map_err(LocalSandboxError::Unavailable)?;
    log::info!(
        "SANDBOX_CHILD_STARTED backend=appcontainer pid={} target={}",
        process.pid,
        target.display()
    );
    let start = Instant::now();
    let effective_timeout = timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT);
    let snapshot_trigger = Arc::new(AtomicBool::new(false));
    let telemetry = LocalTelemetrySession::start(process.pid, snapshot_trigger.clone());
    // The collector only receives the AppContainer process handle. It is
    // stopped and joined before that handle is released, so it cannot read a
    // stale process handle or outlive the disposable sandbox session.
    let memory_collector = MemorySnapshotCollector::start(
        process.process.raw(),
        process.pid,
        snapshot_trigger,
        effective_timeout.as_millis() as u64,
    );
    let (exit_code, timed_out, was_cancelled) =
        wait_local_process(&process, &job, effective_timeout, cancelled)
            .map_err(|error| LocalSandboxError::Failed(SandboxError::Spawn(error)))?;
    let target_pid = process.pid;
    let unpacking = memory_collector.finish();
    log::info!(
        "UNPACKING_RECOVERY backend=appcontainer pid={} status={} candidates={} recovered_entry_points={} observed_execution_points={} rounds={} triggered_snapshots={} bytes={} truncated={}",
        target_pid,
        unpacking.status,
        unpacking.candidate_images,
        unpacking.recovered_entry_points,
        unpacking.observed_execution_points,
        unpacking.snapshot_rounds,
        unpacking.triggered_snapshots,
        unpacking.bytes_captured,
        unpacking.truncated
    );
    let files_changed = snapshot_local_tree(session.path())
        .map(|after| diff_local_tree(session.path(), &baseline_snapshot, &after))
        .map_err(LocalSandboxError::Unavailable)?;
    let decoy_modifications = detect_decoy_modifications(&decoy_files, &files_changed);
    let mut api_calls = vec![
        "isolation:appcontainer".to_string(),
        "isolation:restricted_token".to_string(),
        "isolation:job_object".to_string(),
        "isolation:no_inherited_handles".to_string(),
        "network:appcontainer_no_capability".to_string(),
        "host_mapping:appcontainer_profile".to_string(),
        "monitor:filesystem_snapshot".to_string(),
        "monitor:decoy_surface".to_string(),
    ];
    for indicator in detect_anti_sandbox_indicators(&target) {
        api_calls.push(format!("anti_sandbox:{indicator}"));
    }
    if timed_out {
        api_calls.push("execution:timeout".to_string());
    }
    if let Some(code) = exit_code {
        if code != 0 {
            api_calls.push(format!("execution:exit_code:{code}"));
        }
    }
    api_calls.push(format!("unpacking:status:{}", unpacking.status));
    if unpacking.candidate_images > 0 {
        api_calls.push("unpacking:memory_pe_candidate".to_string());
    }
    if unpacking.recovered_entry_points > 0 {
        api_calls.push("unpacking:entry_point_recovered_candidate".to_string());
    }
    if unpacking.observed_execution_points > 0 {
        api_calls.push("unpacking:thread_ip_correlated".to_string());
    }
    if unpacking.truncated {
        api_calls.push("unpacking:memory_snapshot_truncated".to_string());
    }
    let telemetry_report = telemetry.finish();
    api_calls.extend(telemetry_report.api_calls);
    let registry_writes = telemetry_report.registry_writes;
    let network_connections = telemetry_report.network_connections;
    api_calls.extend(decoy_modifications);
    drop(process);
    drop(job);
    drop(restricted_token);

    session.close().map_err(|error| {
        LocalSandboxError::Failed(SandboxError::Spawn(format!(
            "local sandbox temporary storage cleanup failed: {error}"
        )))
    })?;
    profile.cleanup().map_err(|error| {
        LocalSandboxError::Failed(SandboxError::Spawn(format!(
            "local AppContainer profile cleanup failed: {error}"
        )))
    })?;

    if was_cancelled {
        return Err(LocalSandboxError::Failed(SandboxError::Cancelled));
    }

    Ok(SandboxReport {
        target,
        exit_code,
        target_pid: Some(target_pid),
        files_changed,
        registry_writes,
        network_connections,
        processes: vec!["isolation:windows_appcontainer".to_string()],
        api_calls,
        timed_out,
        isolation_backend: "windows_appcontainer_job".to_string(),
        isolation_verified: true,
        cleanup_verified: true,
        resource_limits: vec![
            "memory_mb:1024_process".to_string(),
            "memory_mb:2048_job".to_string(),
            "active_processes:32".to_string(),
            format!("timeout_ms:{}", effective_timeout.as_millis()),
            "network:no_capability".to_string(),
            "token:restricted_no_privileges".to_string(),
            "job:kill_on_close".to_string(),
            "ui:desktop_clipboard_handles_restricted".to_string(),
            "decoy_surface:documents_browser_wallet_messenger".to_string(),
            "unpacking:memory_snapshot_max_mb:32".to_string(),
            "unpacking:max_executable_regions:96".to_string(),
        ],
        unpacking,
        duration_ms: start.elapsed().as_millis(),
    })
}

#[cfg(target_family = "windows")]
fn static_packer_family(target: &Path) -> Option<crate::layers::unpacking::PackerFamily> {
    use crate::layers::unpacking::assess_unpacking;

    let Ok(mut file) = fs::File::open(target) else {
        return None;
    };
    let mut bytes = Vec::new();
    if std::io::Read::by_ref(&mut file)
        .take(8 * 1024 * 1024)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return None;
    }
    assess_unpacking(&bytes).packer
}

#[cfg(target_family = "windows")]
fn merge_adaptive_reports(mut first: SandboxReport, mut second: SandboxReport) -> SandboxReport {
    let mut files_changed = first.files_changed;
    for path in second.files_changed.drain(..) {
        if !files_changed.contains(&path) {
            files_changed.push(path);
        }
    }
    let mut registry_writes = first.registry_writes;
    for value in second.registry_writes.drain(..) {
        if !registry_writes.contains(&value) {
            registry_writes.push(value);
        }
    }
    let mut network_connections = first.network_connections;
    for value in second.network_connections.drain(..) {
        if !network_connections.contains(&value) {
            network_connections.push(value);
        }
    }
    let mut api_calls = first.api_calls;
    for value in second.api_calls.drain(..) {
        if !api_calls.contains(&value) {
            api_calls.push(value);
        }
    }
    api_calls.push("unpacking:adaptive_replay:2".to_string());

    let mut candidates = first.unpacking.candidates;
    for candidate in second.unpacking.candidates.drain(..) {
        if !candidates.iter().any(|existing| {
            existing.region_base == candidate.region_base
                && existing.entry_point_address == candidate.entry_point_address
        }) {
            candidates.push(candidate);
        }
    }
    let recovered_entry_points = first
        .unpacking
        .recovered_entry_points
        .saturating_add(second.unpacking.recovered_entry_points);
    let candidate_images = candidates.len() as u32;
    let mut notes = first.unpacking.notes;
    notes.extend(second.unpacking.notes);
    notes.push("adaptive_replay_completed".to_string());
    let unpacking = SandboxUnpackingReport {
        status: if recovered_entry_points > 0 {
            "recovered_candidate".to_string()
        } else if candidate_images > 0 {
            "candidate".to_string()
        } else {
            "no_candidate".to_string()
        },
        regions_scanned: first
            .unpacking
            .regions_scanned
            .saturating_add(second.unpacking.regions_scanned),
        executable_regions: first
            .unpacking
            .executable_regions
            .saturating_add(second.unpacking.executable_regions),
        candidate_images,
        recovered_entry_points,
        observed_execution_points: first
            .unpacking
            .observed_execution_points
            .saturating_add(second.unpacking.observed_execution_points),
        snapshot_rounds: first
            .unpacking
            .snapshot_rounds
            .saturating_add(second.unpacking.snapshot_rounds),
        triggered_snapshots: first
            .unpacking
            .triggered_snapshots
            .saturating_add(second.unpacking.triggered_snapshots),
        adaptive_timeout_ms: first
            .unpacking
            .adaptive_timeout_ms
            .max(second.unpacking.adaptive_timeout_ms),
        bytes_captured: first
            .unpacking
            .bytes_captured
            .saturating_add(second.unpacking.bytes_captured),
        truncated: first.unpacking.truncated || second.unpacking.truncated,
        confidence: first.unpacking.confidence.max(second.unpacking.confidence),
        candidates,
        notes,
    };
    first.files_changed = files_changed;
    first.registry_writes = registry_writes;
    first.network_connections = network_connections;
    first.api_calls = api_calls;
    first.processes.extend(second.processes);
    first.exit_code = second.exit_code.or(first.exit_code);
    first.timed_out = second.timed_out;
    first.isolation_verified &= second.isolation_verified;
    first.cleanup_verified &= second.cleanup_verified;
    first.resource_limits.extend(second.resource_limits);
    first
        .resource_limits
        .push("unpacking:adaptive_replay_runs:2".to_string());
    first.unpacking = unpacking;
    first.duration_ms = first.duration_ms.saturating_add(second.duration_ms);
    first
}

#[cfg(target_family = "windows")]
struct OwnedHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(target_family = "windows")]
impl OwnedHandle {
    fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.0
    }
}

#[cfg(target_family = "windows")]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

#[cfg(target_family = "windows")]
struct AppContainerProfile {
    name: Vec<u16>,
    sid: windows_sys::Win32::Security::PSID,
    folder: PathBuf,
    cleaned: bool,
}

#[cfg(target_family = "windows")]
impl AppContainerProfile {
    fn create() -> Result<Self, String> {
        use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::Isolation::CreateAppContainerProfile;
        use windows_sys::Win32::Security::Isolation::GetAppContainerFolderPath;
        use windows_sys::Win32::System::Com::CoTaskMemFree;

        // The profile is disposable and the local backend is serialized by
        // WINDOWS_SANDBOX_LOCK. Reusing one process-scoped slot prevents a
        // long-running service from creating an unbounded sequence of
        // AppContainer profiles when a previous cleanup was interrupted.
        let name = to_wide_str(&format!("EverbloomSecurity.Sandbox.{}", std::process::id()));
        let display_name = to_wide_str("EverbloomSecurity local sandbox");
        let description = to_wide_str("Disposable restricted execution container");
        let mut sid = null_mut();
        // A crashed previous scan can leave this owned profile behind. The
        // name contains the current PID, so no other live process can own the
        // same slot; remove it before recreating the disposable profile.
        unsafe {
            let _ =
                windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile(name.as_ptr());
        }
        let result = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                display_name.as_ptr(),
                description.as_ptr(),
                null_mut(),
                0,
                &mut sid,
            )
        };
        if result < 0 || sid.is_null() {
            return Err(format!(
                "CreateAppContainerProfile failed: HRESULT 0x{result:08x}"
            ));
        }

        let mut sid_string_ptr = null_mut();
        let converted = unsafe { ConvertSidToStringSidW(sid, &mut sid_string_ptr) } != 0;
        if !converted || sid_string_ptr.is_null() {
            unsafe {
                windows_sys::Win32::Security::FreeSid(sid);
            }
            return Err("ConvertSidToStringSidW failed".to_string());
        }
        let sid_string = unsafe { read_wide_ptr(sid_string_ptr) };
        unsafe {
            LocalFree(sid_string_ptr.cast::<core::ffi::c_void>() as HLOCAL);
        }
        let sid_string_wide = to_wide_str(&sid_string);

        let mut folder_ptr = null_mut();
        let folder_result =
            unsafe { GetAppContainerFolderPath(sid_string_wide.as_ptr(), &mut folder_ptr) };
        if folder_result < 0 || folder_ptr.is_null() {
            unsafe {
                windows_sys::Win32::Security::FreeSid(sid);
            }
            return Err(format!(
                "GetAppContainerFolderPath failed: HRESULT 0x{folder_result:08x}"
            ));
        }
        let folder = unsafe { PathBuf::from(read_wide_ptr(folder_ptr)) };
        unsafe {
            CoTaskMemFree(folder_ptr.cast::<core::ffi::c_void>());
        }
        if folder.as_os_str().is_empty() {
            unsafe {
                windows_sys::Win32::Security::FreeSid(sid);
            }
            return Err("AppContainer folder path is empty".to_string());
        }

        record_appcontainer_profile(&name);

        Ok(Self {
            name,
            sid,
            folder,
            cleaned: false,
        })
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if self.cleaned {
            return Ok(());
        }
        let result = unsafe {
            windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile(self.name.as_ptr())
        };
        if result < 0 {
            return Err(format!(
                "DeleteAppContainerProfile failed: HRESULT 0x{result:08x}"
            ));
        }
        unsafe {
            windows_sys::Win32::Security::FreeSid(self.sid);
        }
        remove_appcontainer_profile_record(&self.name);
        self.cleaned = true;
        Ok(())
    }
}

#[cfg(target_family = "windows")]
impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        if !self.cleaned {
            unsafe {
                windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile(
                    self.name.as_ptr(),
                );
                windows_sys::Win32::Security::FreeSid(self.sid);
            }
            remove_appcontainer_profile_record(&self.name);
        }
    }
}

#[cfg(target_family = "windows")]
struct RestrictedToken(OwnedHandle);

#[cfg(target_family = "windows")]
impl RestrictedToken {
    fn create() -> Result<Self, String> {
        use windows_sys::Win32::Security::{
            CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, TOKEN_DUPLICATE, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut current_token = null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY,
                &mut current_token,
            )
        } == 0
        {
            return Err(format!("OpenProcessToken failed: win32={}", unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }));
        }
        let current_token = OwnedHandle(current_token);
        let mut restricted_token = null_mut();
        if unsafe {
            CreateRestrictedToken(
                current_token.raw(),
                DISABLE_MAX_PRIVILEGE,
                0,
                null_mut(),
                0,
                null_mut(),
                0,
                null_mut(),
                &mut restricted_token,
            )
        } == 0
        {
            return Err(format!("CreateRestrictedToken failed: win32={}", unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }));
        }

        // Drop the token to Low integrity. AppContainer processes default to
        // Low integrity, but the restriction token used with
        // CreateProcessAsUserW would otherwise keep Medium/High integrity and
        // let the sample write to user-level protected locations. Setting
        // SE_GROUP_INTEGRITY on the label makes the downgrade authoritative.
        set_token_integrity_level(restricted_token)?;
        Ok(Self(OwnedHandle(restricted_token)))
    }
}

#[cfg(target_family = "windows")]
fn set_token_integrity_level(token: *mut core::ffi::c_void) -> Result<(), String> {
    use std::mem::size_of;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, SetTokenInformation, TokenIntegrityLevel, WinLowLabelSid,
        SID_AND_ATTRIBUTES, TOKEN_MANDATORY_LABEL,
    };
    use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;

    let mut sid_buffer = [0u8; 68];
    let mut sid_length = sid_buffer.len() as u32;
    let sid = sid_buffer.as_mut_ptr() as *mut core::ffi::c_void;
    if unsafe { CreateWellKnownSid(WinLowLabelSid, null_mut(), sid, &mut sid_length) } == 0 {
        return Err(format!("CreateWellKnownSid failed: win32={}", unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    if unsafe {
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            &label as *const _ as *const core::ffi::c_void,
            (size_of::<TOKEN_MANDATORY_LABEL>() as u32 + sid_length) as u32,
        )
    } == 0
    {
        return Err(format!("SetTokenInformation(integrity) failed: win32={}", unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    Ok(())
}

#[cfg(target_family = "windows")]
struct LocalJob(OwnedHandle);

#[cfg(target_family = "windows")]
impl LocalJob {
    fn create() -> Result<Self, String> {
        use std::mem::size_of;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
            JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
            JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS,
            JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };

        let job = unsafe { CreateJobObjectW(null_mut(), null_mut()) };
        if job.is_null() {
            return Err(format!("CreateJobObjectW failed: win32={}", unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }));
        }
        let job = LocalJob(OwnedHandle(job));
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        limits.BasicLimitInformation.ActiveProcessLimit = 32;
        limits.ProcessMemoryLimit = 1024 * 1024 * 1024;
        limits.JobMemoryLimit = 2 * 1024 * 1024 * 1024;
        if unsafe {
            SetInformationJobObject(
                job.0.raw(),
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const core::ffi::c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(format!(
                "SetInformationJobObject(limits) failed: win32={}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            ));
        }

        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };
        if unsafe {
            SetInformationJobObject(
                job.0.raw(),
                JobObjectBasicUIRestrictions,
                &ui as *const _ as *const core::ffi::c_void,
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        } == 0
        {
            return Err(format!(
                "SetInformationJobObject(ui) failed: win32={}",
                unsafe { windows_sys::Win32::Foundation::GetLastError() }
            ));
        }
        Ok(job)
    }

    fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.0.raw()
    }
}

#[cfg(target_family = "windows")]
struct LocalProcess {
    process: OwnedHandle,
    pid: u32,
    /// The isolated desktop the sample was launched on. Kept alive until the
    /// process handle is released so the sample cannot hop to the interactive
    /// desktop mid-run. CloseHandle would leak the desktop object; Drop uses
    /// CloseDesktop. RAII only: never read directly.
    _desktop: IsolatedDesktop,
}

/// A dedicated desktop visible only to the sandboxed child. GUI malware gets
/// a real window station surface but has no path to the user's desktop:
/// screenshots, overlays and keyboard capture on the interactive desktop all
/// fail inside the isolated desktop.
#[cfg(target_family = "windows")]
struct IsolatedDesktop {
    handle: windows_sys::Win32::Foundation::HANDLE,
    number: u64,
    window_station: String,
}

#[cfg(target_family = "windows")]
static DESKTOP_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[cfg(target_family = "windows")]
impl IsolatedDesktop {
    fn create() -> Result<Self, String> {
        use windows_sys::Win32::System::StationsAndDesktops::CreateDesktopW;
        let number = DESKTOP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let window_station = current_window_station();
        let name = to_wide_str(&format!("EverbloomSecurity_Sandbox_{number}"));
        let handle = unsafe {
            CreateDesktopW(
                name.as_ptr(),
                null_mut(),
                null_mut(),
                0,
                windows_sys::Win32::Foundation::GENERIC_ALL as u32,
                null_mut(),
            )
        };
        if handle.is_null() {
            return Err(format!("CreateDesktopW failed: win32={}", unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }));
        }
        Ok(Self {
            handle,
            number,
            window_station,
        })
    }

    /// "WindowStation\\Desktop" path used by STARTUPINFO.lpDesktop.
    fn path(&self) -> String {
        format!(
            "{}\\EverbloomSecurity_Sandbox_{}",
            self.window_station, self.number
        )
    }
}

#[cfg(target_family = "windows")]
fn current_window_station() -> String {
    use windows_sys::Win32::System::StationsAndDesktops::{
        GetProcessWindowStation, GetUserObjectInformationW, UOI_NAME,
    };
    let station = unsafe { GetProcessWindowStation() };
    let mut needed = 0u32;
    let index = UOI_NAME;
    unsafe {
        GetUserObjectInformationW(
            station,
            index,
            null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return String::from("Winsta0");
    }
    let mut buffer = vec![0u16; needed as usize / 2 + 1];
    let mut written = 0u32;
    if unsafe {
        GetUserObjectInformationW(
            station,
            index,
            buffer.as_mut_ptr() as *mut core::ffi::c_void,
            (buffer.len() * 2) as u32,
            &mut written,
        )
    } == 0
    {
        return String::from("Winsta0");
    }
    buffer.pop(); // trailing NUL from the API
    String::from_utf16_lossy(&buffer)
}

#[cfg(target_family = "windows")]
impl Drop for IsolatedDesktop {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::StationsAndDesktops::CloseDesktop(self.handle);
        }
    }
}

#[cfg(target_family = "windows")]
fn create_local_process(
    token: &RestrictedToken,
    profile: &AppContainerProfile,
    job: &LocalJob,
    target: &Path,
    current_dir: &Path,
) -> Result<LocalProcess, String> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        ResumeThread, UpdateProcThreadAttribute, CREATE_NO_WINDOW, CREATE_SUSPENDED,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW,
    };

    let desktop = IsolatedDesktop::create().map_err(|error| {
        format!("sandbox desktop creation failed: {error}")
    })?;
    let desktop_path = to_wide_str(&desktop.path());
    let mut desktop_path = desktop_path;

    let application_name = to_wide_os(target.as_os_str());
    let mut command_line = to_wide_str(&format!(r#""{}""#, target.display()));
    let current_dir = to_wide_os(current_dir.as_os_str());
    let mut attribute_size = 0usize;
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attribute_size);
    }
    if attribute_size == 0 {
        return Err(format!(
            "InitializeProcThreadAttributeList sizing failed: win32={}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        ));
    }
    let mut attribute_storage = vec![0u8; attribute_size];
    let attribute_list = attribute_storage.as_mut_ptr().cast::<core::ffi::c_void>();
    if unsafe { InitializeProcThreadAttributeList(attribute_list, 1, 0, &mut attribute_size) } == 0
    {
        return Err(format!(
            "InitializeProcThreadAttributeList failed: win32={}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        ));
    }
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let update_result = unsafe {
        UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            &capabilities as *const _ as *const core::ffi::c_void,
            size_of::<SECURITY_CAPABILITIES>(),
            null_mut(),
            null_mut(),
        )
    };
    if update_result == 0 {
        unsafe {
            DeleteProcThreadAttributeList(attribute_list);
        }
        return Err(format!(
            "UpdateProcThreadAttribute failed: win32={}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        ));
    }

    let mut startup = unsafe { zeroed::<STARTUPINFOEXW>() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.lpDesktop = desktop_path.as_mut_ptr();
    startup.lpAttributeList = attribute_list as LPPROC_THREAD_ATTRIBUTE_LIST;
    let mut process_info = unsafe { zeroed::<PROCESS_INFORMATION>() };
    let created = unsafe {
        CreateProcessAsUserW(
            token.0.raw(),
            application_name.as_ptr(),
            command_line.as_mut_ptr(),
            null_mut(),
            null_mut(),
            FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            null_mut(),
            current_dir.as_ptr(),
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    unsafe {
        DeleteProcThreadAttributeList(attribute_list);
    }
    if created == 0 {
        return Err(format!("CreateProcessAsUserW failed: win32={}", unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }

    let process = OwnedHandle(process_info.hProcess);
    let thread = OwnedHandle(process_info.hThread);
    if unsafe {
        windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(job.raw(), process.raw())
    } == 0
    {
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(process.raw(), 1);
        }
        return Err(format!(
            "AssignProcessToJobObject failed: win32={}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        ));
    }
    if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(process.raw(), 1);
        }
        return Err(format!("ResumeThread failed: win32={}", unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    drop(thread);
    Ok(LocalProcess {
        process,
        pid: process_info.dwProcessId,
        _desktop: desktop,
    })
}

#[cfg(target_family = "windows")]
fn wait_local_process(
    process: &LocalProcess,
    job: &LocalJob,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<(Option<i32>, bool, bool), String> {
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    };

    let start = Instant::now();
    loop {
        if cancelled.load(Ordering::Relaxed) {
            log::warn!(
                "SANDBOX_CHILD_TERMINATING backend=appcontainer pid={} reason=cancelled",
                process.pid
            );
            if unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(job.raw(), 1) }
                == 0
            {
                return Err(format!(
                    "TerminateJobObject after cancellation failed: win32={}",
                    unsafe { windows_sys::Win32::Foundation::GetLastError() }
                ));
            }
            let cleanup_wait = unsafe { WaitForSingleObject(process.process.raw(), 5000) };
            if cleanup_wait != WAIT_OBJECT_0 {
                unsafe {
                    TerminateProcess(process.process.raw(), 1);
                }
            }
            return Ok((None, false, true));
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            log::warn!(
                "SANDBOX_CHILD_TERMINATING backend=appcontainer pid={} reason=timeout timeout_ms={}",
                process.pid,
                timeout.as_millis()
            );
            if unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(job.raw(), 1) }
                == 0
            {
                return Err(format!("TerminateJobObject failed: win32={}", unsafe {
                    windows_sys::Win32::Foundation::GetLastError()
                }));
            }
            let cleanup_wait = unsafe { WaitForSingleObject(process.process.raw(), 5000) };
            if cleanup_wait != WAIT_OBJECT_0 {
                unsafe {
                    TerminateProcess(process.process.raw(), 1);
                }
                return Err(format!(
                    "local sandbox process did not terminate after timeout (wait={cleanup_wait})"
                ));
            }
            return Ok((None, true, false));
        }
        let remaining_ms = timeout.saturating_sub(elapsed).as_millis().clamp(1, 250) as u32;
        let wait_result = unsafe { WaitForSingleObject(process.process.raw(), remaining_ms) };
        if wait_result == WAIT_OBJECT_0 {
            let mut exit_code = 0u32;
            if unsafe { GetExitCodeProcess(process.process.raw(), &mut exit_code) } == 0 {
                return Err(format!("GetExitCodeProcess failed: win32={}", unsafe {
                    windows_sys::Win32::Foundation::GetLastError()
                }));
            }
            return Ok((Some(exit_code as i32), false, false));
        }
        if wait_result == WAIT_FAILED {
            return Err(format!("WaitForSingleObject failed: win32={}", unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }));
        }
        if wait_result != WAIT_TIMEOUT {
            return Err(format!("unexpected process wait result: {wait_result}"));
        }
    }
}

#[cfg(target_family = "windows")]
fn to_wide_str(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_family = "windows")]
fn to_wide_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(target_family = "windows")]
unsafe fn read_wide_ptr(value: *const u16) -> String {
    let mut length = 0usize;
    while *value.add(length) != 0 {
        length += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
}

#[cfg(target_family = "windows")]
fn run_windows_sandbox(
    target: PathBuf,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<SandboxReport, SandboxError> {
    let _single_session = WINDOWS_SANDBOX_LOCK
        .lock()
        .map_err(|_| SandboxError::Spawn("sandbox session lock was poisoned".to_string()))?;
    if cancelled.load(Ordering::Relaxed) {
        return Err(SandboxError::Cancelled);
    }
    let sandbox_executable = windows_sandbox_executable()?;
    let target = target.canonicalize().map_err(SandboxError::Io)?;
    let metadata = fs::metadata(&target)?;
    if !metadata.is_file() {
        return Err(SandboxError::UnsupportedTarget(
            "the selected target is not a regular file".to_string(),
        ));
    }
    if metadata.len() > MAX_SAMPLE_SIZE {
        return Err(SandboxError::UnsupportedTarget(format!(
            "sample exceeds the {} MiB safety limit",
            MAX_SAMPLE_SIZE / 1024 / 1024
        )));
    }

    let extension = supported_extension(&target)?;
    let resource_limits = vec![
        "memory_mb:4096".to_string(),
        format!(
            "timeout_ms:{}",
            timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT).as_millis()
        ),
        "network:disabled".to_string(),
        "vgpu:disabled".to_string(),
        "clipboard:disabled".to_string(),
        "mapped_input:read_only".to_string(),
        "decoy_surface:documents_browser_wallet_messenger".to_string(),
    ];
    let anti_sandbox_indicators = detect_anti_sandbox_indicators(&target);
    let session = TempDir::new()?;
    let input_dir = session.path().join("input");
    let output_dir = session.path().join("guest-output");
    fs::create_dir(&input_dir)?;
    fs::create_dir(&output_dir)?;
    let sample_name = format!("sample.{extension}");
    let isolated_sample = input_dir.join(&sample_name);
    copy_sample_to_sandbox(&target, &isolated_sample, metadata.len(), cancelled)?;
    let staged_metadata = fs::metadata(&isolated_sample)?;
    if staged_metadata.len() != metadata.len() {
        return Err(SandboxError::Spawn(
            "staged sample size changed during copy".to_string(),
        ));
    }
    let mut permissions = fs::metadata(&isolated_sample)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&isolated_sample, permissions)?;
    stage_decoy_surface(&input_dir).map_err(SandboxError::Spawn)?;

    let runner = build_runner_with_output(
        &sample_name,
        &extension,
        r"C:\EverbloomSecurityOutput\guest_snapshot.json",
    );
    let guest_capture = build_guest_capture_script();
    fs::write(input_dir.join("runner.ps1"), runner)?;
    fs::write(input_dir.join("guest_capture.ps1"), guest_capture)?;
    let config = build_windows_sandbox_config_with_output(&input_dir, &output_dir);
    validate_windows_sandbox_config(&config).map_err(SandboxError::Spawn)?;
    let config_path = session.path().join("everbloom-session.wsb");
    fs::write(&config_path, config)?;

    let start = Instant::now();
    let mut child = Command::new(&sandbox_executable)
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            SandboxError::Spawn(format!(
                "unable to start {}: {error}",
                sandbox_executable.display()
            ))
        })?;
    log::info!(
        "SANDBOX_CHILD_STARTED backend=windows_sandbox pid={} target={} config={}",
        child.id(),
        target.display(),
        config_path.display()
    );

    let effective_timeout = timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT);
    let mut exit_code = None;
    while start.elapsed() < effective_timeout {
        if cancelled.load(Ordering::Relaxed) {
            log::warn!(
                "SANDBOX_CHILD_TERMINATING backend=windows_sandbox pid={} reason=cancelled target={}",
                child.id(),
                target.display()
            );
            terminate_windows_sandbox(&mut child).map_err(SandboxError::Spawn)?;
            return Err(SandboxError::Cancelled);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = Some(status.code().unwrap_or(-1));
                log::info!(
                    "SANDBOX_CHILD_EXITED backend=windows_sandbox pid={} exit_code={:?} target={} duration_ms={}",
                    child.id(),
                    exit_code,
                    target.display(),
                    start.elapsed().as_millis()
                );
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(250)),
            Err(error) => {
                let cleanup = terminate_windows_sandbox(&mut child);
                let cleanup_message = cleanup.err().unwrap_or_default();
                return Err(SandboxError::Spawn(format!(
                    "unable to observe Windows Sandbox: {error}; cleanup: {}",
                    if cleanup_message.is_empty() {
                        "ok"
                    } else {
                        &cleanup_message
                    }
                )));
            }
        }
    }

    let timed_out = exit_code.is_none();
    if timed_out {
        log::warn!(
            "SANDBOX_CHILD_TERMINATING backend=windows_sandbox pid={} reason=timeout target={} timeout_ms={}",
            child.id(),
            target.display(),
            effective_timeout.as_millis()
        );
        terminate_windows_sandbox(&mut child).map_err(SandboxError::Spawn)?;
    } else if exit_code.is_some_and(|code| code != 0) {
        return Err(SandboxError::Spawn(format!(
            "Windows Sandbox exited with code {}",
            exit_code.unwrap_or(-1)
        )));
    }

    let guest_unpacking = read_guest_unpacking_report(&output_dir).unwrap_or_else(|reason| {
        log::warn!("UNPACKING_GUEST_REPORT_UNAVAILABLE backend=windows_sandbox reason={reason}");
        SandboxUnpackingReport::unavailable(format!("guest snapshot unavailable: {reason}"))
    });

    Ok(SandboxReport {
        target,
        exit_code,
        target_pid: None,
        files_changed: Vec::new(),
        registry_writes: Vec::new(),
        network_connections: Vec::new(),
        processes: vec!["isolation:windows_sandbox".to_string()],
        api_calls: vec![
            "isolation:hardware_virtualization".to_string(),
            "isolation:protected_client".to_string(),
            "isolation:hypervisor".to_string(),
            "network:disabled".to_string(),
            "clipboard:disabled".to_string(),
            "vgpu:disabled".to_string(),
            "host_mapping:read_only".to_string(),
            "monitor:readonly_decoy_surface".to_string(),
            format!("unpacking:status:{}", guest_unpacking.status),
        ]
        .into_iter()
        .chain(
            anti_sandbox_indicators
                .into_iter()
                .map(|indicator| format!("anti_sandbox:{indicator}")),
        )
        .collect(),
        timed_out,
        isolation_backend: "windows_sandbox".to_string(),
        isolation_verified: true,
        cleanup_verified: true,
        resource_limits,
        unpacking: guest_unpacking,
        duration_ms: start.elapsed().as_millis(),
    })
}

#[cfg(target_family = "windows")]
fn windows_sandbox_executable() -> Result<PathBuf, SandboxError> {
    let windows_dir = std::env::var_os("WINDIR")
        .or_else(|| std::env::var_os("SystemRoot"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            SandboxError::IsolationUnavailable(
                "the Windows system directory could not be resolved".to_string(),
            )
        })?;
    let system_dir = windows_dir.join("System32");
    let executable = system_dir.join("WindowsSandbox.exe");
    let canonical = executable.canonicalize().map_err(|_| {
        SandboxError::IsolationUnavailable(
            "install the optional Windows Sandbox feature and restart Windows".to_string(),
        )
    })?;
    let canonical_system_dir = system_dir.canonicalize().map_err(SandboxError::Io)?;
    if !canonical.starts_with(canonical_system_dir) {
        return Err(SandboxError::IsolationUnavailable(
            "WindowsSandbox.exe is outside the trusted System32 directory".to_string(),
        ));
    }
    Ok(canonical)
}

#[cfg(target_family = "windows")]
fn system_executable(name: &str) -> Result<PathBuf, SandboxError> {
    let windows_dir = std::env::var_os("WINDIR")
        .or_else(|| std::env::var_os("SystemRoot"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            SandboxError::IsolationUnavailable(
                "the Windows system directory could not be resolved".to_string(),
            )
        })?;
    let system_dir = windows_dir.join("System32");
    let executable = system_dir.join(name);
    let canonical = executable
        .canonicalize()
        .map_err(|_| SandboxError::IsolationUnavailable(format!("{} is unavailable", name)))?;
    let canonical_system_dir = system_dir.canonicalize().map_err(SandboxError::Io)?;
    if !canonical.starts_with(canonical_system_dir) {
        return Err(SandboxError::IsolationUnavailable(format!(
            "{} is outside the trusted System32 directory",
            name
        )));
    }
    Ok(canonical)
}

#[cfg(target_family = "windows")]
fn terminate_windows_sandbox(child: &mut Child) -> Result<(), String> {
    let pid = child.id();
    let taskkill = system_executable("taskkill.exe").map_err(|error| error.to_string())?;
    let taskkill_status = Command::new(taskkill)
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status()
        .map_err(|error| format!("unable to terminate sandbox process tree: {error}"))?;
    let _ = child.kill();
    let _ = child.wait();
    if !taskkill_status.success() {
        return Err(format!("taskkill returned {}", taskkill_status));
    }
    Ok(())
}

#[cfg(any(test, target_family = "windows"))]
fn supported_extension(target: &Path) -> Result<String, SandboxError> {
    let extension = target
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| {
            SandboxError::UnsupportedTarget(
                "a recognized executable or script extension is required".to_string(),
            )
        })?;
    match extension.as_str() {
        "exe" | "com" | "scr" | "bat" | "cmd" | "ps1" | "msi" => Ok(extension),
        _ => Err(SandboxError::UnsupportedTarget(format!(
            ".{extension} files are not executed automatically"
        ))),
    }
}

#[cfg(any(test, target_family = "windows"))]
fn build_guest_capture_script() -> String {
    include_str!("../resources/guest_capture.ps1").to_string()
}

#[cfg(test)]
fn build_runner(sample_name: &str, extension: &str) -> String {
    build_runner_with_output(
        sample_name,
        extension,
        r"C:\EverbloomSecurityOutput\guest_snapshot.json",
    )
}

#[cfg(any(test, target_family = "windows"))]
fn build_runner_with_output(sample_name: &str, _extension: &str, output_path: &str) -> String {
    let sample_path = format!(r#"C:\EverbloomSecurityInput\{sample_name}"#);
    let sample_literal = powershell_single_quote(&sample_path);
    let output_literal = powershell_single_quote(output_path);
    format!(
        "$ErrorActionPreference = 'SilentlyContinue'\r\nSet-Location -LiteralPath 'C:\\EverbloomSecurityInput'\r\n$agent = 'C:\\EverbloomSecurityInput\\guest_capture.ps1'\r\n$child = Start-Process -FilePath ($env:SystemRoot + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe') -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $agent, '-SamplePath', {sample_literal}, '-OutputPath', {output_literal}, '-TimeoutMs', '600000') -WindowStyle Hidden -Wait -PassThru\r\n$exitCode = if ($null -ne $child) {{ [int]$child.ExitCode }} else {{ 1 }}\r\n& ($env:SystemRoot + '\\System32\\shutdown.exe') /s /t 0 /f\r\nexit $exitCode\r\n"
    )
}

#[cfg(any(test, target_family = "windows"))]
fn powershell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
fn build_windows_sandbox_config(input_dir: &Path) -> String {
    build_windows_sandbox_config_with_output(input_dir, Path::new(""))
}

#[cfg(any(test, target_family = "windows"))]
fn build_windows_sandbox_config_with_output(input_dir: &Path, output_dir: &Path) -> String {
    let host_folder = xml_escape(&input_dir.to_string_lossy());
    let output_mapping = if output_dir.as_os_str().is_empty() {
        String::new()
    } else {
        format!(
            r#"  <MappedFolder>
      <HostFolder>{}</HostFolder>
      <SandboxFolder>C:\EverbloomSecurityOutput</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
"#,
            xml_escape(&output_dir.to_string_lossy())
        )
    };
    format!(
        r#"<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Disable</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{host_folder}</HostFolder>
      <SandboxFolder>C:\EverbloomSecurityInput</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
{output_mapping}  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\EverbloomSecurityInput\runner.ps1</Command>
  </LogonCommand>
</Configuration>
"#
    )
}

#[cfg(target_family = "windows")]
fn read_guest_unpacking_report(output_dir: &Path) -> Result<SandboxUnpackingReport, String> {
    const MAX_GUEST_REPORT_BYTES: usize = 2 * 1024 * 1024;
    let report_path = output_dir.join("guest_snapshot.json");
    let mut bytes =
        fs::read(&report_path).map_err(|error| format!("unable to read guest report: {error}"))?;
    if bytes.len() > MAX_GUEST_REPORT_BYTES {
        return Err(format!(
            "guest report exceeds {} bytes",
            MAX_GUEST_REPORT_BYTES
        ));
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        bytes.drain(..3);
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("guest report JSON is invalid: {error}"))
}

#[cfg(any(test, target_family = "windows"))]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(test, target_family = "windows"))]
fn validate_windows_sandbox_config(config: &str) -> Result<(), String> {
    const REQUIRED: &[&str] = &[
        "<VGpu>Disable</VGpu>",
        "<Networking>Disable</Networking>",
        "<ClipboardRedirection>Disable</ClipboardRedirection>",
        "<ProtectedClient>Enable</ProtectedClient>",
        "<ReadOnly>true</ReadOnly>",
    ];
    if let Some(missing) = REQUIRED.iter().find(|required| !config.contains(*required)) {
        return Err(format!(
            "sandbox policy is missing required control: {missing}"
        ));
    }
    if (config.contains("<ReadOnly>false</ReadOnly>")
        && !config.contains("<SandboxFolder>C:\\EverbloomSecurityOutput</SandboxFolder>"))
        || config.contains("<Networking>Enable</Networking>")
        || config.contains("<VGpu>Enable</VGpu>")
    {
        return Err("sandbox policy enables a forbidden host integration".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_configuration_disables_host_integrations() {
        let config = build_windows_sandbox_config(Path::new(r"C:\Temp\EverbloomSecurity & Samples"));
        assert!(config.contains("<VGpu>Disable</VGpu>"));
        assert!(config.contains("<Networking>Disable</Networking>"));
        assert!(config.contains("<AudioInput>Disable</AudioInput>"));
        assert!(config.contains("<VideoInput>Disable</VideoInput>"));
        assert!(config.contains("<PrinterRedirection>Disable</PrinterRedirection>"));
        assert!(config.contains("<ClipboardRedirection>Disable</ClipboardRedirection>"));
        assert!(config.contains("<ProtectedClient>Enable</ProtectedClient>"));
        assert!(config.contains("<MemoryInMB>4096</MemoryInMB>"));
        assert!(config.contains("<ReadOnly>true</ReadOnly>"));
        assert!(!config.contains("<vGPU>"));
        assert!(validate_windows_sandbox_config(&config).is_ok());
        assert!(!config.contains("EverbloomSecurity & Samples"));
        assert!(config.contains("EverbloomSecurity &amp; Samples"));
    }

    #[test]
    fn runner_uses_hidden_powershell_and_fixed_guest_path() {
        let runner = build_runner("sample.exe", "exe");
        assert!(runner.contains("Start-Process"));
        assert!(runner.contains("C:\\EverbloomSecurityInput\\sample.exe"));
        assert!(!runner.contains("@echo off"));
        assert!(runner.contains("shutdown.exe"));
        assert!(runner.contains("/s /t 0 /f"));
    }

    #[test]
    fn windows_sandbox_uses_hidden_powershell_logon_command() {
        let config = build_windows_sandbox_config(Path::new(r"C:\Temp\EverbloomSecurity"));
        assert!(config.contains("powershell.exe"));
        assert!(config.contains("-WindowStyle Hidden"));
        assert!(config.contains(r#"C:\EverbloomSecurityInput\runner.ps1"#));
        assert!(!config.contains("runner.cmd"));
    }

    #[test]
    fn guest_capture_agent_is_bounded_and_reports_thread_ip_limit() {
        let script = build_guest_capture_script();
        assert!(script.contains("VirtualQueryEx"));
        assert!(script.contains("ReadProcessMemory"));
        assert!(script.contains("MaxCapture"));
        assert!(script.contains("guest_thread_ip_tracked"));
        assert!(script.contains("GetThreadContext"));
        assert!(script.contains("snapshot_rounds"));
        assert!(script.contains("adaptive_timeout_ms"));
    }

    #[test]
    fn guest_output_mapping_is_writable_but_input_stays_read_only() {
        let config = build_windows_sandbox_config_with_output(
            Path::new(r"C:\Temp\EverbloomSecurity"),
            Path::new(r"C:\Temp\EverbloomSecurity\guest-output"),
        );
        assert!(config.contains("<ReadOnly>true</ReadOnly>"));
        assert!(config.contains("<ReadOnly>false</ReadOnly>"));
        assert!(config.contains("<SandboxFolder>C:\\EverbloomSecurityOutput</SandboxFolder>"));
        assert!(validate_windows_sandbox_config(&config).is_ok());
    }

    #[test]
    fn rejects_non_executable_file_types() {
        let error = supported_extension(Path::new("document.pdf")).unwrap_err();
        assert!(matches!(error, SandboxError::UnsupportedTarget(_)));
    }
}
