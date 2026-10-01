//! Resident stdin/stdout NDJSON protocol for the scanning engine.
//!
//! The platform-facing transport is intentionally strict about its public
//! dictionaries (`engine_status.code` and `scan_result.verdict`) while staying
//! forgiving about malformed input: every input line either produces one JSON
//! response line or, for EOF, a clean process exit.  Engine diagnostics are
//! routed through the file logger; stdout is reserved for protocol frames.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use walkdir::WalkDir;


use crate::layers::ai::{AiModel, AiModelKind};
use crate::scanner::{ScanRequest, ScanResult, ScanVerdict, Scanner};

const MAX_NDJSON_LINE_BYTES: usize = 1024 * 1024;
const DEFAULT_AI_THRESHOLD: f32 = 0.9;
const DEFAULT_ARCHIVE_DEPTH: u32 = 3;
const MAX_ARCHIVE_ENTRIES: usize = 4096;
const DEFAULT_ARCHIVE_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const ARCHIVE_COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_ARCHIVE_COMMAND_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const ENGINE_NAME: &str = "EverbloomSecurity-Core";

/// Fixed execution-state dictionary from the platform contract.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum EngineStatusCode {
    #[serde(rename = "SUCCESS")]
    Success,
    #[serde(rename = "ERR_PARTIAL")]
    ErrPartial,
    #[serde(rename = "ERR_INITIALIZATION")]
    ErrInitialization,
    #[serde(rename = "ERR_LICENSE")]
    ErrLicense,
    #[serde(rename = "ERR_FILE_ACCESS")]
    ErrFileAccess,
    #[serde(rename = "ERR_UNSUPPORTED")]
    ErrUnsupported,
    #[serde(rename = "ERR_EXTRACTION")]
    ErrExtraction,
    #[serde(rename = "ERR_NETWORK")]
    ErrNetwork,
    #[serde(rename = "ERR_TIMEOUT")]
    ErrTimeout,
    #[serde(rename = "ERR_RESOURCE")]
    ErrResource,
    #[serde(rename = "ERR_INTERNAL")]
    ErrInternal,
}

/// Fixed threat-verdict dictionary from the platform contract.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum ContractVerdict {
    #[serde(rename = "Malware")]
    Malware,
    #[serde(rename = "Suspicious")]
    Suspicious,
    #[serde(rename = "Benign")]
    Benign,
    #[serde(rename = "Undetected")]
    Undetected,
}

impl ContractVerdict {
    fn rank(self) -> u8 {
        match self {
            Self::Malware => 3,
            Self::Suspicious => 2,
            Self::Undetected => 1,
            Self::Benign => 0,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawEnvelope {
    task_info: Option<RawTaskInfo>,
    target: Option<RawTarget>,
    scan_options: Option<RawScanOptions>,
}

#[derive(Debug, Deserialize)]
struct RawTaskInfo {
    task_id: Option<String>,
    priority: Option<String>,
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawTarget {
    #[serde(rename = "type")]
    target_type: Option<String>,
    file_path: Option<String>,
    file_name: Option<String>,
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawScanOptions {
    enable_heuristics: Option<bool>,
    enable_yara: Option<bool>,
    enable_ai: Option<bool>,
    enable_sandbox: Option<bool>,
    enable_clamav: Option<bool>,
    ai_threshold: Option<f32>,
    cloud_enabled: Option<bool>,
    max_archive_depth: Option<u32>,
    max_file_size_mb: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct TargetInfo {
    task_id: Option<String>,
    file_path: Option<String>,
    file_name: Option<String>,
    sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EngineStatus {
    code: EngineStatusCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub_code: Option<i32>,
    message: String,
}

#[derive(Debug, Serialize)]
struct ReadyResponse {
    engine_status: EngineStatus,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    target_info: TargetInfo,
    engine_status: EngineStatus,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    target_info: TargetInfo,
    engine_status: EngineStatus,
    scan_result: ScanResultPayload,
    engine_metadata: EngineMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_analysis: Option<SandboxAnalysisPayload>,
}

#[derive(Debug, Serialize)]
struct ScanResultPayload {
    verdict: ContractVerdict,
    confidence: Option<f32>,
    threat_name: Option<String>,
    threat_category: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    matched_rules: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    details: Vec<ScanDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attack_chains: Option<Vec<AttackChainPayload>>,
}

/// Multi-step attack chain surfaced to the GUI, one entry per matched chain
/// signature, in the order the chain's steps are defined. `step_labels` carry
/// the human-readable correlation names so the page can be rendered without
/// the GUI knowing the engine's internal signature table.
#[derive(Debug, Serialize)]
struct AttackChainPayload {
    chain: String,
    /// intermediate `intervene`/`correlate`/`observe` stage from the fusion
    /// verdict that surfaced this chain.
    stage: String,
    /// True for gap-tolerant correlation chains that are weaker evidence and
    /// need corroboration to reach `intervene`.
    tolerant: bool,
    /// Evidence flavour that latched this chain: strict in-order match or the
    /// tolerant window matcher.
    matched_by: String,
    step_labels: Vec<&'static str>,
}

impl AttackChainPayload {
    fn build(name: &str, stage: &str, matched_by: &str) -> Option<Self> {
        let step_labels = crate::layers::sequence::chain_step_labels(name)?;
        Some(Self {
            chain: name.to_string(),
            stage: stage.to_string(),
            tolerant: crate::layers::sequence::is_tolerant_chain(name),
            matched_by: matched_by.to_string(),
            step_labels,
        })
    }
}

#[derive(Debug, Serialize)]
struct ScanDetail {
    file_path: String,
    threat_name: Option<String>,
    verdict: ContractVerdict,
}

#[derive(Debug, Serialize)]
struct SandboxAnalysisPayload {
    backend: String,
    status: String,
    snapshot_rounds: u32,
    triggered_snapshots: u32,
    adaptive_timeout_ms: u64,
    candidate_images: u32,
    recovered_entry_points: u32,
    observed_execution_points: u32,
    bytes_captured: u64,
    truncated: bool,
    timed_out: bool,
    isolation_verified: bool,
    cleanup_verified: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EngineMetadata {
    engine_name: &'static str,
    engine_version: &'static str,
    signature_version: String,
    /// The platform task id is the stable correlation id for this scan.
    /// Keeping it in metadata lets GUI logs, engine logs and later telemetry
    /// exporters join records without adding a second id dictionary.
    trace_id: String,
    scan_time_ms: u128,
    scan_timestamp: String,
}

#[derive(Debug)]
struct ParsedRequest {
    target_info: TargetInfo,
    file_path: PathBuf,
    timeout_ms: u64,
    enable_heuristics: bool,
    enable_yara: bool,
    enable_ai: bool,
    enable_sandbox: bool,
    enable_clamav: bool,
    ai_threshold: f32,
    cloud_enabled: bool,
    max_archive_depth: u32,
    max_file_size_bytes: u64,
}

/// Parse a permissive boolean environment flag. Only explicit truthy values
/// enable a feature; everything else, including a missing variable, is false.
pub fn env_var_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

pub type NdjsonResultCallback = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;
pub type NdjsonCommandCallback = Arc<dyn Fn(String) -> Result<String, String> + Send + Sync>;

/// Optional control-plane handlers shared by the legacy IPC and NDJSON
/// transports. Scan requests stay contract-compatible; these callbacks keep
/// GUI settings and model/hash management functional after the transport move.
#[derive(Default, Clone)]
pub struct NdjsonRuntime {
    pub config_reload: Option<NdjsonResultCallback>,
    pub hash_import: Option<NdjsonCommandCallback>,
    pub model_command: Option<NdjsonCommandCallback>,
    pub allowlist: Arc<crate::allowlist::Allowlist>,
}

enum RequestAction {
    Continue(Value),
    Shutdown(Value),
}

fn status(code: EngineStatusCode, message: impl Into<String>) -> EngineStatus {
    EngineStatus {
        code,
        sub_code: None,
        message: message.into(),
    }
}

fn ready_response(message: impl Into<String>) -> Value {
    serde_json::to_value(ReadyResponse {
        engine_status: status(EngineStatusCode::Success, message),
    })
    .unwrap_or_else(|_| serde_json::json!({"engine_status":{"code":"ERR_INTERNAL","message":"serialization error"}}))
}

fn error_response(
    target_info: TargetInfo,
    code: EngineStatusCode,
    message: impl Into<String>,
) -> Value {
    serde_json::to_value(ErrorResponse {
        target_info,
        engine_status: status(code, message),
    })
    .unwrap_or_else(|_| {
        serde_json::json!({
            "target_info": {"task_id": null, "file_path": null, "file_name": null, "sha256": null},
            "engine_status": {"code": "ERR_INTERNAL", "message": "serialization error"}
        })
    })
}

fn target_info_hint(value: Option<&Value>) -> TargetInfo {
    let task_id = value
        .and_then(|value| value.get("task_info"))
        .and_then(|value| value.get("task_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let target = value.and_then(|value| value.get("target"));
    let file_path = target
        .and_then(|value| value.get("file_path"))
        .and_then(Value::as_str)
        .map(normalize_path_string);
    let file_name = target
        .and_then(|value| value.get("file_name"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let sha256 = target
        .and_then(|value| value.get("sha256"))
        .and_then(Value::as_str)
        .map(str::to_owned);

    TargetInfo {
        task_id,
        file_path,
        file_name,
        sha256,
    }
}

fn normalize_path_string(path: &str) -> String {
    path.replace('\\', "/")
}

fn validate_priority(priority: Option<&str>) -> Result<(), String> {
    match priority.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(()),
        Some("HIGH" | "NORMAL" | "LOW") => Ok(()),
        Some(value) => Err(format!("unsupported task_info.priority: {value}")),
    }
}

fn parse_request_value(
    value: Value,
) -> Result<ParsedRequest, (TargetInfo, EngineStatusCode, String)> {
    let hint = target_info_hint(Some(&value));
    let envelope: RawEnvelope = serde_json::from_value(value).map_err(|error| {
        (
            hint.clone(),
            EngineStatusCode::ErrInternal,
            format!("Malformed JSON request received or essential fields missing: {error}"),
        )
    })?;

    let task_info = envelope.task_info.ok_or_else(|| {
        (
            hint.clone(),
            EngineStatusCode::ErrInternal,
            "Malformed JSON request received or essential fields missing: missing task_info."
                .to_string(),
        )
    })?;
    validate_priority(task_info.priority.as_deref())
        .map_err(|error| (hint.clone(), EngineStatusCode::ErrInternal, error))?;

    let task_id = task_info
        .task_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            (
                hint.clone(),
                EngineStatusCode::ErrInternal,
                "Malformed JSON request received or essential fields missing: missing task_info.task_id.".to_string(),
            )
        })?;
    let timeout_ms = task_info.timeout_ms.ok_or_else(|| {
        (
            hint.clone(),
            EngineStatusCode::ErrInternal,
            "Malformed JSON request received or essential fields missing: missing task_info.timeout_ms.".to_string(),
        )
    })?;

    let target = envelope.target.ok_or_else(|| {
        (
            TargetInfo {
                task_id: Some(task_id.clone()),
                ..hint.clone()
            },
            EngineStatusCode::ErrInternal,
            "Malformed JSON request received or essential fields missing: missing target."
                .to_string(),
        )
    })?;
    let target_type = target
        .target_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            (
                TargetInfo {
                    task_id: Some(task_id.clone()),
                    ..hint.clone()
                },
                EngineStatusCode::ErrInternal,
                "Malformed JSON request received or essential fields missing: missing target.type."
                    .to_string(),
            )
        })?;
    if target_type != "LOCAL_PATH" {
        return Err((
            TargetInfo {
                task_id: Some(task_id.clone()),
                file_path: target.file_path.as_deref().map(normalize_path_string),
                file_name: target.file_name.clone(),
                sha256: target.sha256.clone(),
            },
            EngineStatusCode::ErrUnsupported,
            format!("Unsupported target.type: {target_type}."),
        ));
    }

    let raw_file_path = target
        .file_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            (
                TargetInfo {
                    task_id: Some(task_id.clone()),
                    file_path: None,
                    file_name: target.file_name.clone(),
                    sha256: target.sha256.clone(),
                },
                EngineStatusCode::ErrInternal,
                "Malformed JSON request received or essential fields missing: missing target.file_path.".to_string(),
            )
        })?;

    let scan_options = envelope.scan_options.unwrap_or(RawScanOptions {
        enable_heuristics: None,
        enable_yara: None,
        enable_ai: None,
        enable_sandbox: None,
        enable_clamav: None,
        ai_threshold: None,
        cloud_enabled: None,
        max_archive_depth: None,
        max_file_size_mb: None,
    });
    let enable_heuristics = scan_options.enable_heuristics.unwrap_or(true);
    let enable_yara = scan_options.enable_yara.unwrap_or(true);
    let enable_ai = scan_options.enable_ai.unwrap_or(enable_heuristics);
    let enable_sandbox = scan_options.enable_sandbox.unwrap_or(false);
    let enable_clamav = scan_options
        .enable_clamav
        .unwrap_or_else(|| env_var_flag("EVERBLOOM_CLAMAV", false));
    let ai_threshold = scan_options
        .ai_threshold
        .unwrap_or(DEFAULT_AI_THRESHOLD)
        .clamp(0.0, 1.0);
    let cloud_enabled = scan_options.cloud_enabled.unwrap_or(false);
    let max_archive_depth = scan_options
        .max_archive_depth
        .unwrap_or(DEFAULT_ARCHIVE_DEPTH);
    let max_file_size_bytes = match scan_options.max_file_size_mb {
        Some(0) => {
            return Err((
                TargetInfo {
                    task_id: Some(task_id.clone()),
                    file_path: Some(normalize_path_string(raw_file_path)),
                    file_name: target.file_name.clone(),
                    sha256: target.sha256.clone(),
                },
                EngineStatusCode::ErrResource,
                "scan_options.max_file_size_mb must be greater than zero.".to_string(),
            ))
        }
        Some(value) => value.checked_mul(1024 * 1024).ok_or_else(|| {
            (
                TargetInfo {
                    task_id: Some(task_id.clone()),
                    file_path: Some(normalize_path_string(raw_file_path)),
                    file_name: target.file_name.clone(),
                    sha256: target.sha256.clone(),
                },
                EngineStatusCode::ErrResource,
                "scan_options.max_file_size_mb is too large.".to_string(),
            )
        })?,
        None => 0,
    };

    let file_path = PathBuf::from(raw_file_path);
    let file_name = target.file_name.or_else(|| {
        Path::new(raw_file_path)
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_owned)
    });

    Ok(ParsedRequest {
        target_info: TargetInfo {
            task_id: Some(task_id),
            file_path: Some(normalize_path_string(raw_file_path)),
            file_name,
            sha256: target.sha256,
        },
        file_path,
        timeout_ms,
        enable_heuristics,
        enable_yara,
        enable_ai,
        enable_sandbox,
        enable_clamav,
        ai_threshold,
        cloud_enabled,
        max_archive_depth,
        max_file_size_bytes,
    })
}

fn build_scan_request(
    scanner: &Scanner,
    request: &ParsedRequest,
    cancelled: Arc<AtomicBool>,
) -> ScanRequest {
    ScanRequest {
        paths: vec![request.file_path.clone()],
        timeout_ms: request.timeout_ms,
        sandbox_enabled: request.enable_sandbox,
        yara_enabled: request.enable_yara && scanner.yara.is_some(),
        ai_enabled: request.enable_ai && request.enable_heuristics && scanner.ai.is_some(),
        heuristic_enabled: request.enable_heuristics,
        clamav_enabled: request.enable_clamav && scanner.clamav.is_some(),
        ai_threshold: request.ai_threshold,
        maximum_file_size: request.max_file_size_bytes,
        cloud_enabled: request.cloud_enabled,
        cancelled,
        progress_tx: None,
    }
}

fn empty_archive_error(path: PathBuf, message: String) -> ScanResult {
    ScanResult {
        path,
        malicious: false,
        reason: "archive_extraction_error".to_string(),
        yara_matches: Vec::new(),
        heuristic_score: None,
        heuristic_indicators: Vec::new(),
        ai_score: None,
        ai_components: Vec::new(),
        ai_fallback_reason: None,
        behavior_score: None,
        sequence_matches: None,
        sandbox: None,
        process_state: None,
        rollback_record: None,
        rollback_actions: None,
        static_sandbox: None,
        error: Some(message),
        duration_ms: 0,
    }
}

fn is_archive_path(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "zip"
                    | "jar"
                    | "apk"
                    | "7z"
                    | "rar"
                    | "cab"
                    | "msi"
                    | "tar"
                    | "gz"
                    | "tgz"
                    | "bz2"
                    | "xz"
            )
        })
}

fn validate_archive_member_path(member: &str) -> Result<(), String> {
    let member = member.trim().trim_end_matches(['/', '\\']);
    if member.is_empty() {
        return Ok(());
    }
    let member_path = Path::new(member);
    if member_path.is_absolute()
        || member_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
                    | std::path::Component::ParentDir
            )
        })
    {
        return Err(format!("unsafe archive member path: {member}"));
    }
    Ok(())
}

fn directory_size(root: &Path) -> u64 {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| entry.metadata().ok())
        .fold(0u64, |total, metadata| total.saturating_add(metadata.len()))
}

fn run_command_with_limits(
    mut command: Command,
    monitor_dir: Option<&Path>,
    max_directory_bytes: u64,
) -> Result<Output, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("archive extractor is unavailable: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "archive extractor stdout pipe was not created".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "archive extractor stderr pipe was not created".to_string())?;
    let stdout_reader = std::thread::spawn(move || read_command_stream(stdout));
    let stderr_reader = std::thread::spawn(move || read_command_stream(stderr));
    let started = Instant::now();

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("archive extractor wait failed: {error}"))?
        {
            return finish_command_output(status, stdout_reader, stderr_reader);
        }

        if started.elapsed() > ARCHIVE_COMMAND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!(
                "archive extractor timed out after {} seconds",
                ARCHIVE_COMMAND_TIMEOUT.as_secs()
            ));
        }

        if let Some(directory) = monitor_dir {
            if max_directory_bytes > 0 && directory_size(directory) > max_directory_bytes {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!(
                    "archive extraction exceeded {} MiB",
                    max_directory_bytes / 1024 / 1024
                ));
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct LimitedCommandOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_command_stream(mut reader: impl Read) -> Result<LimitedCommandOutput, String> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("archive extractor output read failed: {error}"))?;
        if read == 0 {
            break;
        }
        let remaining = MAX_ARCHIVE_COMMAND_OUTPUT_BYTES.saturating_sub(output.len());
        let copy_len = read.min(remaining);
        output.extend_from_slice(&buffer[..copy_len]);
        truncated |= copy_len < read;
    }
    Ok(LimitedCommandOutput {
        bytes: output,
        truncated,
    })
}

fn finish_command_output(
    status: ExitStatus,
    stdout_reader: std::thread::JoinHandle<Result<LimitedCommandOutput, String>>,
    stderr_reader: std::thread::JoinHandle<Result<LimitedCommandOutput, String>>,
) -> Result<Output, String> {
    let stdout = stdout_reader
        .join()
        .map_err(|_| "archive extractor stdout reader panicked".to_string())??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "archive extractor stderr reader panicked".to_string())??;
    if stdout.truncated || stderr.truncated {
        return Err(format!(
            "archive extractor output exceeded {} MiB",
            MAX_ARCHIVE_COMMAND_OUTPUT_BYTES / 1024 / 1024
        ));
    }
    Ok(Output {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

fn command_error(output: &Output, operation: &str) -> String {
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if detail.is_empty() {
        format!("{operation} failed with {}", output.status)
    } else {
        format!("{operation} failed: {detail}")
    }
}

fn find_7z_exe() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("EVERBLOOM_7Z_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }

    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("tools").join("7z.exe"));
            candidates.push(parent.join("7z.exe"));
            candidates.push(parent.join("Driver").join("7z.exe"));
        }
    }
    candidates.extend([
        PathBuf::from(r"C:\Program Files\7-Zip\7z.exe"),
        PathBuf::from(r"C:\Program Files (x86)\7-Zip\7z.exe"),
    ]);
    candidates.into_iter().find(|path| path.is_file())
}

fn validate_7z_entry(
    path: &str,
    size: u64,
    is_folder: bool,
    entry_count: &mut usize,
    total_size: &mut u64,
    per_entry_limit: u64,
    total_limit: u64,
) -> Result<(), String> {
    validate_archive_member_path(path)?;
    if is_folder {
        return Ok(());
    }
    *entry_count = entry_count.saturating_add(1);
    if *entry_count > MAX_ARCHIVE_ENTRIES {
        return Err(format!(
            "archive contains more than {} entries",
            MAX_ARCHIVE_ENTRIES
        ));
    }
    if size > per_entry_limit {
        return Err(format!(
            "archive entry exceeds {} MiB: {}",
            per_entry_limit / 1024 / 1024,
            path
        ));
    }
    *total_size = total_size.saturating_add(size);
    if *total_size > total_limit {
        return Err(format!(
            "archive contents exceed {} MiB",
            total_limit / 1024 / 1024
        ));
    }
    Ok(())
}

fn validate_7z_listing(
    listing: &[u8],
    per_entry_limit: u64,
    total_limit: u64,
) -> Result<(), String> {
    let text = String::from_utf8_lossy(listing);
    let mut current_path = None::<String>;
    let mut current_size = 0u64;
    let mut current_has_size = false;
    let mut current_folder = false;
    let mut entry_count = 0usize;
    let mut total_size = 0u64;

    let mut flush = |path: &mut Option<String>,
                     size: &mut u64,
                     has_size: &mut bool,
                     folder: &mut bool|
     -> Result<(), String> {
        if let Some(path) = path.take() {
            if *has_size || *folder {
                validate_7z_entry(
                    &path,
                    *size,
                    *folder,
                    &mut entry_count,
                    &mut total_size,
                    per_entry_limit,
                    total_limit,
                )?;
            }
        }
        *size = 0;
        *has_size = false;
        *folder = false;
        Ok(())
    };

    for line in text.lines() {
        if let Some(path) = line.strip_prefix("Path = ") {
            flush(
                &mut current_path,
                &mut current_size,
                &mut current_has_size,
                &mut current_folder,
            )?;
            current_path = Some(path.to_string());
        } else if let Some(size) = line.strip_prefix("Size = ") {
            current_size = size
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("invalid archive entry size: {size}"))?;
            current_has_size = true;
        } else if line.trim() == "Folder = +" {
            current_folder = true;
        }
    }
    flush(
        &mut current_path,
        &mut current_size,
        &mut current_has_size,
        &mut current_folder,
    )?;
    Ok(())
}

fn collect_extracted_files(
    destination: &Path,
    per_entry_limit: u64,
    total_limit: u64,
) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut total_size = 0u64;
    for entry in WalkDir::new(destination).follow_links(false) {
        let entry = entry.map_err(|error| format!("unable to enumerate archive: {error}"))?;
        let path = entry.path();
        if !path.starts_with(destination) {
            return Err("archive extractor produced a path outside its workspace".to_string());
        }
        if entry.file_type().is_symlink() {
            return Err("archive contains a symbolic link; extraction was rejected".to_string());
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let size = entry
            .metadata()
            .map_err(|error| format!("unable to inspect extracted file: {error}"))?
            .len();
        if size > per_entry_limit {
            return Err(format!(
                "extracted file exceeds {} MiB: {}",
                per_entry_limit / 1024 / 1024,
                path.display()
            ));
        }
        total_size = total_size.saturating_add(size);
        if total_size > total_limit {
            return Err(format!(
                "extracted files exceed {} MiB",
                total_limit / 1024 / 1024
            ));
        }
        files.push(path.to_path_buf());
        if files.len() > MAX_ARCHIVE_ENTRIES {
            return Err(format!(
                "archive contains more than {} extracted files",
                MAX_ARCHIVE_ENTRIES
            ));
        }
    }
    Ok(files)
}

fn extract_archive_with_limits(
    archive_path: &Path,
    destination: &Path,
    per_entry_limit: u64,
    total_limit: u64,
) -> Result<Vec<PathBuf>, String> {
    let is_tar_family = archive_path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "tar" | "gz" | "tgz" | "bz2" | "xz"
            )
        });
    let mut errors = Vec::new();

    if is_tar_family {
        match extract_with_tar(archive_path, destination, per_entry_limit, total_limit) {
            Ok(files) => return Ok(files),
            Err(error) => errors.push(format!("tar: {error}")),
        }
        let _ = std::fs::remove_dir_all(destination);
    }

    if let Some(sevenz) = find_7z_exe() {
        match extract_with_7z(
            &sevenz,
            archive_path,
            destination,
            per_entry_limit,
            total_limit,
        ) {
            Ok(files) => return Ok(files),
            Err(error) => errors.push(format!("7z: {error}")),
        }
        let _ = std::fs::remove_dir_all(destination);
    } else if !is_tar_family {
        errors.push(
            "7z extractor was not found; set EVERBLOOM_7Z_PATH or install 7-Zip to scan this format"
                .to_string(),
        );
    }

    if !is_tar_family {
        match extract_with_tar(archive_path, destination, per_entry_limit, total_limit) {
            Ok(files) => return Ok(files),
            Err(error) => errors.push(format!("tar: {error}")),
        }
    }

    Err(errors.join("; "))
}

fn extract_with_tar(
    archive_path: &Path,
    destination: &Path,
    per_entry_limit: u64,
    total_limit: u64,
) -> Result<Vec<PathBuf>, String> {
    let listing = run_command_with_limits(
        {
            let mut command = Command::new("tar");
            command.args(["-tf"]).arg(archive_path);
            command
        },
        None,
        0,
    )?;
    if !listing.status.success() {
        return Err(command_error(&listing, "archive listing"));
    }

    let members = String::from_utf8_lossy(&listing.stdout);
    if members.lines().count() > MAX_ARCHIVE_ENTRIES {
        return Err(format!(
            "archive contains more than {} entries",
            MAX_ARCHIVE_ENTRIES
        ));
    }
    for member in members.lines().filter(|value| !value.trim().is_empty()) {
        validate_archive_member_path(member)?;
    }

    std::fs::create_dir_all(destination)
        .map_err(|error| format!("unable to create archive directory: {error}"))?;
    let output = run_command_with_limits(
        {
            let mut command = Command::new("tar");
            command
                .args(["-xf"])
                .arg(archive_path)
                .args(["-C"])
                .arg(destination);
            command
        },
        Some(destination),
        total_limit,
    )?;
    if !output.status.success() {
        return Err(command_error(&output, "archive extraction"));
    }
    collect_extracted_files(destination, per_entry_limit, total_limit)
}

fn extract_with_7z(
    sevenz: &Path,
    archive_path: &Path,
    destination: &Path,
    per_entry_limit: u64,
    total_limit: u64,
) -> Result<Vec<PathBuf>, String> {
    let listing = run_command_with_limits(
        {
            let mut command = Command::new(sevenz);
            command.args(["l", "-slt", "-ba"]).arg(archive_path);
            command
        },
        None,
        0,
    )?;
    if !listing.status.success() {
        return Err(command_error(&listing, "7z archive listing"));
    }
    validate_7z_listing(&listing.stdout, per_entry_limit, total_limit)?;

    std::fs::create_dir_all(destination)
        .map_err(|error| format!("unable to create archive directory: {error}"))?;
    let output = run_command_with_limits(
        {
            let mut command = Command::new(sevenz);
            command
                .args(["x", "-y", "-bd"])
                .arg(archive_path)
                .arg(format!("-o{}", destination.display()));
            command
        },
        Some(destination),
        total_limit,
    )?;
    if !output.status.success() {
        return Err(command_error(&output, "7z archive extraction"));
    }
    collect_extracted_files(destination, per_entry_limit, total_limit)
}

async fn scan_archive_children(
    scanner: Arc<Scanner>,
    request: &ParsedRequest,
    cancelled: Arc<AtomicBool>,
) -> Vec<ScanResult> {
    let temp_root = match tempfile::tempdir() {
        Ok(root) => root,
        Err(error) => {
            return vec![empty_archive_error(
                request.file_path.clone(),
                format!("unable to create archive workspace: {error}"),
            )]
        }
    };
    let per_entry_limit = if request.max_file_size_bytes == 0 {
        4 * 1024 * 1024 * 1024u64
    } else {
        request.max_file_size_bytes
    };
    let configured_total = std::env::var("EVERBLOOM_MAX_ARCHIVE_TOTAL_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_ARCHIVE_TOTAL_BYTES);
    let total_limit = configured_total.max(1).min(MAX_ARCHIVE_TOTAL_BYTES);
    let mut extracted_total = 0u64;
    let mut pending = vec![(request.file_path.clone(), 0u32)];
    let mut results = Vec::new();
    let mut archive_index = 0u64;

    while let Some((archive_path, depth)) = pending.pop() {
        if cancelled.load(Ordering::Relaxed) || depth >= request.max_archive_depth {
            continue;
        }
        let destination = temp_root
            .path()
            .join(format!("archive_{depth}_{archive_index}"));
        archive_index = archive_index.saturating_add(1);
        let extraction = tokio::task::spawn_blocking({
            let archive_path = archive_path.clone();
            let destination = destination.clone();
            move || {
                extract_archive_with_limits(
                    &archive_path,
                    &destination,
                    per_entry_limit,
                    total_limit,
                )
            }
        })
        .await;
        let files = match extraction {
            Ok(Ok(files)) => files,
            Ok(Err(error)) => {
                results.push(empty_archive_error(archive_path, error));
                continue;
            }
            Err(error) => {
                results.push(empty_archive_error(
                    archive_path,
                    format!("archive extraction task failed: {error}"),
                ));
                continue;
            }
        };

        for output_path in files {
            if cancelled.load(Ordering::Relaxed) {
                break;
            }
            let size = match std::fs::metadata(&output_path) {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    results.push(empty_archive_error(
                        output_path,
                        format!("unable to read extracted file metadata: {error}"),
                    ));
                    continue;
                }
            };
            if size > per_entry_limit || extracted_total.saturating_add(size) > total_limit {
                results.push(empty_archive_error(
                    output_path,
                    "archive extraction size limit reached".to_string(),
                ));
                continue;
            }
            extracted_total = extracted_total.saturating_add(size);
            let mut child_request =
                build_scan_request(scanner.as_ref(), request, cancelled.clone());
            child_request.paths = vec![output_path.clone()];
            match scanner.scan_request(child_request).await {
                Ok(mut child_results) => results.append(&mut child_results),
                Err(error) => results.push(empty_archive_error(
                    output_path.clone(),
                    format!("archive child scan failed: {error}"),
                )),
            }
            if depth + 1 < request.max_archive_depth && is_archive_path(&output_path) {
                pending.push((output_path, depth + 1));
            }
        }
    }
    results
}

fn contract_verdict(result: &ScanResult) -> ContractVerdict {
    if result.malicious {
        return ContractVerdict::Malware;
    }

    match result.verdict() {
        ScanVerdict::Suspicious => ContractVerdict::Suspicious,
        ScanVerdict::Clean if is_benign_reason(&result.reason) => ContractVerdict::Benign,
        ScanVerdict::Clean => ContractVerdict::Undetected,
        ScanVerdict::Skipped
        | ScanVerdict::Error
        | ScanVerdict::Cancelled
        | ScanVerdict::Incomplete => ContractVerdict::Undetected,
        ScanVerdict::Malicious => ContractVerdict::Malware,
    }
}

fn is_benign_reason(reason: &str) -> bool {
    let reason = reason.strip_prefix("cached:").unwrap_or(reason);
    reason.starts_with("allowlisted:")
        || reason == "browser_cookie_store_metadata_only"
        || reason == "system_protected"
}

fn aggregate_contract_verdict(results: &[ScanResult]) -> ContractVerdict {
    results
        .iter()
        .map(contract_verdict)
        .max_by_key(|verdict| verdict.rank())
        .unwrap_or(ContractVerdict::Undetected)
}

fn result_status_code(result: &ScanResult) -> Option<EngineStatusCode> {
    let reason = result
        .reason
        .strip_prefix("cached:")
        .unwrap_or(&result.reason);
    if reason == "cancelled" {
        return Some(EngineStatusCode::ErrTimeout);
    }
    if reason == "scan_skipped_size" {
        return Some(EngineStatusCode::ErrResource);
    }
    if reason == "archive_extraction_error" {
        return Some(EngineStatusCode::ErrExtraction);
    }
    let Some(error) = &result.error else {
        return None;
    };
    let error_lower = error.to_ascii_lowercase();
    if error_lower.contains("metadata")
        || error_lower.contains("access")
        || error_lower.contains("permission")
        || error_lower.contains("not found")
        || error_lower.contains("no such file")
        || error_lower.contains("unable to read file")
    {
        return Some(EngineStatusCode::ErrFileAccess);
    }
    if reason == "engine_unavailable" {
        return Some(EngineStatusCode::ErrInitialization);
    }
    if reason == "sandbox_unavailable" || reason == "sandbox_unverified" {
        return Some(EngineStatusCode::ErrInternal);
    }
    Some(EngineStatusCode::ErrInternal)
}

fn sha256_hex(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("unable to open target: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("unable to hash target: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn verify_expected_sha256(path: &Path, expected: Option<&str>) -> Result<Option<String>, String> {
    let actual = sha256_hex(path)?;
    if let Some(expected) = expected.map(str::trim).filter(|value| !value.is_empty()) {
        if expected.len() != 64 || !expected.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err(
                "target.sha256 must be a 64-character hexadecimal SHA256 value".to_string(),
            );
        }
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "target SHA256 mismatch: expected {}, actual {}",
                expected, actual
            ));
        }
    }
    Ok(Some(actual))
}

fn control_response(code: EngineStatusCode, message: impl Into<String>) -> Value {
    serde_json::json!({
        "engine_status": {
            "code": code,
            "message": message.into()
        }
    })
}

fn control_response_with_payloads(
    code: EngineStatusCode,
    message: impl Into<String>,
    quarantine_result: Option<Value>,
    model_validation: Option<Value>,
) -> Value {
    let mut response = control_response(code, message);
    if let Some(result) = quarantine_result {
        if let Some(object) = response.as_object_mut() {
            object.insert("quarantine_result".to_string(), result);
        }
    }
    if let Some(result) = model_validation {
        if let Some(object) = response.as_object_mut() {
            object.insert("model_validation".to_string(), result);
        }
    }
    response
}

fn command_bool(value: Option<&Value>, default: bool) -> bool {
    value.and_then(Value::as_bool).unwrap_or(default)
}

fn command_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn quarantine_status_code(error: &crate::quarantine::QuarantineError) -> EngineStatusCode {
    match error {
        crate::quarantine::QuarantineError::FileAccess(_)
        | crate::quarantine::QuarantineError::AlreadyExists(_) => EngineStatusCode::ErrFileAccess,
        crate::quarantine::QuarantineError::InvalidRequest(_)
        | crate::quarantine::QuarantineError::NotFound(_) => EngineStatusCode::ErrUnsupported,
        crate::quarantine::QuarantineError::Storage(_)
        | crate::quarantine::QuarantineError::Encryption(_)
        | crate::quarantine::QuarantineError::CorruptMetadata(_)
        | crate::quarantine::QuarantineError::CorruptObject(_) => EngineStatusCode::ErrInternal,
    }
}

fn command_model_kind(value: Option<&Value>) -> AiModelKind {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .map(|kind| match kind.to_ascii_lowercase().as_str() {
            "transformer" | "tf" => AiModelKind::Transformer,
            _ => AiModelKind::CNN,
        })
        .unwrap_or(AiModelKind::CNN)
}

fn format_driver_error(error: crate::driver_bridge::DriverBridgeError) -> String {
    if error.is_unavailable() {
        error.unavailable_message()
    } else {
        error.to_string()
    }
}
fn apply_protection_modes(r3_enabled: bool, driver_enabled: bool) -> Result<String, String> {
    if !driver_enabled {
        crate::protection_state::set_modes(r3_enabled, false);
        return Ok("protection modes updated: driver layer disabled".to_string());
    }

    let bridge = crate::driver_bridge::DriverBridge::new();
    let capabilities = match bridge.probe_capabilities() {
        Ok(capabilities) if capabilities.is_compatible() => capabilities,
        Ok(capabilities) => {
            crate::protection_state::set_modes(r3_enabled, false);
            return Err(format!(
                "driver protocol is incompatible: {}",
                capabilities.summary()
            ));
        }
        Err(error) if error.is_unavailable() => {
            crate::protection_state::set_modes(r3_enabled, false);
            return Ok(format!(
                "R3 protection remains active; driver protection unavailable: {}",
                error.unavailable_message()
            ));
        }
        Err(error) => {
            crate::protection_state::set_modes(r3_enabled, false);
            return Err(format!("driver capability query failed: {error}"));
        }
    };

    if let Err(error) = bridge.set_protection_modes(r3_enabled, true) {
        crate::protection_state::set_modes(r3_enabled, false);
        if error.is_unavailable() {
            return Ok(format!(
                "R3 protection remains active; driver protection unavailable: {}",
                error.unavailable_message()
            ));
        }
        return Err(format!("driver protection update failed: {error}"));
    }

    match bridge.install_vulnerable_driver_policies() {
        Ok(count) => {
            crate::protection_state::set_modes(r3_enabled, true);
            Ok(format!(
                "protection modes updated; kernel capabilities={} vulnerable-driver rules={count}",
                capabilities.summary()
            ))
        }
        Err(error) => {
            crate::protection_state::set_modes(r3_enabled, false);
            if error.is_unavailable() {
                Ok(format!(
                    "R3 protection remains active; driver protection unavailable: {}",
                    error.unavailable_message()
                ))
            } else {
                Err(format!("driver policy initialization failed: {error}"))
            }
        }
    }
}
fn handle_control_command(runtime: &NdjsonRuntime, value: &Value) -> Value {
    let Some(raw_command) = value.get("command").and_then(Value::as_str) else {
        return control_response(EngineStatusCode::ErrInternal, "missing command");
    };
    let command = raw_command.trim().to_ascii_uppercase();
    let mut quarantine_result = None;
    let mut model_validation_result = None;
    let mut error_status = EngineStatusCode::ErrInternal;
    let callback_result = match command.as_str() {
        "RELOAD_HASH_DATABASE" => runtime
            .config_reload
            .as_ref()
            .ok_or_else(|| "hash database reload is unavailable".to_string())
            .and_then(|callback| callback().map(|_| "hash database reloaded".to_string())),
        "RELOAD_VULNERABLE_DRIVERS" => {
            match crate::driver_bridge::reload_vulnerable_driver_names_from_default_locations() {
                Ok(source_count) => {
                    let bridge = crate::driver_bridge::DriverBridge::new();
                    if crate::protection_state::driver_enabled() {
                        bridge
                            .install_vulnerable_driver_policies()
                            .map(|installed| {
                                format!(
                                    "vulnerable driver list reloaded: source={:?} kernel_rules={installed}",
                                    source_count
                                )
                            })
                            .map_err(format_driver_error)
                    } else {
                        Ok(format!(
                            "vulnerable driver list reloaded for user mode: source={:?}; kernel protection disabled",
                            source_count
                        ))
                    }
                }
                Err(error) => Err(error),
            }
        }
        "IMPORT_HASH_DATABASE" => runtime
            .hash_import
            .as_ref()
            .ok_or_else(|| "hash database import is unavailable".to_string())
            .and_then(|callback| {
                let path = value
                    .get("path")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                    .ok_or_else(|| "missing hash database path".to_string())?;
                callback(format!("import_hash_database:{path}"))
            }),
        "CONVERT_MODEL" => runtime
            .model_command
            .as_ref()
            .ok_or_else(|| "model conversion is unavailable".to_string())
            .and_then(|callback| {
                let payload = serde_json::to_string(value)
                    .map_err(|error| format!("serialize model conversion request: {error}"))?;
                callback(format!("convert_model:{payload}"))
            }),
        "IMPORT_MODEL" => runtime
            .model_command
            .as_ref()
            .ok_or_else(|| "model import is unavailable".to_string())
            .and_then(|callback| {
                let path = value
                    .get("path")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                    .ok_or_else(|| "missing model path".to_string())?;
                callback(format!("import_model:{path}"))
            }),
        "VALIDATE_MODEL" => command_string(value, "path")
            .ok_or_else(|| "missing model path".to_string())
            .map(|path| {
                let kind = command_model_kind(value.get("kind"));
                let report = AiModel::validate_model_for_scanner(path, kind);
                let message = if report.usable {
                    format!(
                        "model validation passed: {} (feature_dim={})",
                        report.path,
                        report
                            .feature_dim
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    )
                } else {
                    format!(
                        "model validation failed: {}",
                        report.errors.first().cloned().unwrap_or_else(|| {
                            "model is not compatible with EverbloomSecurity".to_string()
                        })
                    )
                };
                model_validation_result = serde_json::to_value(report).ok();
                message
            }),
        "SET_AI_STRATEGY" => runtime
            .model_command
            .as_ref()
            .ok_or_else(|| "AI model control is unavailable".to_string())
            .and_then(|callback| {
                let strategy = value
                    .get("strategy")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|strategy| !strategy.is_empty())
                    .ok_or_else(|| "missing AI strategy".to_string())?;
                callback(format!("set_ai_strategy:{strategy}"))
            }),
        "SET_PROTECTION_MODES" => {
            let r3_enabled = command_bool(value.get("r3_enabled"), true);
            let driver_enabled = command_bool(value.get("driver_enabled"), false);
            apply_protection_modes(r3_enabled, driver_enabled)
        }
        "BLOCK_FILE" => value
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing file path".to_string())
            .and_then(|path| {
                if !crate::protection_state::driver_enabled() {
                    return Ok(
                        "R3 protection remains active; driver file policy unavailable: driver layer disabled"
                            .to_string(),
                    );
                }
                crate::driver_bridge::DriverBridge::new()
                    .block_file(path)
                    .map(|_| "file block request submitted".to_string())
                    .map_err(|error| {
                        if error.is_unavailable() {
                            crate::protection_state::set_driver_enabled(false);
                        }
                        format_driver_error(error)
                    })
            }),
"ALLOW_FILE" => value
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing file path".to_string())
            .and_then(|path| {
                crate::driver_bridge::DriverBridge::new()
                    .clear_file(path)
                    .map(|_| "file allow request submitted".to_string())
                    .map_err(format_driver_error)
            }),
        "ALLOWLIST_ADD" => value
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing file path".to_string())
            .and_then(|path| {
                let path = std::path::Path::new(path);
                match runtime.allowlist.add_trusted(path) {
                    Ok(hash) => Ok(format!("allowlist updated with trusted sha256:{hash}")),
                    Err(error) => Err(format!("allowlist add failed: {error}")),
                }
            }),
        "QUARANTINE_FILE" => command_string(value, "path")
            .ok_or_else(|| "missing file path".to_string())
            .and_then(|path_str| {
                let path = std::path::Path::new(&path_str);
                let reason = command_string(value, "reason");
                match crate::quarantine::quarantine_file(path, reason.as_deref()) {
                    Ok(report) => {
                        let message = report.message.clone();
                        quarantine_result = serde_json::to_value(report).ok();
                        Ok(message)
                    }
                    Err(error) => {
                        error_status = quarantine_status_code(&error);
                        Err(format!("{}", error))
                    }
                }
            }),
        "RESTORE_QUARANTINE" => command_string(value, "id")
            .ok_or_else(|| "missing quarantine id".to_string())
            .and_then(|id| {
                let restore_path = command_string(value, "restore_path");
                let overwrite = command_bool(value.get("overwrite"), false);
                match crate::quarantine::restore_quarantine(id, restore_path, overwrite) {
                    Ok(report) => {
                        let message = report.message.clone();
                        quarantine_result = serde_json::to_value(report).ok();
                        Ok(message)
                    }
                    Err(error) => {
                        error_status = quarantine_status_code(&error);
                        Err(format!("{}", error))
                    }
                }
            }),
        "CLEAR_STEALER_FIREWALL" => Ok(format!("removed {} active StealerGuard firewall rule(s)", crate::stealer_guard::clear_active_firewall_rules().len())),
        "DELETE_QUARANTINE" => command_string(value, "id")
            .ok_or_else(|| "missing quarantine id".to_string())
            .and_then(|id| match crate::quarantine::delete_quarantine(id) {
                Ok(report) => {
                    let message = report.message.clone();
                    quarantine_result = serde_json::to_value(report).ok();
                    Ok(message)
                }
                Err(error) => {
                    error_status = quarantine_status_code(&error);
                    Err(format!("{}", error))
                }
            }),
"LIST_QUARANTINE" => {
            let include_inactive = command_bool(value.get("include_inactive"), false);
            match crate::quarantine::list_quarantine(include_inactive) {
                Ok(report) => {
                    let message = report.message.clone();
                    quarantine_result = serde_json::to_value(report).ok();
                    Ok(message)
                }
                Err(error) => {
                    error_status = quarantine_status_code(&error);
                    Err(format!("{}", error))
                }
            }
        }
        "EXPORT_QUARANTINE" => command_string(value, "path")
            .ok_or_else(|| "missing backup path".to_string())
            .and_then(|path| match crate::quarantine::export_quarantine(path) {
                Ok(report) => {
                    let message = report.message.clone();
                    quarantine_result = serde_json::to_value(report).ok();
                    Ok(message)
                }
                Err(error) => {
                    error_status = quarantine_status_code(&error);
                    Err(format!("{}", error))
                }
            }),
        "IMPORT_QUARANTINE" => command_string(value, "path")
            .ok_or_else(|| "missing backup path".to_string())
            .and_then(|path| match crate::quarantine::import_quarantine(path) {
                Ok(report) => {
                    let message = report.message.clone();
                    quarantine_result = serde_json::to_value(report).ok();
                    Ok(message)
                }
                Err(error) => {
                    error_status = quarantine_status_code(&error);
                    Err(format!("{}", error))
                }
            }),
        _ => Err(format!("unsupported NDJSON command: {raw_command}")),
    };

    match callback_result {
        Ok(message) => control_response_with_payloads(
            EngineStatusCode::Success,
            message,
            quarantine_result,
            model_validation_result,
        ),
        Err(message) => control_response_with_payloads(
            error_status,
            message,
            quarantine_result,
            model_validation_result,
        ),
    }
}

fn aggregate_status(results: &[ScanResult], timed_out: bool) -> EngineStatus {
    if timed_out {
        return status(
            EngineStatusCode::ErrTimeout,
            "Scan exceeded the requested timeout and was cancelled.",
        );
    }

    let has_threat = results.iter().any(|result| {
        matches!(
            contract_verdict(result),
            ContractVerdict::Malware | ContractVerdict::Suspicious
        )
    });
    let mut error_codes = results
        .iter()
        .filter_map(result_status_code)
        .collect::<Vec<_>>();

    if has_threat && !error_codes.is_empty() {
        return status(
            EngineStatusCode::ErrPartial,
            "Scan completed with partial errors.",
        );
    }

    if let Some(code) = error_codes.pop() {
        let message = match code {
            EngineStatusCode::ErrFileAccess => "File access error.",
            EngineStatusCode::ErrResource => "Resource limit reached.",
            EngineStatusCode::ErrInitialization => {
                "Engine initialization or layer availability error."
            }
            EngineStatusCode::ErrTimeout => "Scan timed out.",
            EngineStatusCode::ErrUnsupported => "Unsupported target or format.",
            EngineStatusCode::ErrExtraction => "Extraction or parsing error.",
            EngineStatusCode::ErrNetwork => "Network or cloud query error.",
            EngineStatusCode::ErrLicense => "License error.",
            EngineStatusCode::ErrPartial => "Scan completed with partial errors.",
            EngineStatusCode::ErrInternal => "Engine internal error.",
            EngineStatusCode::Success => "Scan completed successfully.",
        };
        return status(code, message);
    }

    status(EngineStatusCode::Success, "Scan completed successfully.")
}

fn matched_rules(result: &ScanResult) -> Vec<String> {
    let mut rules = result
        .yara_matches
        .iter()
        .map(|item| item.rule_name.clone())
        .collect::<Vec<_>>();
    if let Some(sequence_matches) = &result.sequence_matches {
        rules.extend(
            sequence_matches
                .iter()
                .map(|item| format!("sequence:{item}")),
        );
    }
    if let Some(prediction) = &result.static_sandbox {
        rules.extend(
            prediction
                .capabilities
                .iter()
                .take(16)
                .map(|item| format!("sbox_static:{item}")),
        );
        // ATT&CK techniques give the consumer a stable, vendor-neutral pivot
        // for correlation without having to parse capability strings.
        rules.extend(
            prediction
                .attack_techniques
                .iter()
                .take(16)
                .map(|item| format!("attack:{item}")),
        );
    }

    let reason = result
        .reason
        .strip_prefix("cached:")
        .unwrap_or(&result.reason);
    if !reason.is_empty()
        && reason != "unknown"
        && reason != "browser_cookie_store_metadata_only"
        && !reason.starts_with("allowlisted:")
    {
        rules.push(reason.to_string());
    }

    rules.sort();
    rules.dedup();
    rules
}

fn confidence(result: &ScanResult, verdict: ContractVerdict) -> Option<f32> {
    match verdict {
        ContractVerdict::Malware => {
            let mut score = 98.0f32;
            if result.reason.starts_with("hash:") || result.reason.starts_with("cached:hash:") {
                score = 99.9;
            } else if result.reason.starts_with("fuzzy_hash:") {
                score = parse_similarity(&result.reason).unwrap_or(92.0);
            } else if result.reason.starts_with("yara:") {
                score = 98.5;
            } else if let Some(value) = result.ai_score {
                score = score.max(value * 100.0);
            } else if let Some(value) = result.heuristic_score {
                score = score.max(value * 100.0);
            }
            Some(round_one(score.clamp(0.0, 100.0)))
        }
        ContractVerdict::Suspicious => {
            let score = result
                .behavior_score
                .or(result.heuristic_score)
                .or(result.ai_score)
                .map(|value| value * 100.0)
                .unwrap_or(65.0);
            Some(round_one(score.clamp(0.0, 100.0)))
        }
        ContractVerdict::Benign => Some(100.0),
        ContractVerdict::Undetected => Some(0.0),
    }
}

fn parse_similarity(reason: &str) -> Option<f32> {
    let marker = "similarity=";
    let start = reason.find(marker)? + marker.len();
    let value = reason[start..]
        .split(|ch| ch == ':' || ch == ',' || ch == ';')
        .next()?;
    value
        .parse::<f32>()
        .ok()
        .map(|value| if value <= 1.0 { value * 100.0 } else { value })
}

fn round_one(value: f32) -> f32 {
    (value * 10.0).round() / 10.0
}

fn threat_name(result: &ScanResult, verdict: ContractVerdict) -> Option<String> {
    if !matches!(
        verdict,
        ContractVerdict::Malware | ContractVerdict::Suspicious
    ) {
        return None;
    }

    let reason = result
        .reason
        .strip_prefix("cached:")
        .unwrap_or(&result.reason);
    if let Some(rule) = result.yara_matches.first() {
        return Some(rule.rule_name.clone());
    }
    if let Some(label) = reason.strip_prefix("hash:") {
        return Some(format!(
            "HashDB.{}",
            label.split(':').next().unwrap_or("Malware")
        ));
    }
    if let Some(label) = reason.strip_prefix("fuzzy_hash:") {
        return Some(format!(
            "FuzzyHash.{}",
            label.split(':').next().unwrap_or("SimilarMalware")
        ));
    }
    if reason.starts_with("cookie_theft_detected:") {
        return Some("Trojan.CookieTheft.Generic".to_string());
    }
    if reason.starts_with("script_trojan:") {
        return Some("Trojan.Script.Generic".to_string());
    }
    // `high_confidence_override` is the fusion-policy form of the two legacy
    // direct decisions below; keep the user-visible naming identical so a
    // report does not change meaning when fusion is attached.
    if let Some(rest) = reason.strip_prefix("fusion:high_confidence_override:") {
        return Some(
            if rest.contains("source=ai") {
                "ML.Generic.Malware"
            } else {
                "Heur.Generic.HighRisk"
            }
            .to_string(),
        );
    }
    if reason == "heuristic_high" {
        return Some("Heur.Generic.HighRisk".to_string());
    }
    if reason == "ai_high" {
        return Some("ML.Generic.Malware".to_string());
    }
    if reason.starts_with("threat_intel:") {
        return Some("ThreatIntel.NetworkIOC.Generic".to_string());
    }
    if reason.starts_with("behavior_score:") || reason.starts_with("behavior_sequence:") {
        return Some("Behavior.Generic.Malware".to_string());
    }
    if reason.starts_with("fusion:") {
        return Some("Suspicious.MultiEngine.Fusion".to_string());
    }
    if reason == "sandbox_behavior" {
        return Some("Sandbox.Behavior.Generic".to_string());
    }
    Some(match verdict {
        ContractVerdict::Malware => "Malware.Generic".to_string(),
        ContractVerdict::Suspicious => "Suspicious.Generic".to_string(),
        ContractVerdict::Benign | ContractVerdict::Undetected => return None,
    })
}

fn threat_category(result: &ScanResult, verdict: ContractVerdict) -> Option<String> {
    if !matches!(
        verdict,
        ContractVerdict::Malware | ContractVerdict::Suspicious
    ) {
        return None;
    }
    let reason = result
        .reason
        .strip_prefix("cached:")
        .unwrap_or(&result.reason);
    let lower = reason.to_ascii_lowercase();
    if lower.contains("ransom") || lower.contains("wannacry") {
        Some("Ransomware".to_string())
    } else if lower.contains("cookie") || lower.contains("credential") || lower.contains("steal") {
        Some("CredentialTheft".to_string())
    } else if lower.contains("script") || lower.contains("trojan") {
        Some("Trojan".to_string())
    } else if lower.contains("threat_intel") || lower.contains("network") {
        Some("NetworkIOC".to_string())
    } else if matches!(verdict, ContractVerdict::Suspicious) {
        Some("Suspicious".to_string())
    } else {
        Some("Malware".to_string())
    }
}

fn primary_result(results: &[ScanResult]) -> Option<&ScanResult> {
    results
        .iter()
        .max_by_key(|result| contract_verdict(result).rank())
}

/// Extract chain names from the reason strings produced by the sequence and
/// sequence-tolerant fusion branches. Only these two prefixes carry chain
/// names; the atc/static/hips/sandbox_flags reasons embed evidence labels in
/// the trailing segment and are intentionally ignored.
fn chain_names_from_reason(reason: &str) -> Option<(&str, Vec<String>)> {
    let prefix = if reason.starts_with("fusion:kaspersky_sequence_tolerant:") {
        "tolerant"
    } else if reason.starts_with("fusion:kaspersky_sequence:")
        || reason.starts_with("behavior_sequence:")
    {
        "strict"
    } else {
        return None;
    };
    let names = reason
        .rsplit(':')
        .next()
        .map(|segment| {
            segment
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })?
    ;
    Some((prefix, names))
}

/// Resolve the attack chains referenced by a scan result into renderable
/// frames. Strict chain names ride in `ScanResult.sequence_matches`; tolerant
/// names are only recorded in the fusion reason string, so both are combined
/// here. Unknown trailing segments (evidence labels) resolve to no chains.
fn build_attack_chains(result: &ScanResult) -> Vec<AttackChainPayload> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let stage = result.reason.split("stage=").nth(1).map_or_else(
        || {
            if result.malicious {
                "intervene"
            } else {
                "observe"
            }
        },
        |segment| {
            let stage = segment.split(':').next().unwrap_or("observe");
            match stage {
                "intervene" | "correlate" | "observe" => stage,
                _ => "observe",
            }
        },
    );

    let mut push_chain = |name: String, matched_by: &str, out: &mut Vec<AttackChainPayload>| {
        if seen.insert(name.clone()) {
            if let Some(frame) = AttackChainPayload::build(&name, stage, matched_by) {
                out.push(frame);
            }
        }
    };

    if let Some(names) = result.sequence_matches.as_ref() {
        for name in names {
            push_chain(name.clone(), "strict", &mut out);
        }
    }
    if let Some((matched_by, names)) = chain_names_from_reason(&result.reason) {
        for name in names {
            push_chain(name, matched_by, &mut out);
        }
    }
    out
}

fn scan_result_payload(results: &[ScanResult]) -> ScanResultPayload {
    let verdict = aggregate_contract_verdict(results);
    let primary = primary_result(results);
    let confidence = primary.and_then(|result| confidence(result, verdict));
    let top_threat_name = primary.and_then(|result| threat_name(result, verdict));
    let threat_category = primary.and_then(|result| threat_category(result, verdict));
    let mut matched_rules = results.iter().flat_map(matched_rules).collect::<Vec<_>>();
    matched_rules.sort();
    matched_rules.dedup();

    let details = if results.len() > 1 {
        results
            .iter()
            .filter_map(|result| {
                let verdict = contract_verdict(result);
                if !matches!(
                    verdict,
                    ContractVerdict::Malware | ContractVerdict::Suspicious
                ) {
                    return None;
                }
                Some(ScanDetail {
                    file_path: normalize_path_string(&result.path.to_string_lossy()),
                    threat_name: threat_name(result, verdict),
                    verdict,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

ScanResultPayload {
        verdict,
        confidence,
        threat_name: top_threat_name,
        threat_category,
        matched_rules,
        details,
        attack_chains: {
            let chains = results.iter().flat_map(build_attack_chains).collect::<Vec<_>>();
            if chains.is_empty() {
                None
            } else {
                Some(chains)
            }
        },
    }
}

fn sandbox_analysis_payload(results: &[ScanResult]) -> Option<SandboxAnalysisPayload> {
    let report = results
        .iter()
        .filter_map(|result| result.sandbox.as_ref())
        .max_by_key(|report| {
            (
                report.unpacking.recovered_entry_points,
                report.unpacking.candidate_images,
                report.unpacking.snapshot_rounds,
            )
        })?;
    Some(SandboxAnalysisPayload {
        backend: report.isolation_backend.clone(),
        status: report.unpacking.status.clone(),
        snapshot_rounds: report.unpacking.snapshot_rounds,
        triggered_snapshots: report.unpacking.triggered_snapshots,
        adaptive_timeout_ms: report.unpacking.adaptive_timeout_ms,
        candidate_images: report.unpacking.candidate_images,
        recovered_entry_points: report.unpacking.recovered_entry_points,
        observed_execution_points: report.unpacking.observed_execution_points,
        bytes_captured: report.unpacking.bytes_captured,
        truncated: report.unpacking.truncated,
        timed_out: report.timed_out,
        isolation_verified: report.isolation_verified,
        cleanup_verified: report.cleanup_verified,
        notes: report.unpacking.notes.clone(),
    })
}

fn metadata(scan_time_ms: u128, trace_id: &str) -> EngineMetadata {
    EngineMetadata {
        engine_name: ENGINE_NAME,
        engine_version: env!("CARGO_PKG_VERSION"),
        signature_version: std::env::var("EVERBLOOM_SIGNATURE_VERSION")
            .unwrap_or_else(|_| "local".to_string()),
        trace_id: trace_id.to_string(),
        scan_time_ms,
        scan_timestamp: timestamp_now_utc(),
    }
}

fn timestamp_now_utc() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_unix_timestamp(now.as_secs() as i64, now.subsec_millis())
}

fn format_unix_timestamp(seconds: i64, millis: u32) -> String {
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year as i32, month as u32, day as u32)
}

async fn handle_request(
    scanner: Arc<Scanner>,
    runtime: NdjsonRuntime,
    line: String,
) -> RequestAction {
    let line = line.trim_end_matches(['\r', '\n']);
    let value = match serde_json::from_str::<Value>(line) {
        Ok(value) => value,
        Err(error) => {
            return RequestAction::Continue(error_response(
                TargetInfo {
                    task_id: None,
                    file_path: None,
                    file_name: None,
                    sha256: None,
                },
                EngineStatusCode::ErrInternal,
                format!("Malformed JSON request received or essential fields missing: {error}"),
            ));
        }
    };

    if value
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command.eq_ignore_ascii_case("EXIT"))
    {
        return RequestAction::Shutdown(ready_response("Engine is shutting down."));
    }

    if value.get("command").is_some() {
        return RequestAction::Continue(handle_control_command(&runtime, &value));
    }

    let request = match parse_request_value(value) {
        Ok(request) => request,
        Err((target_info, code, message)) => {
            return RequestAction::Continue(error_response(target_info, code, message));
        }
    };
    // `parse_request_value` requires task_id for a valid scan request. Keep a
    // defensive fallback so future protocol extensions cannot accidentally
    // emit an empty correlation id.
    let trace_id = request
        .target_info
        .task_id
        .clone()
        .unwrap_or_else(|| "engine-unattributed-scan".to_string());

    if !request.file_path.exists() {
        return RequestAction::Continue(error_response(
            request.target_info,
            EngineStatusCode::ErrFileAccess,
            "Target file does not exist or is inaccessible.",
        ));
    }

    let actual_sha256 =
        match verify_expected_sha256(&request.file_path, request.target_info.sha256.as_deref()) {
            Ok(actual) => actual,
            Err(error) => {
                return RequestAction::Continue(error_response(
                    request.target_info,
                    EngineStatusCode::ErrInternal,
                    error,
                ));
            }
        };
    let mut target_info = request.target_info.clone();
    if target_info.sha256.is_none() {
        target_info.sha256 = actual_sha256;
    }

    if request.max_archive_depth != DEFAULT_ARCHIVE_DEPTH {
        log::debug!(
            "NDJSON request set max_archive_depth={}; archive recursion is reserved for the archive layer",
            request.max_archive_depth
        );
    }

    let cancelled = Arc::new(AtomicBool::new(false));
    let scan_request = build_scan_request(&scanner, &request, cancelled.clone());
    let cancel_task = if request.timeout_ms > 0 {
        let cancelled = cancelled.clone();
        Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(request.timeout_ms)).await;
            cancelled.store(true, Ordering::Relaxed);
        }))
    } else {
        None
    };

    let started = Instant::now();
    let scan_result = scanner.scan_request(scan_request).await;
    if let Some(cancel_task) = cancel_task {
        cancel_task.abort();
    }
    let scan_time_ms = started.elapsed().as_millis();
    let timed_out = cancelled.load(Ordering::Relaxed);

    match scan_result {
        Ok(mut results) => {
            if request.max_archive_depth > 0
                && is_archive_path(&request.file_path)
                && !cancelled.load(Ordering::Relaxed)
            {
                let mut archive_results =
                    scan_archive_children(scanner.clone(), &request, cancelled.clone()).await;
                results.append(&mut archive_results);
            }
            let response = ScanResponse {
                target_info,
                engine_status: aggregate_status(&results, timed_out),
                scan_result: scan_result_payload(&results),
                engine_metadata: metadata(scan_time_ms, &trace_id),
                sandbox_analysis: sandbox_analysis_payload(&results),
            };
            RequestAction::Continue(serde_json::to_value(response).unwrap_or_else(|_| {
                error_response(
                    TargetInfo {
                        task_id: None,
                        file_path: None,
                        file_name: None,
                        sha256: None,
                    },
                    EngineStatusCode::ErrInternal,
                    "serialization error",
                )
            }))
        }
        Err(error) => RequestAction::Continue(error_response(
            target_info,
            EngineStatusCode::ErrInternal,
            format!("Engine internal error: {error}"),
        )),
    }
}

async fn write_response(writer: &mut BufWriter<io::Stdout>, response: &Value) -> io::Result<()> {
    let encoded = serde_json::to_vec(response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writer.write_all(&encoded).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

async fn write_kernel_events(writer: &mut BufWriter<io::Stdout>) -> io::Result<()> {
    let dropped = crate::monitoring::drain_kernel_event_dropped();
    if dropped > 0 {
        let frame = serde_json::json!({
            "engine_event": {
                "kind": "kernel_event_overflow",
                "dropped": dropped
            }
        });
        write_response(writer, &frame).await?;
    }
    for event in crate::monitoring::drain_kernel_events() {
        let event_kind = if event.status == 0 {
            "KERNEL_ALERT"
        } else {
            "KERNEL_BLOCK"
        };
        let frame = serde_json::json!({
            "engine_event": {
                "kind": event_kind,
                "target": normalize_path_string(&event.target),
                "reason": event.reason,
                "pid": event.caller_pid,
                "sequence": event.sequence,
                "status": event.status,
                "timestamp": event.timestamp
            }
        });
        write_response(writer, &frame).await?;
    }
    Ok(())
}

async fn write_r3_hips_events(writer: &mut BufWriter<io::Stdout>) -> io::Result<()> {
    let (hips_dropped, review_dropped) = crate::hips::drain_event_dropped();
    if hips_dropped > 0 || review_dropped > 0 {
        let frame = serde_json::json!({
            "engine_event": {
                "kind": "r3_event_overflow",
                "hips_dropped": hips_dropped,
                "driver_review_dropped": review_dropped
            }
        });
        write_response(writer, &frame).await?;
    }
    let (etw_dropped, kernel_queue_dropped) = crate::monitoring::drain_queue_dropped();
    if etw_dropped > 0 || kernel_queue_dropped > 0 {
        let frame = serde_json::json!({
            "engine_event": {
                "kind": "monitoring_queue_overflow",
                "etw_dropped": etw_dropped,
                "kernel_queue_dropped": kernel_queue_dropped
            }
        });
        write_response(writer, &frame).await?;
    }
    for event in crate::hips::drain_hips_events() {
        let event_type = hips_event_type(&event);
        let frame = serde_json::json!({
            "engine_event": {
                "kind": "R3_HIPS_ALERT",
                "event_type": event_type,
                "target": "",
                "reason": event.description(),
                "pid": event.process_id(),
                "status": 0,
                "timestamp": timestamp_now_utc()
            }
        });
        write_response(writer, &frame).await?;
    }
    Ok(())
}

fn hips_event_type(event: &crate::hips::HipsEvent) -> &'static str {
    match event {
        crate::hips::HipsEvent::SuspiciousProcessChain { .. } => "process_chain",
        crate::hips::HipsEvent::SuspiciousRwxRegion { .. } => "rwx_memory",
        crate::hips::HipsEvent::SuspiciousMemoryLoad { .. } => "private_executable_memory",
        crate::hips::HipsEvent::SuspiciousApcInjection { .. } => "apc_injection",
        crate::hips::HipsEvent::SuspiciousThreadPoolInjection { .. } => "thread_pool_injection",
        crate::hips::HipsEvent::SuspiciousReflectivePe { .. } => "reflective_pe",
        crate::hips::HipsEvent::SuspiciousModuleBaseline { .. } => "module_baseline",
        crate::hips::HipsEvent::SuspiciousDllLoad { .. } => "dll_load",
        crate::hips::HipsEvent::CtfHijackDllLoad { .. } => "ctf_hijack",
        crate::hips::HipsEvent::WhiteBlackSideLoad { .. } => "white_black_sideload",
        crate::hips::HipsEvent::SuspiciousApiPatch { .. } => "api_patch",
        crate::hips::HipsEvent::SuspiciousThreadStack { .. } => "thread_stack",
        crate::hips::HipsEvent::CookieTheftSuspected { .. } => "cookie_theft",
        crate::hips::HipsEvent::SuspiciousPplProcess { .. } => "ppl_process",
        crate::hips::HipsEvent::DriverBlocked { .. } => "driver_blocked",
    }
}

async fn write_stealer_protection_events(writer: &mut BufWriter<io::Stdout>) -> io::Result<()> {
    for event in crate::stealer_guard::drain_protection_events() {
        let frame = serde_json::json!({
            "engine_event": {
                "kind": "STEALER_PROTECTION",
                "target": normalize_path_string(&event.process_path),
                "reason": event.message,
                "pid": event.pid,
                "status": if event.firewall_applied { 1 } else { 0 },
                "score": event.score_percent,
                "indicators": event.indicators,
                "firewall_rule": event.firewall_rule,
                "firewall_applied": event.firewall_applied,
                "timestamp": timestamp_now_utc()
            }
        });
        write_response(writer, &frame).await?;
    }
    Ok(())
}
/// Streams live kernel/Sysmon/sandbox behavioral telemetry (file, registry,
/// process, network) to the GUI as R3_BEHAVIOR frames. These are observations,
/// never enforcement: the UI renders them exactly like HIPS alerts, and the
/// per-event pid keeps the process chain attributable. The shared queue is
/// ring-bounded by `monitoring`; the per-flush cap additionally protects the
/// protocol stream from a single pathological burst.
async fn write_behavior_events(writer: &mut BufWriter<io::Stdout>) -> io::Result<()> {
    // Optional encryption of behavior payloads when the operator sets
    // EVERBLOOM_ENCRYPT_BEHAVIOR. The event_type, pid, status and timestamp
    // remain in plaintext for rapid filtering; only the detail/reason payload
    // is encrypted using the custom stream cipher (crypto.rs).
    let encrypt_payload = std::env::var("EVERBLOOM_ENCRYPT_BEHAVIOR").is_ok();
    let cipher_key = if encrypt_payload { Some(b"EVERBLOOM_BEHAVIOR_KEY" as &[u8]) } else { None };

    for event in crate::monitoring::drain_behavior_events()
        .into_iter()
        .take(128)
    {
        let event_type = event.kind.as_str();
        let pid = event.process_id.unwrap_or(0);
        let (target_value, reason_value, encrypted_flag) = if encrypt_payload {
            // Encrypt the detail string and rebuild the reason with a
            // shorter descriptor (not leaking the full path in plaintext).
            let encrypted_detail_bytes = crate::crypto::encrypt_payload(event.detail.as_bytes(), cipher_key.unwrap());
            let encrypted_detail_base64 = crate::layers::unpacking::encode_base64(&encrypted_detail_bytes)
                .into_iter()
                .map(|b| b as char)
                .collect::<String>();
            let short_reason = format!("behavior ({event_type}) pid={pid} [encrypted payload]");
            (encrypted_detail_base64, short_reason, true)
        } else {
            (event.detail.clone(), format!("behavior ({event_type}) pid={pid}: {}", event.detail), false)
        };
        let frame = serde_json::json!({
            "engine_event": {
                "kind": "R3_BEHAVIOR",
                "event_type": event_type,
                "target": target_value,
                "reason": reason_value,
                "pid": pid,
                "status": 0,
                "encrypted": encrypted_flag,
                "timestamp": timestamp_now_utc()
            }
        });
        write_response(writer, &frame).await?;
    }
    Ok(())
}
async fn write_engine_metrics(writer: &mut BufWriter<io::Stdout>) -> io::Result<()> {
    let frame = serde_json::json!({
        "engine_metrics": crate::metrics::snapshot()
    });
    write_response(writer, &frame).await
}

/// Runs the resident NDJSON engine loop until EOF or an `{"command":"EXIT"}` line.
pub async fn run_ndjson(scanner: Arc<Scanner>, runtime: NdjsonRuntime) -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout);
    let mut line = Vec::new();

    write_response(
        &mut writer,
        &ready_response("Engine initialized and ready."),
    )
    .await?;

    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line).await?;
        if bytes_read == 0 {
            break;
        }

        if line.len() > MAX_NDJSON_LINE_BYTES {
            let response = error_response(
                TargetInfo {
                    task_id: None,
                    file_path: None,
                    file_name: None,
                    sha256: None,
                },
                EngineStatusCode::ErrResource,
                format!(
                    "request exceeds maximum NDJSON line size of {MAX_NDJSON_LINE_BYTES} bytes"
                ),
            );
            write_response(&mut writer, &response).await?;
            continue;
        }

        let line = match String::from_utf8(std::mem::take(&mut line)) {
            Ok(line) => line,
            Err(_) => {
                let response = error_response(
                    TargetInfo {
                        task_id: None,
                        file_path: None,
                        file_name: None,
                        sha256: None,
                    },
                    EngineStatusCode::ErrInternal,
                    "invalid UTF-8 request line",
                );
                write_response(&mut writer, &response).await?;
                continue;
            }
        };

        // A task boundary converts an unexpected scanner panic into a standard
        // error response and keeps the resident protocol loop alive.
        let panic_target_info = serde_json::from_str::<Value>(&line)
            .ok()
            .map(|value| target_info_hint(Some(&value)))
            .unwrap_or_else(|| target_info_hint(None));
        let result = tokio::spawn(handle_request(scanner.clone(), runtime.clone(), line)).await;
        let action = match result {
            Ok(action) => action,
            Err(error) => {
                log::error!("NDJSON request task failed: {}", error);
                RequestAction::Continue(error_response(
                    panic_target_info,
                    EngineStatusCode::ErrInternal,
                    format!("request task failed safely: {error}"),
                ))
            }
        };

        let should_shutdown = matches!(action, RequestAction::Shutdown(_));
        let response = match action {
            RequestAction::Continue(response) | RequestAction::Shutdown(response) => response,
        };
        write_response(&mut writer, &response).await?;
write_kernel_events(&mut writer).await?;
        write_r3_hips_events(&mut writer).await?;
        write_stealer_protection_events(&mut writer).await?;
        write_behavior_events(&mut writer).await?;
        write_engine_metrics(&mut writer).await?;
        if should_shutdown {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
use super::{
        aggregate_contract_verdict, build_attack_chains, error_response, format_unix_timestamp,
        is_archive_path, parse_request_value, ready_response, scan_result_payload,
        validate_7z_listing, validate_archive_member_path, ContractVerdict, EngineStatusCode,
        TargetInfo,
    };
    use crate::scanner::ScanResult;
    use serde_json::Value;
    use std::path::{Path, PathBuf};

    fn parse_value(text: &str) -> Value {
        serde_json::from_str(text).expect("test JSON parses")
    }

    #[test]
    fn ready_handshake_uses_contract_status() {
        let value = ready_response("Engine initialized and ready.");
        assert_eq!(value["engine_status"]["code"], "SUCCESS");
        assert_eq!(
            value["engine_status"]["message"],
            "Engine initialized and ready."
        );
    }

    #[test]
    fn missing_task_id_returns_simplified_error_with_target_info() {
        let value = parse_value(
            r#"{
                "task_info": {"timeout_ms": 30000},
                "target": {"type": "LOCAL_PATH", "file_path": "D:/sample.bin"}
            }"#,
        );
        let error = parse_request_value(value).unwrap_err();
        assert_eq!(error.0.file_path.as_deref(), Some("D:/sample.bin"));
        assert_eq!(error.1, EngineStatusCode::ErrInternal);
    }

    #[test]
    fn redundant_fields_are_ignored() {
        let value = parse_value(
            r#"{
                "task_info": {
                    "task_id": "req_1",
                    "priority": "HIGH",
                    "timeout_ms": 30000,
                    "future_field": true
                },
                "target": {
                    "type": "LOCAL_PATH",
                    "file_path": "D:/sample.bin",
                    "file_name": "sample.bin",
                    "unknown": "ignored"
                },
                "scan_options": {
                    "enable_heuristics": true,
                    "max_archive_depth": 3,
                    "max_file_size_mb": 50,
                    "another_unknown": 1
                }
            }"#,
        );
        let request = parse_request_value(value).expect("extra fields are ignored");
        assert_eq!(request.target_info.task_id.as_deref(), Some("req_1"));
        assert_eq!(request.max_file_size_bytes, 50 * 1024 * 1024);
    }

    #[test]
    fn unsupported_target_type_uses_supported_status_dictionary() {
        let value = parse_value(
            r#"{
                "task_info": {"task_id": "req_1", "timeout_ms": 30000},
                "target": {"type": "REMOTE_URL", "file_path": "https://example.test/a"}
            }"#,
        );
        let error = parse_request_value(value).unwrap_err();
        assert_eq!(error.1, EngineStatusCode::ErrUnsupported);
    }

    #[test]
    fn highest_watermark_verdict_matches_contract_order() {
        let benign = ScanResult {
            path: PathBuf::from("safe.exe"),
            malicious: false,
            reason: "allowlisted:path".to_string(),
            yara_matches: Vec::new(),
            heuristic_score: None,
            heuristic_indicators: Vec::new(),
            ai_score: None,
            ai_components: Vec::new(),
            ai_fallback_reason: None,
            behavior_score: None,
            sequence_matches: None,
            sandbox: None,
            process_state: None,
            rollback_record: None,
            rollback_actions: None,
            static_sandbox: None,
            error: None,
            duration_ms: 1,
        };
        let suspicious = ScanResult {
            reason: "fusion:multi_signal".to_string(),
            ..benign.clone()
        };
        let malware = ScanResult {
            path: PathBuf::from("bad.exe"),
            malicious: true,
            reason: "heuristic_high".to_string(),
            ..benign.clone()
        };
        assert_eq!(
            aggregate_contract_verdict(&[benign, suspicious, malware]),
            ContractVerdict::Malware
        );
    }

    #[test]
    fn simplified_error_keeps_target_info_node() {
        let value = error_response(
            TargetInfo {
                task_id: None,
                file_path: None,
                file_name: None,
                sha256: None,
            },
            EngineStatusCode::ErrInternal,
            "bad input",
        );
        assert!(value.get("target_info").is_some());
        assert_eq!(value["target_info"]["task_id"], Value::Null);
        assert_eq!(value["engine_status"]["code"], "ERR_INTERNAL");
    }

    #[test]
    fn archive_member_paths_reject_escape_and_absolute_names() {
        assert!(validate_archive_member_path("../payload.exe").is_err());
        assert!(validate_archive_member_path(r"C:\Windows\System32\payload.exe").is_err());
        assert!(validate_archive_member_path(r"\Windows\payload.exe").is_err());
        assert!(validate_archive_member_path("safe/payload.exe").is_ok());
        assert!(validate_archive_member_path("./safe/payload.exe").is_ok());
    }

    #[test]
    fn archive_format_detection_covers_reference_formats() {
        for path in [
            "sample.zip",
            "sample.7z",
            "sample.rar",
            "sample.msi",
            "sample.tar.gz",
            "sample.xz",
        ] {
            assert!(is_archive_path(Path::new(path)), "{path}");
        }
        assert!(!is_archive_path(Path::new("sample.exe")));
    }

    #[test]
    fn seven_zip_listing_enforces_entry_and_total_limits() {
        let listing = b"Path = payload.exe\nSize = 16\nFolder = -\n\n";
        assert!(validate_7z_listing(listing, 32, 32).is_ok());
        assert!(validate_7z_listing(listing, 8, 32).is_err());
        assert!(validate_7z_listing(listing, 32, 8).is_err());

        let unsafe_listing = b"Path = ../payload.exe\nSize = 1\nFolder = -\n\n";
        assert!(validate_7z_listing(unsafe_listing, 32, 32).is_err());
    }
#[test]
    fn timestamp_format_is_iso_utc() {
        assert_eq!(
            format_unix_timestamp(1_714_998_615, 123),
            "2024-05-06T12:30:15.123Z"
        );
    }

    #[test]
    fn strict_sequence_reason_yields_intervene_chain_frame() {
        let result = ScanResult {
            path: PathBuf::from("bad.exe"),
            malicious: true,
            reason: "fusion:kaspersky_sequence:stage=intervene:persistence_chain,network_dropper"
                .to_string(),
            sequence_matches: Some(vec![
                "persistence_chain".to_string(),
                "network_dropper".to_string(),
            ]),
            ..ScanResult {
                path: PathBuf::from("bad.exe"),
                malicious: false,
                reason: String::new(),
                yara_matches: Vec::new(),
                heuristic_score: None,
                heuristic_indicators: Vec::new(),
                ai_score: None,
                ai_components: Vec::new(),
                ai_fallback_reason: None,
                behavior_score: None,
                sequence_matches: None,
                sandbox: None,
                process_state: None,
                rollback_record: None,
                rollback_actions: None,
                static_sandbox: None,
                error: None,
                duration_ms: 1,
            }
        };
        let chains = build_attack_chains(&result);
        assert_eq!(chains.len(), 2, "strict names resolved");
        let chain = &chains[0];
        assert_eq!(chain.chain, "persistence_chain");
        assert_eq!(chain.stage, "intervene");
        assert!(!chain.tolerant);
        assert_eq!(chain.matched_by, "strict");
        assert_eq!(chain.step_labels, vec!["registry_write", "file_write", "process_create"]);
    }

    #[test]
    fn tolerant_sequence_reason_yields_correlate_tolerant_frame() {
        let result = ScanResult {
            path: PathBuf::from("maybe.exe"),
            malicious: false,
            reason: "fusion:kaspersky_sequence_tolerant:stage=correlate:events=5:score=0.40:loader_module_codeexec_chain"
                .to_string(),
            sequence_matches: None,
            ..ScanResult {
                path: PathBuf::from("maybe.exe"),
                malicious: false,
                reason: String::new(),
                yara_matches: Vec::new(),
                heuristic_score: None,
                heuristic_indicators: Vec::new(),
                ai_score: None,
                ai_components: Vec::new(),
                ai_fallback_reason: None,
                behavior_score: None,
                sequence_matches: None,
                sandbox: None,
                process_state: None,
                rollback_record: None,
                rollback_actions: None,
                static_sandbox: None,
                error: None,
                duration_ms: 1,
            }
        };
        let chains = build_attack_chains(&result);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].chain, "loader_module_codeexec_chain");
        assert_eq!(chains[0].stage, "correlate");
        assert!(chains[0].tolerant);
        assert_eq!(chains[0].matched_by, "tolerant");
        assert_eq!(
            chains[0].step_labels,
            vec![
                "process_create",
                "suspicious_module_load",
                "suspicious_api_call",
                "process_inject"
            ]
        );
    }

    #[test]
    fn non_sequence_reasons_produce_no_chain_frames() {
        for reason in [
            "sandbox_behavior",
            "heuristic_high",
            "fusion:atc:0.91:stage=intervene:evidence=2:file_write,suspicious_api_call",
            "fusion:hips:stage=intervene:evidence=3:a|b|c",
            "fusion:static:stage=correlate:heuristic=0.91:ai=0.70:combined=0.78:corroboration=0.70",
        ] {
            let result = ScanResult {
                path: PathBuf::from("sample.exe"),
                malicious: reason.starts_with("fusion:atc"),
                reason: reason.to_string(),
                sequence_matches: None,
                ..ScanResult {
                    path: PathBuf::from("sample.exe"),
                    malicious: false,
                    reason: String::new(),
                    yara_matches: Vec::new(),
                    heuristic_score: None,
                    heuristic_indicators: Vec::new(),
                    ai_score: None,
                    ai_components: Vec::new(),
                    ai_fallback_reason: None,
                    behavior_score: None,
                    sequence_matches: None,
                    sandbox: None,
                    process_state: None,
                    rollback_record: None,
                    rollback_actions: None,
                    static_sandbox: None,
                    error: None,
                    duration_ms: 1,
                }
            };
            assert!(
                build_attack_chains(&result).is_empty(),
                "reason `{reason}` must not resolve to chains"
            );
        }
    }

    #[test]
    fn scan_result_payload_embeds_attack_chains_only_when_present() {
        let benign = ScanResult {
            path: PathBuf::from("safe.exe"),
            malicious: false,
            reason: "allowlisted:path".to_string(),
            yara_matches: Vec::new(),
            heuristic_score: None,
            heuristic_indicators: Vec::new(),
            ai_score: None,
            ai_components: Vec::new(),
            ai_fallback_reason: None,
            behavior_score: None,
            sequence_matches: None,
            sandbox: None,
            process_state: None,
            rollback_record: None,
            rollback_actions: None,
            static_sandbox: None,
            error: None,
            duration_ms: 1,
        };
        let clean_payload = scan_result_payload(&[benign.clone()]);
        assert!(clean_payload.attack_chains.is_none());

        let malicious = ScanResult {
            malicious: true,
            reason: "fusion:kaspersky_sequence:stage=intervene:ransomware_impact_chain".to_string(),
            sequence_matches: Some(vec!["ransomware_impact_chain".to_string()]),
            ..benign
        };
        let payload = scan_result_payload(&[malicious]);
        let chains = payload.attack_chains.expect("malicious payload carries chains");
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].step_labels, vec!["file_write", "backup_deletion", "ransomware_encryption"]);
    }
}
