use std::cmp::Ordering;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering as AtomicOrdering},
    Arc, Once,
};
use std::time::Instant;

use rayon::prelude::*;
use tokio::runtime::Handle;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;

use log::{debug, info, warn};
use thiserror::Error;
use walkdir::WalkDir;

use crate::allowlist::Allowlist;
use crate::driver_bridge::{known_vulnerable_driver_name, DriverBridge};
use crate::hips::{self, HipsEvent};
use crate::layers::ai::AiModel;
use crate::layers::clamav::{ClamAvClient, ClamAvVerdict};
use crate::layers::behavior::{
    BehaviorEvent, BehaviorEventKind, BehaviorScoreResult, BehavioralScorer,
};
use crate::layers::cache::{
    FileFingerprint, ScanCache, ScanContext, ScanResult as CacheScanResult,
};
use crate::layers::cookie_guard::{
    analyze_bytes as analyze_cookie_bytes, is_browser_cookie_store, is_cookie_guard_candidate_file,
};
use crate::layers::fusion::{FusionDecision, FusionInput, ProtectionFusion};
use crate::layers::hash::HashMatcher;
use crate::layers::heuristic::STATIC_RULES_VERSION;
use crate::layers::heuristic::{analyze_bytes_with_context, analyze_script_bytes};
use crate::layers::process_state::{ProcessState, ProcessStateMachine};
use crate::layers::rollback::{RollbackExecutor, RollbackPlanner, RollbackRecord};
use crate::layers::sequence::SequenceMatcher;
use crate::layers::threat_intel::ThreatIntelMatcher;
use crate::layers::yara::YaraScanner;
use crate::monitoring;
use crate::protection_state;
use crate::sandbox::{run_sandbox_with_cancel, SandboxReport, SANDBOX_POLICY_VERSION};

const DEFAULT_MAXIMUM_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;
// Static engines receive a bounded, distributed sample for very large files.
// Exact and fuzzy hashes still stream over the complete file, so appending
// filler bytes cannot turn a known sample into a clean result while keeping
// parallel scan memory bounded.
const MAX_STATIC_ANALYSIS_BYTES: usize = 64 * 1024 * 1024;
const STATIC_ANALYSIS_WINDOWS: usize = 8;
const DEFAULT_MAX_SCAN_FILES: usize = 100_000;
const MAX_ALLOWED_SCAN_FILES: usize = 1_000_000;

/// Per-file scan result produced by the orchestrator.
///
/// Sandbox report is attached for all samples that reach the sandbox stage,
/// regardless of whether the sample is ultimately marked malicious.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: PathBuf,
    pub malicious: bool,
    pub reason: String,
    pub yara_matches: Vec<crate::layers::yara::YaraMatch>,
    pub heuristic_score: Option<f32>,
    /// Rule/family names that produced `heuristic_score`. Kept alongside the
    /// score because a bare 0.76 cannot answer the only question that matters
    /// when a false positive is investigated: *which* rules added up to it.
    /// Attribution consumers should read this rather than re-running the
    /// heuristic engine, so the record always reflects the decision path that
    /// actually ran.
    pub heuristic_indicators: Vec<String>,
    pub ai_score: Option<f32>,
    pub ai_components: Vec<(String, f32, f32)>,
    /// `Some(reason)` when `ai_score` is a degraded heuristic estimate rather
    /// than the output of a successfully executed ONNX model. Without it an
    /// attribution record reports the same "ai = 0.47" whether the model ran
    /// or the layer fell back, which makes false-positive triage unsound.
    pub ai_fallback_reason: Option<String>,
    pub behavior_score: Option<f32>,
    pub sequence_matches: Option<Vec<String>>,
    pub sandbox: Option<SandboxReport>,
    pub process_state: Option<ProcessState>,
    pub rollback_record: Option<RollbackRecord>,
    pub rollback_actions: Option<Vec<String>>,
    /// Static capability-chain prediction; computed during scanning but not
    /// persisted in the scan cache.
    pub static_sandbox: Option<crate::layers::static_sandbox::StaticSandboxPrediction>,
    pub error: Option<String>,
    pub duration_ms: u128,
}

/// Security outcome of one scan item. A non-malicious result is not
/// necessarily clean: unavailable engines, cancellation and size limits must
/// remain visible to callers instead of being mistaken for a clean verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanVerdict {
    Clean,
    Malicious,
    Suspicious,
    Skipped,
    Error,
    Cancelled,
    Incomplete,
}

impl ScanVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Malicious => "malicious",
            Self::Suspicious => "suspicious",
            Self::Skipped => "skipped",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
            Self::Incomplete => "incomplete",
        }
    }
}

impl ScanResult {
    pub fn verdict(&self) -> ScanVerdict {
        if self.malicious {
            return ScanVerdict::Malicious;
        }

        let reason = self.reason.strip_prefix("cached:").unwrap_or(&self.reason);
        if reason == "cancelled" {
            return ScanVerdict::Cancelled;
        }
        if reason == "scan_skipped_size" {
            return ScanVerdict::Skipped;
        }
        if reason.starts_with("fusion:") {
            return ScanVerdict::Suspicious;
        }
        if self.error.is_some() {
            if matches!(
                reason,
                "engine_unavailable" | "sandbox_unavailable" | "sandbox_unverified"
            ) {
                return ScanVerdict::Incomplete;
            }
            return ScanVerdict::Error;
        }
        if reason == "unknown" || reason.is_empty() {
            return ScanVerdict::Incomplete;
        }
        ScanVerdict::Clean
    }
}

fn scan_result_from_cache(cached: CacheScanResult, duration_ms: u128) -> ScanResult {
    ScanResult {
        path: cached.path,
        malicious: cached.malicious,
        reason: cached.summary,
        yara_matches: cached
            .yara_matches
            .into_iter()
            .map(|rule_name| crate::layers::yara::YaraMatch {
                rule_name,
                namespace: "cache".to_string(),
                score: 0,
            })
            .collect(),
        heuristic_score: cached.heuristic_score,
        heuristic_indicators: cached.heuristic_indicators,
        ai_score: cached.ai_score,
        ai_components: cached.ai_components,
        ai_fallback_reason: cached.ai_fallback_reason,
        behavior_score: cached.behavior_score,
        sequence_matches: cached.sequence_matches,
        sandbox: None,
        process_state: None,
        rollback_record: None,
        rollback_actions: None,
        static_sandbox: None,
        error: None,
        duration_ms,
    }
}

fn cache_result_from_scan(result: &ScanResult, context: ScanContext) -> CacheScanResult {
    CacheScanResult {
        path: result.path.clone(),
        malicious: result.malicious,
        summary: result.reason.clone(),
        context,
        heuristic_score: result.heuristic_score,
        heuristic_indicators: result
            .heuristic_indicators
            .iter()
            .take(64)
            .cloned()
            .collect(),
        ai_score: result.ai_score,
        ai_components: result.ai_components.clone(),
        ai_fallback_reason: result.ai_fallback_reason.clone(),
        yara_matches: result
            .yara_matches
            .iter()
            .take(256)
            .map(|item| item.rule_name.clone())
            .collect(),
        behavior_score: result.behavior_score,
        sequence_matches: result
            .sequence_matches
            .clone()
            .map(|matches| matches.into_iter().take(128).collect()),
    }
}

fn cancelled_result(path: PathBuf, duration_ms: u128) -> ScanResult {
    ScanResult {
        path,
        malicious: false,
        reason: "cancelled".to_string(),
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
        error: Some("scan cancelled".to_string()),
        duration_ms,
    }
}

fn cached_summary_is_immutable(summary: &str) -> bool {
    matches!(summary, "browser_cookie_store_metadata_only")
        || summary.starts_with("allowlisted:")
        || [
            "hash:",
            "fuzzy_hash:",
            "yara:",
            "clamav:",
            "script_trojan:",
            "cookie_theft_detected:",
            "vulnerable_driver_blocklist:",
            "kernel_policy_block:",
            "ransomware",
            "behavior_sequence:",
            "sandbox_behavior",
            "threat_intel:",
            "fusion:atc:",
            "fusion:kaspersky_sequence:",
            "fusion:driver:",
            "fusion:anti_sandbox:",
            "fusion:sandbox_flags:",
            "fusion:cookie_theft_suspected:",
        ]
        .iter()
        .any(|prefix| summary.starts_with(prefix))
}

fn cached_summary_is_static_recomputable(summary: &str) -> bool {
    // Only a completed clean/undetected scan can be safely re-decided without
    // re-running the sandbox. Any previous positive or fusion result must go
    // through the full pipeline so a newly changed verdict can still trigger
    // enforcement and rollback.
    summary == "unknown"
}

fn recompute_cached_decision(
    cached: CacheScanResult,
    path: &Path,
    ai: Option<&AiModel>,
    ai_enabled: bool,
    suppress_static_layers: bool,
    ai_threshold: f32,
    fusion: Option<&ProtectionFusion>,
    duration_ms: u128,
) -> Option<ScanResult> {
    let summary = cached.summary.clone();
    if cached_summary_is_immutable(&summary) {
        let mut result = scan_result_from_cache(cached, duration_ms);
        result.reason = format!("cached:{summary}");
        return Some(result);
    }
    if !cached_summary_is_static_recomputable(&summary) {
        // Dynamic evidence that is not represented by the static recompute
        // path must be rescanned instead of being guessed from a stale reason.
        return None;
    }
    if suppress_static_layers {
        return None;
    }

    let mut result = scan_result_from_cache(cached, duration_ms);
    if result.malicious {
        return None;
    }
    result.malicious = false;
    result.reason = "unknown".to_string();

    if ai_enabled && !suppress_static_layers {
        let model = ai?;
        if let Some(score) = model.aggregate_cached_components(&result.ai_components) {
            result.ai_score = Some(score);
        } else {
            let fresh = model.infer_path(path).ok()?;
            result.ai_score = Some(fresh.score);
            result.ai_components = fresh
                .components
                .into_iter()
                .map(|component| (component.id, component.score, component.weight))
                .collect();
        }
    } else {
        result.ai_score = None;
    }

if let Some(fusion) = fusion {
        let input = FusionInput {
            path: path.to_string_lossy().into_owned(),
            sandbox_report: None,
            behavior_score: None,
            sequence_matches: None,
            tolerant_sequence_matches: None,
            sandbox_flags: Vec::new(),
            heuristic_score: result.heuristic_score,
            ai_score: result.ai_score,
            ai_threshold: Some(ai_threshold),
            events: Vec::new(),
            hips_alerts: Vec::new(),
        };
        match fusion.evaluate(&input) {
            FusionDecision::Malicious {
                reason,
                rollback: _,
            } => {
                result.malicious = true;
                result.reason = reason;
            }
            FusionDecision::Suspicious { reason } => result.reason = reason,
            FusionDecision::Clean => {}
        }
    }

    // Same contract as the live path: with fusion attached the override is a
    // fusion rule, so the legacy arm must not run and clobber the branch.
    if !result.malicious && fusion.is_none() {
        if result
            .heuristic_score
            .is_some_and(|score| score >= crate::layers::fusion::HIGH_CONFIDENCE_HEURISTIC_OVERRIDE)
        {
            result.malicious = true;
            result.reason = "heuristic_high".to_string();
        } else if result.ai_score.is_some_and(|score| score >= ai_threshold) {
            result.malicious = true;
            result.reason = "ai_high".to_string();
        }
    }
    if result.malicious || result.reason.starts_with("fusion:") {
        return None;
    }
    result.reason = format!("cached:{}", result.reason);
    Some(result)
}

/// Request to scan a set of file paths.
pub struct ScanRequest {
    pub paths: Vec<PathBuf>,
    pub timeout_ms: u64,
    pub sandbox_enabled: bool,
    pub yara_enabled: bool,
    pub ai_enabled: bool,
    pub heuristic_enabled: bool,
    /// Allow the optional resident clamd second-opinion layer to run. The
    /// engine-level default comes from EVERBLOOM_CLAMAV; callers may override.
    pub clamav_enabled: bool,
    pub ai_threshold: f32,
    pub maximum_file_size: u64,
    /// Cloud inspection is a local no-op placeholder until a deployment
    /// provides an authenticated endpoint. It never replaces local verdicts.
    pub cloud_enabled: bool,
    pub cancelled: Arc<AtomicBool>,
    pub progress_tx: Option<Sender<ScanProgress>>,
}

/// Progress message sent via channel during scanning.
#[derive(Debug, Clone)]
pub enum ScanProgress {
    Enumerating(PathBuf, usize),
    BatchStarted(usize),
    Started(PathBuf),
    LayerCompleted(PathBuf, String),
    FileError(PathBuf, String),
    Completed(PathBuf),
    BatchCompleted {
        total_files: usize,
        processed_files: usize,
        threat_count: usize,
        error_count: usize,
        cancelled: bool,
    },
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("ai error: {0}")]
    Ai(String),
    #[error("sandbox error: {0}")]
    Sandbox(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Configure Rayon once for the whole engine process. The previous default
/// used every logical CPU, which is disproportionate for an antivirus UI
/// process that may also be running HIPS, ETW and model inference workers.
/// Deployments can opt into a different limit with EVERBLOOM_SCAN_THREADS.
pub fn configure_scan_pool() {
    static CONFIGURED: Once = Once::new();
    CONFIGURED.call_once(|| {
        let available = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(2);
        let configured = std::env::var("EVERBLOOM_SCAN_THREADS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(available.min(4));
        let threads = configured.clamp(1, available.max(1));
        if let Err(error) = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
        {
            log::debug!("Rayon scan pool was already configured: {}", error);
        } else {
            log::info!("configured scan worker pool with {} thread(s)", threads);
        }
    });
}

/// Orchestrator that runs the configured pipeline over input paths.
pub struct Scanner {
    pub allowlist: Arc<Allowlist>,
    pub hash: Option<Arc<HashMatcher>>,
    pub yara: Option<Arc<YaraScanner>>,
    pub ai: Option<Arc<AiModel>>,
    pub clamav: Option<Arc<ClamAvClient>>,
    pub behavioral: Option<Arc<BehavioralScorer>>,
    pub sequence: Option<Arc<SequenceMatcher>>,
    pub threat_intel: Option<Arc<ThreatIntelMatcher>>,
    pub fusion: Option<Arc<ProtectionFusion>>,
    pub cache: Option<Arc<ScanCache>>,
    pub sandbox_enabled: bool,
    pub sandbox_timeout_ms: u64,
    pub rollback_executor: Option<Arc<RollbackExecutor>>,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            allowlist: Arc::new(Allowlist::builtin()),
            hash: None,
            yara: None,
            ai: None,
            clamav: None,
            behavioral: None,
            sequence: None,
            threat_intel: None,
            cache: None,
            fusion: None,
            sandbox_enabled: false,
            sandbox_timeout_ms: 5000,
            rollback_executor: None,
        }
    }

    pub fn with_allowlist(mut self, allowlist: Arc<Allowlist>) -> Self {
        self.allowlist = allowlist;
        self
    }

    pub fn with_hash(mut self, h: Arc<HashMatcher>) -> Self {
        self.hash = Some(h);
        self
    }
    pub fn with_yara(mut self, y: Arc<YaraScanner>) -> Self {
        self.yara = Some(y);
        self
    }
    pub fn with_ai(mut self, a: Arc<AiModel>) -> Self {
        self.ai = Some(a);
        self
    }
    pub fn with_clamav(mut self, client: Arc<ClamAvClient>) -> Self {
        self.clamav = Some(client);
        self
    }
    pub fn with_behavioral(mut self, b: Arc<BehavioralScorer>) -> Self {
        self.behavioral = Some(b);
        self
    }
    pub fn with_sequence(mut self, s: Arc<SequenceMatcher>) -> Self {
        self.sequence = Some(s);
        self
    }
    pub fn with_threat_intel(mut self, matcher: Arc<ThreatIntelMatcher>) -> Self {
        self.threat_intel = Some(matcher);
        self
    }
    pub fn with_fusion(mut self, f: Arc<ProtectionFusion>) -> Self {
        self.fusion = Some(f);
        self
    }

    /// Attach the production fusion policy (Normal response level).
    ///
    /// Keep this as a named constructor rather than open-coding a
    /// `ProtectionFusion::new()` at each entrypoint: production builders and
    /// regression tests then share the same default policy, and a scanner
    /// cannot silently omit fusion merely because one transport assembled it
    /// differently.
    pub fn with_default_fusion(mut self) -> Self {
        self.fusion = Some(Arc::new(ProtectionFusion::default()));
        self
    }

    pub fn with_cache(mut self, c: Arc<ScanCache>) -> Self {
        self.cache = Some(c);
        self
    }

    /// Invalidate cached verdicts after a protection-policy change. The
    /// policy epoch check is the primary guard; clearing here also releases
    /// stale entries promptly instead of waiting for LRU eviction.
    pub fn invalidate_cache_context(&self) {
        if let Some(cache) = &self.cache {
            cache.invalidate_context();
        }
    }
    pub fn with_sandbox_enabled(mut self, enabled: bool) -> Self {
        self.sandbox_enabled = enabled;
        self
    }
    pub fn with_sandbox_timeout(mut self, ms: u64) -> Self {
        self.sandbox_timeout_ms = ms;
        self
    }
    pub fn with_rollback_executor(mut self, executor: Arc<RollbackExecutor>) -> Self {
        self.rollback_executor = Some(executor);
        self
    }

    /// Run the pipeline over the provided `ScanRequest` asynchronously.
    ///
    /// For each path: consult cache, then run hash -> yara -> heuristic -> ai -> sandbox
    /// until the file is resolved as malicious/clean or all layers are exhausted.
    pub async fn scan_request(&self, req: ScanRequest) -> Result<Vec<ScanResult>, ScanError> {
        crate::metrics::record_scan_request();
        configure_scan_pool();
        // Process files in parallel using rayon but keep async sandbox calls via tokio
        let progress = req.progress_tx.clone();
        let paths = expand_scan_paths_with_progress(req.paths.clone(), progress.as_ref());
        if let Some(tx) = &progress {
            try_send_progress(tx, ScanProgress::BatchStarted(paths.len()));
        }
        let ai = self.ai.clone();
        let hash = self.hash.clone();
        let yara = self.yara.clone();
        let clamav = self.clamav.clone();
        let allowlist = self.allowlist.clone();
        let cache = self.cache.clone();
        let scan_policy_epoch = protection_state::policy_epoch();
        let sandbox_enabled = req.sandbox_enabled || self.sandbox_enabled;
        let sandbox_timeout = if req.timeout_ms == 0 {
            self.sandbox_timeout_ms
        } else {
            req.timeout_ms
        };
        let rollback_executor = self.rollback_executor.clone();
        let behavioral = self.behavioral.clone();
        let sequence = self.sequence.clone();
        let fusion = self.fusion.clone();
        let driver_bridge = Arc::new(DriverBridge::new());
        let threat_intel = self.threat_intel.clone();
        let yara_enabled = req.yara_enabled;
        let ai_enabled = req.ai_enabled;
        let heuristic_enabled = req.heuristic_enabled;
        let clamav_enabled = req.clamav_enabled && clamav.is_some();
        let ai_threshold = req.ai_threshold.clamp(0.0, 1.0);
        let maximum_file_size = if req.maximum_file_size == 0 {
            DEFAULT_MAXIMUM_FILE_SIZE
        } else {
            req.maximum_file_size
        };
        let cache_context = ScanContext {
            yara_enabled,
            heuristic_enabled,
            ai_enabled,
            sandbox_enabled,
            ai_threshold_bits: ai_threshold.to_bits(),
            sandbox_timeout_ms: sandbox_timeout,
            rules_version: STATIC_RULES_VERSION,
            yara_version: yara.as_ref().map(|scanner| scanner.version()).unwrap_or(0),
            ai_model_version: ai.as_ref().map(|model| model.model_version()).unwrap_or(0),
            sandbox_policy_version: SANDBOX_POLICY_VERSION,
        };
        if req.cloud_enabled {
            debug!(
                "cloud scan placeholder enabled for {} path(s); local engines remain authoritative",
                paths.len()
            );
        }
        let cancelled = req.cancelled.clone();

        // Reuse the caller's Tokio runtime for all sandbox jobs. Building a
        // runtime per scan request adds reactor threads and startup latency.
        let sandbox_runtime = if sandbox_enabled {
            Some(Handle::try_current().map_err(|error| {
                ScanError::Internal(format!("sandbox requires a Tokio runtime: {error}"))
            })?)
        } else {
            None
        };

        // Global ETW/HIPS queues cannot identify a file in a parallel batch.
        // Take a snapshot only for a single-file request, where temporal
        // correlation is meaningful, and never drain the queue once per file.
        // A Windows Sandbox session has no host PID, so its sample must not
        // inherit unrelated host events from this snapshot.
        let single_path_scan = paths.len() == 1;
        let external_behavior_events = Arc::new(if single_path_scan {
            monitoring::drain_behavior_events()
        } else {
            Vec::new()
        });
        let external_hips_events = Arc::new(if single_path_scan {
            hips::drain_hips_events()
        } else {
            Vec::new()
        });

        let scanned: Vec<ScanResult> = tokio::task::spawn_blocking(move || {
            paths
            .into_par_iter()
            .map(|path| {
                let driver_bridge = driver_bridge.clone();
                let start = Instant::now();
                let finish = |path: &PathBuf| {
                    if let Some(tx) = &progress {
                        try_send_progress(tx, ScanProgress::Completed(path.clone()));
                    }
                };
                let fail = |path: &PathBuf, message: String| {
                    if let Some(tx) = &progress {
                        try_send_progress(tx, ScanProgress::FileError(path.clone(), message));
                    }
                };
                let execute_rollback = |res: &mut ScanResult| {
                    if let Some(executor) = &rollback_executor {
                        if let Some(record) = &res.rollback_record {
                            res.rollback_actions = Some(
                                executor
                                    .execute(record)
                                    .into_iter()
                                    .map(|result| match result {
                                        Ok(msg) => msg,
                                        Err(err) => format!("rollback_error:{}", err),
                                    })
                                    .collect(),
                            );
                        }
                    }
                };

                if let Some(tx) = &progress {
                    try_send_progress(tx, ScanProgress::Started(path.clone()));
                }

                if cancelled.load(AtomicOrdering::Relaxed) {
                    finish(&path);
                    return ScanResult {
                        path,
                        malicious: false,
                        reason: "cancelled".to_string(),
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
                        error: Some("scan cancelled".to_string()),
                        duration_ms: start.elapsed().as_millis(),
                    };
                }

                let metadata = match std::fs::metadata(&path) {
                    Ok(metadata) if metadata.len() > maximum_file_size => {
                        let message = format!(
                            "file exceeds the configured {} MiB scan limit",
                            maximum_file_size / 1024 / 1024
                        );
                        fail(&path, message.clone());
                        finish(&path);
                        return ScanResult {
                            path,
                            malicious: false,
                            reason: "scan_skipped_size".to_string(),
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
                            duration_ms: start.elapsed().as_millis(),
                        };
                    }
                    Ok(metadata) => metadata,
                    Err(error) => {
                        if error.kind() == std::io::ErrorKind::NotFound {
                            if let Some(evidence) = monitoring::lookup_ghost_file_evidence(&path) {
                                finish(&path);
                                return ScanResult {
                                    path,
                                    malicious: true,
                                    reason: format!(
                                        "ghost_file_cache:silverfox_driver_directory_selfdelete:sequence={}:pid={}",
                                        evidence.sequence, evidence.caller_pid
                                    ),
                                    yara_matches: Vec::new(),
                                    heuristic_score: Some(0.90),
                                    heuristic_indicators: Vec::new(),
                                    ai_score: None,
                                    ai_components: Vec::new(),
                                    ai_fallback_reason: None,
                                    behavior_score: None,
                                    sequence_matches: Some(vec![
                                        "silverfox_ctf_driver_directory_ghost".to_string(),
                                    ]),
                                    sandbox: None,
                                    process_state: None,
                                    rollback_record: None,
                                    rollback_actions: None,
                                    static_sandbox: None,
                                    error: None,
                                    duration_ms: start.elapsed().as_millis(),
                                };
                            }
                        }
                        let message = format!("unable to read file metadata: {error}");
                        fail(&path, message.clone());
                        finish(&path);
                        return ScanResult {
                            path,
                            malicious: false,
                            reason: "scan_error".to_string(),
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
                            duration_ms: start.elapsed().as_millis(),
                        };
                    }
                };

                let file_size = metadata.len();

                if cancelled.load(AtomicOrdering::Relaxed) {
                    finish(&path);
                    return cancelled_result(path, start.elapsed().as_millis());
                }

                // BYOVD is a high-value early detection point. Keep this
                // basename list exact; do not treat arbitrary .sys files as
                // malicious merely because they are kernel modules.
                if let Some(driver_name) = known_vulnerable_driver_name(&path.to_string_lossy()) {
                    if protection_state::driver_enabled() {
                        match driver_bridge.block_file(&path.to_string_lossy()) {
                            Ok(verdict) => info!(
                                "vulnerable driver policy submitted path={} request={}",
                                path.display(),
                                verdict.request_id
                            ),
                            Err(error) if error.is_unavailable() => {
                                protection_state::set_driver_enabled(false);
                                debug!("driver layer unavailable; continuing without kernel enforcement: {}", error.unavailable_message());
                            }
                            Err(error) => warn!(
                                "vulnerable driver policy unavailable path={}: {}",
                                path.display(),
                                error
                            ),
                        }
                    }
                    finish(&path);
                    return ScanResult {
                        path,
                        malicious: true,
                        reason: format!("vulnerable_driver_blocklist:{driver_name}"),
                        yara_matches: Vec::new(),
                        heuristic_score: Some(0.99),
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
                        duration_ms: start.elapsed().as_millis(),
                    };
                }

                // Metadata is a cheap cache prefilter. Only a path that has a
                // plausible current cache entry pays the full content-hash
                // cost; cache misses continue directly into the scan pipeline.
                let fingerprint = cache.as_ref().and_then(|cache| {
                    let metadata_fingerprint = FileFingerprint::from_metadata(&metadata);
                    cache
                        .has_metadata_candidate(&path, metadata_fingerprint)
                        .then(|| FileFingerprint::from_path(&path).ok())
                        .flatten()
                });

                // Allowlisted paths/hashes suppress only noisy static/AI
                // verdicts. Exact hash hits, YARA and dynamic behavior still
                // run first and remain authoritative.
                let allowlist_match = allowlist.matches(&path);
                let suppress_static_layers = allowlist_match.is_some();
                let cookie_guard_candidate = is_cookie_guard_candidate_file(&path);

                // The kernel policy is an enforcement authority. Query it
                // before consulting the user-mode cache so a file blocked by
                // a newly-installed driver rule cannot return a cached Clean
                // result from the Rust pipeline.
                if protection_state::driver_enabled() {
                    match driver_bridge.scan_file(&path.to_string_lossy()) {
                        Ok(verdict) if verdict.blocked => {
                            let duration = start.elapsed().as_millis();
                            if let Some(tx) = &progress {
                                try_send_progress(tx, ScanProgress::Completed(path.clone()));
                            }
                            return ScanResult {
                                path: path.clone(),
                                malicious: true,
                                reason: format!(
                                    "kernel_policy_block:request={}",
                                    verdict.request_id
                                ),
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
                                duration_ms: duration,
                            };
                        }
                        Ok(_) => {
                        }
                        Err(error) if error.is_unavailable() => {
                                protection_state::set_driver_enabled(false);
                                debug!("driver layer unavailable; continuing without kernel enforcement: {}", error.unavailable_message());
                            }
                        Err(error) => debug!(
                            "kernel policy preflight unavailable for {}: {}",
                            path.display(),
                            error
                        ),
                    }
                }

                if cancelled.load(AtomicOrdering::Relaxed) {
                    finish(&path);
                    return cancelled_result(path, start.elapsed().as_millis());
                }

                // check cache
                if let Some(c) = &cache {
                    if let Some(fingerprint) = fingerprint {
                        if !cookie_guard_candidate {
                            if let Some(cached) = c.get_fresh_for_policy_with_context(
                                &path,
                                fingerprint,
                                protection_state::policy_epoch(),
                                cache_context,
                            ) {
                                let duration = start.elapsed().as_millis();
                                if let Some(tx) = &progress {
                                    try_send_progress(
                                        tx,
                                        ScanProgress::Completed(path.clone()),
                                    );
                                }
                                let mut result = scan_result_from_cache(cached, duration);
                                result.reason = format!("cached:{}", result.reason);
                                return result;
                            }

                            if let Some(cached) = c.get_evidence_for_policy_with_context(
                                &path,
                                fingerprint,
                                protection_state::policy_epoch(),
                                cache_context,
                            ) {
                                if let Some(mut result) = recompute_cached_decision(
                                    cached,
                                    &path,
                                    ai.as_deref(),
                                    ai_enabled,
                                    suppress_static_layers,
                                    ai_threshold,
                                    fusion.as_deref(),
                                    start.elapsed().as_millis(),
                                ) {
                                    if let Some(cache) = &cache {
                                        let mut cacheable = result.clone();
                                        cacheable.reason = cacheable
                                            .reason
                                            .strip_prefix("cached:")
                                            .unwrap_or(&cacheable.reason)
                                            .to_string();
                                        cache.put_fresh_for_policy(
                                            cache_result_from_scan(&cacheable, cache_context),
                                            fingerprint,
                                            protection_state::policy_epoch(),
                                        );
                                    }
                                    if let Some(tx) = &progress {
                                        try_send_progress(
                                            tx,
                                            ScanProgress::Completed(path.clone()),
                                        );
                                    }
                                    result.duration_ms = start.elapsed().as_millis();
                                    return result;
                                }
                            }
                        }
                    }
                }

                // default result
                let mut res = ScanResult {
                    path: path.clone(),
                    malicious: false,
                    reason: "unknown".to_string(),
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
                    duration_ms: 0,
                };

                let cache_result = |result: &mut ScanResult| {
                    // A policy can change while a long static/sandbox scan is
                    // running. Re-check immediately before publishing or
                    // caching the result so the kernel remains authoritative
                    // for the final decision, not only for the cache lookup.
                    if protection_state::driver_enabled() {
                        match driver_bridge.scan_file(&result.path.to_string_lossy()) {
                            Ok(verdict) if verdict.blocked => {
                                result.malicious = true;
                                result.reason = format!(
                                    "kernel_policy_block:request={}",
                                    verdict.request_id
                                );
                                result.error = None;
                            }
                            Ok(_) => {
                            }
                            Err(error) if error.is_unavailable() => {
                                protection_state::set_driver_enabled(false);
                                debug!("driver layer unavailable; continuing without kernel enforcement: {}", error.unavailable_message());
                            }
                            Err(error) => debug!(
                                "kernel policy final check unavailable for {}: {}",
                                result.path.display(),
                                error
                            ),
                        }
                    }
                    // A malicious file verdict is also materialized in the
                    // kernel file policy. The update is best-effort because
                    // the driver is optional; the Rust verdict remains
                    // authoritative when the driver is absent.
                    if result.malicious && protection_state::driver_enabled() {
                        match driver_bridge.block_file(&result.path.to_string_lossy()) {
                            Ok(verdict) => {
                                info!(
                                    "driver file policy acknowledged path={} request={}",
                                    result.path.display(),
                                    verdict.request_id
                                );
                            }
                            Err(error) if error.is_unavailable() => {
                                protection_state::set_driver_enabled(false);
                                debug!("driver layer unavailable; continuing without kernel enforcement: {}", error.unavailable_message());
                            }
                            Err(error) => warn!(
                                "driver file policy unavailable path={}: {}",
                                result.path.display(),
                                error
                            ),
                        }
                    }
                    if result.error.is_none() {
                        if let Some(cache) = &cache {
                            match FileFingerprint::from_path(&path) {
                                Ok(current)
                                    if fingerprint
                                        .map(|original| current == original)
                                        .unwrap_or(true) =>
                                {
                                    cache.put_fresh_for_policy(
                                        cache_result_from_scan(result, cache_context),
                                        current,
                                        scan_policy_epoch,
                                    );
                                }
                                Ok(_) => warn!(
                                    "file changed during scan; result was not cached: {}",
                                    path.display()
                                ),
                                Err(error) => warn!(
                                    "unable to revalidate file after scan; result was not cached {}: {}",
                                    path.display(),
                                    error
                                ),
                            }
                        }
                    }
                };

                // stage: hash
                let hash_stage_enabled = hash
                    .as_ref()
                    .is_some_and(|matcher| matcher.entry_count() > 0);
                if hash_stage_enabled {
                    let h = hash.as_ref().expect("hash matcher checked above");
                    match h.match_file(&path) {
                        Ok(Some(hm)) => {
                            res.malicious = true;
                            let source_count = hm.sources.len().max(1);
                            res.reason = if hm.algorithm != "exact" {
                                format!(
                                    "fuzzy_hash:{}:similarity={}:sources={}",
                                    hm.label, hm.similarity, source_count
                                )
                            } else {
                                format!("hash:{}:sources={}", hm.label, source_count)
                            };
                            if hm.algorithm == "exact" {
                                res.duration_ms = start.elapsed().as_millis();
                                if let Some(tx) = &progress {
                                    try_send_progress(tx, ScanProgress::LayerCompleted(
                                        path.clone(),
                                        "hash".to_string(),
                                    ));
                                }
                                cache_result(&mut res);
                                finish(&path);
                                return res;
                            }
                        }
                        Ok(None) => {
                            // not found by hash, continue
                        }
                        Err(e) => {
                            warn!("hash error {}: {}", path.display(), e);
                        }
                    }
                }

                if hash_stage_enabled {
                    if let Some(tx) = &progress {
                        try_send_progress(tx, ScanProgress::LayerCompleted(
                            path.clone(),
                            "hash".to_string(),
                        ));
                    }
                }

                if cancelled.load(AtomicOrdering::Relaxed) {
                    finish(&path);
                    return cancelled_result(path, start.elapsed().as_millis());
                }

                // stage: clamav. A resident clamd provides an independent
                // second opinion with its own signature database. Unavailable
                // clamd is never a detection and never blocks the pipeline;
                // the client's retry cooldown keeps batch scans fast when
                // the daemon is down.
                let clamav_stage_enabled =
                    clamav_enabled && !res.malicious && !suppress_static_layers;
                if clamav_stage_enabled {
                    let client = clamav.as_ref().expect("clamav client checked above");
                    match client.scan_path(&path) {
                        ClamAvVerdict::Found { signature } => {
                            res.malicious = true;
                            res.reason = format!("clamav:{signature}");
                            res.duration_ms = start.elapsed().as_millis();
                            if let Some(tx) = &progress {
                                try_send_progress(tx, ScanProgress::LayerCompleted(
                                    path.clone(),
                                    "clamav".to_string(),
                                ));
                            }
                            cache_result(&mut res);
                            finish(&path);
                            return res;
                        }
                        ClamAvVerdict::Clean => {}
                        ClamAvVerdict::Unavailable { message } => {
                            debug!("clamav layer unavailable for {}: {}", path.display(), message);
                        }
                    }
                    if let Some(tx) = &progress {
                        try_send_progress(tx, ScanProgress::LayerCompleted(
                            path.clone(),
                            "clamav".to_string(),
                        ));
                    }
                }

                if cancelled.load(AtomicOrdering::Relaxed) {
                    finish(&path);
                    return cancelled_result(path, start.elapsed().as_millis());
                }

                // stage: yara
                if cancelled.load(AtomicOrdering::Relaxed) {
                    res.reason = "cancelled".to_string();
                    res.error = Some("scan cancelled".to_string());
                    res.duration_ms = start.elapsed().as_millis();
                    finish(&path);
                    return res;
                }

                // YARA and heuristic analysis both consume the same immutable
                // file snapshot. Reusing it removes a second full-file read
                // for the common scan configuration without retaining bytes
                // after the static stages finish.
                let static_bytes = if yara_enabled
                    || (heuristic_enabled && !suppress_static_layers)
                    || cookie_guard_candidate
                {
                    match read_static_analysis_bytes(&path, file_size, cancelled.as_ref()) {
                        Ok(bytes) => Some(bytes),
                        Err(error)
                            if error.kind() == std::io::ErrorKind::Interrupted
                                && cancelled.load(AtomicOrdering::Relaxed) =>
                        {
                            finish(&path);
                            return cancelled_result(path, start.elapsed().as_millis());
                        }
                        Err(error) => {
                            let message = format!("unable to read file for static analysis: {error}");
                            fail(&path, message.clone());
                            res.reason = "scan_error".to_string();
                            res.error = Some(message);
                            res.duration_ms = start.elapsed().as_millis();
                            finish(&path);
                            return res;
                        }
                    }
                } else {
                    None
                };

                if yara_enabled {
                    let Some(y) = &yara else {
                        let message = "YARA was requested but no rules are loaded".to_string();
                        fail(&path, message.clone());
                        res.reason = "engine_unavailable".to_string();
                        res.error = Some(message);
                        res.duration_ms = start.elapsed().as_millis();
                        finish(&path);
                        return res;
                    };
                    match static_bytes.as_deref().map(|bytes| y.scan_bytes(bytes)) {
                        Some(Ok(matches)) => {
                            if !matches.is_empty() {
                                res.malicious = true;
                                res.reason = format!(
                                    "yara:{}",
                                    matches
                                        .iter()
                                        .map(|m| m.rule_name.clone())
                                        .collect::<Vec<_>>()
                                        .join(",")
                                );
                                res.yara_matches = matches;
                                res.duration_ms = start.elapsed().as_millis();
                                if let Some(tx) = &progress {
                                    try_send_progress(tx, ScanProgress::LayerCompleted(
                                        path.clone(),
                                        "yara".to_string(),
                                    ));
                                }
                                cache_result(&mut res);
                                finish(&path);
                                return res;
                            }
                        }
                        Some(Err(e)) => {
                            let message = format!("YARA scan failed: {e}");
                            warn!("yara scan error {}: {}", path.display(), e);
                            fail(&path, message.clone());
                            res.reason = "scan_error".to_string();
                            res.error = Some(message);
                            res.duration_ms = start.elapsed().as_millis();
                            finish(&path);
                            return res;
                        }
                        None => {
                            let message = "static scan bytes were unavailable".to_string();
                            fail(&path, message.clone());
                            res.reason = "scan_error".to_string();
                            res.error = Some(message);
                            res.duration_ms = start.elapsed().as_millis();
                            finish(&path);
                            return res;
                        }
                    }
                }

                if yara_enabled {
                    if let Some(tx) = &progress {
                        try_send_progress(tx, ScanProgress::LayerCompleted(
                            path.clone(),
                            "yara".to_string(),
                        ));
                    }
                }

                // Cookie protection is content-aware only for executable or
                // script candidates. A browser database itself is classified
                // by path metadata and is never inspected for rows, values or
                // encrypted blobs.
                if let Some(bytes) = static_bytes.as_deref() {
                    let cookie_score = analyze_cookie_bytes(&path, bytes);
                    if cookie_score.browser_cookie_store {
                        res.reason = "browser_cookie_store_metadata_only".to_string();
                    } else if cookie_score.high_confidence() {
                        res.malicious = true;
                        res.heuristic_score = Some(
                            res.heuristic_score
                                .unwrap_or(0.0)
                                .max(cookie_score.score),
                        );
                        res.reason = format!(
                            "cookie_theft_detected:{}",
                            cookie_score.indicators.join(",")
                        );
                        res.duration_ms = start.elapsed().as_millis();
                        cache_result(&mut res);
                        finish(&path);
                        return res;
                    }
                    if cookie_score.medium_confidence() {
                        res.heuristic_score = Some(
                            res.heuristic_score
                                .unwrap_or(0.0)
                                .max(cookie_score.score),
                        );
                        res.reason = format!(
                            "fusion:cookie_theft_suspected:{}",
                            cookie_score.indicators.join(",")
                        );
                    }
                } else if is_browser_cookie_store(&path) {
                    res.reason = "browser_cookie_store_metadata_only".to_string();
                }

                if cancelled.load(AtomicOrdering::Relaxed) {
                    finish(&path);
                    return cancelled_result(path, start.elapsed().as_millis());
                }

                // stage: heuristic
                if heuristic_enabled && !suppress_static_layers {
                    if let Some(bytes) = static_bytes.as_deref() {
                        if is_binary_heuristic_candidate(&path, bytes) {
                            match analyze_bytes_with_context(bytes, &path) {
                                Ok(hs) => {
                                    res.heuristic_score = Some(hs.score);
                                    res.heuristic_indicators = hs.indicators.clone();
                                }
                                Err(e) => {
                                    debug!(
                                        "binary heuristic skipped {}: {}",
                                        path.display(),
                                        e
                                    );
                                }
                            }
                        }

                        if is_script_like(&path) {
                            let script_score = analyze_script_bytes(bytes);
                            if script_score.score
                                > res.heuristic_score.unwrap_or(0.0)
                            {
                                res.heuristic_score = Some(script_score.score);
                                res.heuristic_indicators = script_score.indicators.clone();
                            }
                            if script_score.score >= 0.8 {
                                res.malicious = true;
                                res.reason = format!(
                                    "script_trojan:{}",
                                    script_score.indicators.join(",")
                                );
                                res.duration_ms = start.elapsed().as_millis();
                                cache_result(&mut res);
                                finish(&path);
                                return res;
                            }
                        }
                    } else {
                        let message = "static scan bytes were unavailable".to_string();
                        fail(&path, message.clone());
                        res.reason = "scan_error".to_string();
                        res.error = Some(message);
                        res.duration_ms = start.elapsed().as_millis();
                        finish(&path);
                        return res;
                    }
                }

                if heuristic_enabled && !suppress_static_layers {
                    if let Some(tx) = &progress {
                        try_send_progress(tx, ScanProgress::LayerCompleted(
                            path.clone(),
                            "heuristic".to_string(),
                        ));
                    }
                }

                // stage: ai
                if ai_enabled && !suppress_static_layers {
                    let Some(a) = &ai else {
                        let message =
                            "AI was requested but no validated model is loaded".to_string();
                        fail(&path, message.clone());
                        res.reason = "engine_unavailable".to_string();
                        res.error = Some(message);
                        res.duration_ms = start.elapsed().as_millis();
                        finish(&path);
                        return res;
                    };
                    match a.infer_path_with_cancel(&path, cancelled.as_ref()) {
                        Ok(score) => {
                            res.ai_score = Some(score.score);
                            res.ai_components = score
                                .components
                                .into_iter()
                                .map(|component| {
                                    (component.id, component.score, component.weight)
                                })
                                .collect();
                            // Record degraded estimates explicitly. The AI
                            // layer never fails a scan on its own; when the
                            // model cannot run it returns a flagged heuristic
                            // estimate, and that distinction has to survive
                            // into the attribution record.
                            res.ai_fallback_reason = score.fallback_reason.or_else(|| {
                                score
                                    .is_fallback
                                    .then(|| "AI layer reported a fallback score".to_string())
                            });
                        }
                        Err(e) => {
                            let message = format!("AI inference failed: {e}");
                            warn!("ai inference failed {}: {}", path.display(), e);
                            fail(&path, message.clone());
                            res.reason = "scan_error".to_string();
                            res.error = Some(message);
                            res.duration_ms = start.elapsed().as_millis();
                            finish(&path);
                            return res;
                        }
                    }
                }

                if ai_enabled && !suppress_static_layers {
                    if let Some(tx) = &progress {
                        try_send_progress(
                            tx,
                            ScanProgress::LayerCompleted(path.clone(), "ai".to_string()),
                        );
                    }
                }

                if cancelled.load(AtomicOrdering::Relaxed) {
                    finish(&path);
                    return cancelled_result(path, start.elapsed().as_millis());
                }

                // Static capability-chain analysis over the shared byte
                // snapshot. It never executes the sample and never alone
                // produces a malicious verdict; it only escalates an
                // otherwise-unconfirmed finding to a conservative Suspicious
                // reason when dynamic sandboxing is unavailable.
                if !suppress_static_layers {
                    if let Some(bytes) = static_bytes.as_deref() {
                        let prediction =
                            crate::layers::static_sandbox::analyze_static_sandbox(bytes);
                        let corroborated = res
                            .heuristic_score
                            .map(|score| score >= 0.5)
                            .unwrap_or(false)
                            || res.ai_score.map(|score| score >= 0.5).unwrap_or(false);
                        if !res.malicious
                            && !sandbox_enabled
                            && corroborated
                            && (prediction.is_high_confidence_chain()
                                || prediction.is_ransomware_chain())
                        {
                            // Report which shape matched so the two escalation
                            // paths stay distinguishable in telemetry.
                            let shape = if prediction.is_ransomware_chain() {
                                "ransomware"
                            } else {
                                "intrusion"
                            };
                            res.reason = format!(
                                "fusion:sbox_static:{}:{}",
                                shape,
                                prediction.capabilities.join(",")
                            );
                        }
                        res.static_sandbox = Some(prediction);
                    }
                }

                // Static evidence must be fused after both producers have
                // completed. Previously this block ran before heuristic/AI,
                // so it always saw two `None` values and silently skipped the
                // intended cross-engine agreement check.
                if !res.malicious {
                    if let Some(fusion) = &fusion {
let static_input = FusionInput {
                            path: path.to_string_lossy().into_owned(),
                            sandbox_report: None,
                            behavior_score: None,
                            sequence_matches: None,
                            tolerant_sequence_matches: None,
                            sandbox_flags: Vec::new(),
                            heuristic_score: res.heuristic_score,
                            ai_score: res.ai_score,
                            ai_threshold: Some(ai_threshold),
                            events: Vec::new(),
                            hips_alerts: Vec::new(),
                        };
                        match fusion.evaluate(&static_input) {
                            FusionDecision::Malicious { reason, rollback } => {
                                res.malicious = true;
                                res.reason = reason;
                                if rollback {
                                    execute_rollback(&mut res);
                                }
                            }
                            FusionDecision::Suspicious { reason } => {
                                res.reason = reason;
                            }
                            FusionDecision::Clean => {}
                        }
                    }
                }

                if !res.malicious {
                    if let Some(match_kind) = &allowlist_match {
                        res.reason = format!("allowlisted:{}", match_kind.reason());
                    }
                }

                // Legacy direct decision - only for a scanner with NO fusion
                // attached (`--no-fusion` ablation, unit tests, and any caller
                // that never wires a policy). It is deliberately unreachable
                // when a `ProtectionFusion` is present: the equivalent rule
                // runs inside `ProtectionFusion::evaluate` as
                // `fusion:high_confidence_override`, which keeps the fusion
                // branch visible instead of overwriting it.
                //
                // This is the compatibility arm of the contract, not a second
                // decision centre. See wiki 12.6.2.
                if !res.malicious && fusion.is_none() {
                    let heuristic_high = res
                        .heuristic_score
                        .map(|score| score >= crate::layers::fusion::HIGH_CONFIDENCE_HEURISTIC_OVERRIDE)
                        .unwrap_or(false);
                    let ai_high = res
                        .ai_score
                        .map(|score| score >= ai_threshold)
                        .unwrap_or(false);
                    if heuristic_high {
                        res.malicious = true;
                        res.reason = "heuristic_high".to_string();
                    } else if ai_high {
                        res.malicious = true;
                        res.reason = "ai_high".to_string();
                    }
                }

                // Stage: sandbox. Isolation failures are reported as scan errors,
                // never as malware detections, so unsupported file types do not
                // become false positives.
                let sandbox_stage_enabled = sandbox_enabled && !res.malicious;
                let sandbox_res = if sandbox_stage_enabled {
                    if cancelled.load(AtomicOrdering::Relaxed) {
                        finish(&path);
                        return cancelled_result(path, start.elapsed().as_millis());
                    }
                    let p_clone = path.clone();
                    let sandbox_cancelled = cancelled.clone();
                    match sandbox_runtime.as_ref() {
                        Some(runtime) => Some(runtime.block_on(async move {
                            run_sandbox_with_cancel(
                                p_clone,
                                std::time::Duration::from_millis(sandbox_timeout),
                                sandbox_cancelled,
                            )
                            .await
                        })),
                        None => Some(Err(crate::sandbox::SandboxError::Spawn(
                            "sandbox runtime is unavailable".to_string(),
                        ))),
                    }
                } else {
                    None
                };

                if let Some(Err(crate::sandbox::SandboxError::Cancelled)) = sandbox_res.as_ref() {
                    finish(&path);
                    return cancelled_result(path, start.elapsed().as_millis());
                }

                if let Some(Err(error)) = sandbox_res.as_ref() {
                    let message = format!("secure sandbox analysis was not completed: {error}");
                    warn!("secure sandbox failed {}: {}", path.display(), error);
                    res.reason = "sandbox_unavailable".to_string();
                    res.error = Some(message.clone());
                    res.duration_ms = start.elapsed().as_millis();
                    fail(&path, message);
                    finish(&path);
                    return res;
                }

                if let Some(Ok(rep)) = sandbox_res {
                    if cancelled.load(AtomicOrdering::Relaxed) {
                        finish(&path);
                        return cancelled_result(path, start.elapsed().as_millis());
                    }
                    if !rep.isolation_verified || !rep.cleanup_verified {
                        let message = format!(
                            "sandbox trust checks failed: backend={} isolation_verified={} cleanup_verified={}",
                            rep.isolation_backend, rep.isolation_verified, rep.cleanup_verified
                        );
                        res.reason = "sandbox_unverified".to_string();
                        res.error = Some(message.clone());
                        res.duration_ms = start.elapsed().as_millis();
                        fail(&path, message);
                        finish(&path);
                        return res;
                    }
                    // Always attach sandbox telemetry so clean samples also carry behavior logs.
                    res.sandbox = Some(rep.clone());

                    let mut state_machine = ProcessStateMachine::new();
                    for event in derive_behavior_events(&rep).iter() {
                        if let Some(pid) = event.process_id {
                            state_machine.update_state(pid, event.kind.clone(), &event.detail);
                        }
                    }

                    if let Some(pid) = rep.target_pid {
                        if let Some(state) = state_machine.get_state(pid) {
                            res.process_state = Some(state.clone());
                        }
                    }

                    let mut sandbox_flags = Vec::new();
                    if rep.timed_out {
                        sandbox_flags.push("timed_out".to_string());
                    }
                    let anti_sandbox_indicators: Vec<&str> = rep
                        .api_calls
                        .iter()
                        .filter_map(|call| call.strip_prefix("anti_sandbox:"))
                        .collect();
                    if !anti_sandbox_indicators.is_empty() {
                        sandbox_flags.push("anti_sandbox_evasion".to_string());
                        res.reason = format!(
                            "fusion:anti_sandbox:{}",
                            anti_sandbox_indicators.join(",")
                        );
                    } else if rep.timed_out {
                        // A timeout is not evidence of Clean: evasive samples
                        // commonly sleep until the analysis window expires.
                        res.reason = "fusion:anti_sandbox:execution_timeout".to_string();
                    }
                    if !rep.files_changed.is_empty() {
                        sandbox_flags.push("files_changed".to_string());
                    }
                    if !rep.network_connections.is_empty() {
                        sandbox_flags.push("network_activity".to_string());
                    }
                    let mut threat_intel_alerts = Vec::new();
                    if let Some(matcher) = &threat_intel {
                        let observations = rep
                            .network_connections
                            .iter()
                            .chain(rep.api_calls.iter())
                            .map(String::as_str);
                        for hit in matcher.match_observations(observations) {
                            let description = hit.description();
                            if !threat_intel_alerts.contains(&description) {
                                threat_intel_alerts.push(description);
                            }
                        }
                    }
                    if !threat_intel_alerts.is_empty() {
                        sandbox_flags.push("threat_intel_match".to_string());
                    }
                    if !rep.registry_writes.is_empty() {
                        sandbox_flags.push("registry_activity".to_string());
                    }
                    let observed_api_calls = rep
                        .api_calls
                        .iter()
                        .filter(|call| !is_sandbox_control_event(call))
                        .count();
                    if observed_api_calls > 0 {
                        sandbox_flags.push("api_activity".to_string());
                    }

                    res.rollback_record = Some(RollbackPlanner::from_sandbox_report(&rep));
                    if let Some((changed_count, extension_families)) =
                        ransomware_file_burst(&rep.files_changed)
                    {
                        res.malicious = true;
                        res.reason = format!(
                            "ransomware_file_burst:files={changed_count}:families={extension_families}"
                        );
                        execute_rollback(&mut res);
                    } else if let Some((changed_count, extension_families)) =
                        ransomware_slow_file_burst(&rep.files_changed)
                    {
                        res.malicious = true;
                        res.reason = format!(
                            "ransomware_slow_file_burst:files={changed_count}:families={extension_families}"
                        );
                        execute_rollback(&mut res);
                    }
                    let mut behavior_events = derive_behavior_events(&rep);
                    behavior_events.extend(
                        external_behavior_events
                            .iter()
                            .filter(|event| {
                                rep.target_pid
                                    .is_some_and(|pid| event.process_id == Some(pid))
                            })
                            .cloned(),
                    );

                    // AMSI integration: scan the sample file via Windows
                    // Antimalware Scan Interface for behavior/content
                    // analysis. The verdict contributes to the final result
                    // when the AMSI layer returns Detected. AMSI errors are
                    // non-fatal (logged at debug level) because AMSI may be
                    // unavailable on certain hosts (e.g., Windows Server Core
                    // without registered providers).
                    let (amsi_verdict, amsi_name) = if let Some(path) = req.paths.first() {
                        let (v, n) = crate::amsi::scan_file_with_amsi(path);
                        let name = n.unwrap_or_else(|| "amsi_detected".to_string());
                        (v, name)
                    } else {
                        (crate::amsi::AmsiVerdict::Clean, String::new())
                    };
                    if matches!(amsi_verdict, crate::amsi::AmsiVerdict::Detected { .. }) {
                        res.malicious = true;
                        if res.reason.is_empty() {
                            res.reason = format!("amsi:{}", amsi_name);
                        }
                    }
                    log::debug!(
                        "amsi verdict: {:?} ({})",
                        amsi_verdict,
                        amsi_name
                    );

                    // Correlate events emitted while this sandbox session was
                    // running as well as the pre-scan snapshot. This closes
                    // the timing gap where the driver/HIPS response arrived
                    // after the snapshot but before fusion evaluated the
                    // sandbox report. Correlation is PID-bound; an unrelated
                    // host event must not be attributed to this sample.
                    let mut correlated_hips_events: Vec<HipsEvent> = external_hips_events
                        .iter()
                        .filter(|event| {
                            rep.target_pid
                                .is_some_and(|pid| event.process_id() == pid)
                        })
                        .cloned()
.collect();
                    if single_path_scan {
                        for event in hips::drain_hips_events() {
                            let matches_target = rep
                                .target_pid
                                .is_some_and(|pid| event.process_id() == pid);
                            if matches_target
                                && !correlated_hips_events.iter().any(|existing| {
                                    existing.description() == event.description()
                                })
                            {
                                correlated_hips_events.push(event);
                            }
                        }
                    }

                    // Inject R3 HIPS alerts into the behavioral event stream so
                    // the ATC scorer and sequence matcher see user-mode
                    // injection/module/tampering observations too. Previously
                    // HIPS alerts only reached fusion as opaque strings and
                    // could never complete a multi-step chain.
                    behavior_events.extend(
                        correlated_hips_events
                            .iter()
                            .filter_map(|event| event.behavior_event()),
);

                    let mut fusion_input = FusionInput {
                        path: path.to_string_lossy().into_owned(),
                        sandbox_report: Some(rep.clone()),
                        behavior_score: None,
                        sequence_matches: None,
                        tolerant_sequence_matches: None,
                        sandbox_flags: sandbox_flags.clone(),
                        heuristic_score: res.heuristic_score,
                        ai_score: res.ai_score,
                        ai_threshold: Some(ai_threshold),
                        events: behavior_events.clone(),
                        hips_alerts: Vec::new(),
                    };

                    fusion_input.hips_alerts = correlated_hips_events
                        .iter()
                        .map(|event| event.description())
                        .collect();
                    fusion_input
                        .hips_alerts
                        .extend(threat_intel_alerts.iter().map(|alert| {
                            format!("threat_intel:{alert}")
                        }));

                    if let Some(b) = &behavioral {
                        let observed_scores = b.score_events_by_process(&behavior_events);
                        if let Some(best) = observed_scores
                            .iter()
                            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(Ordering::Equal))
                        {
                            res.behavior_score = Some(best.score);
                            fusion_input.behavior_score = Some(BehaviorScoreResult {
                                process_id: best.process_id,
                                score: best.score,
                                matched_indicators: best.matched_indicators.clone(),
                            });
                            if fusion.is_none() && b.is_malicious(best.score) {
                                res.malicious = true;
                                let pid_label = best
                                    .process_id
                                    .map(|pid| pid.to_string())
                                    .unwrap_or_else(|| "aggregate".to_string());
                                res.reason =
                                    format!("behavior_score:{}:{:.2}", pid_label, best.score);
                                execute_rollback(&mut res);
                                res.duration_ms = start.elapsed().as_millis();
                                if let Some(tx) = &progress {
                                    try_send_progress(tx, ScanProgress::LayerCompleted(
                                        path.clone(),
                                        "behavior".to_string(),
                                    ));
                                }
                                cache_result(&mut res);
                                finish(&path);
                                return res;
                            }
                        }
                    }

if let Some(s) = &sequence {
                        let kinds: Vec<BehaviorEventKind> =
                            behavior_events.iter().map(|e| e.kind.clone()).collect();
                        let seq_matches = s.match_sequence(&kinds);
                        if !seq_matches.is_empty() {
                            let names: Vec<String> = seq_matches
                                .iter()
                                .map(|m| m.signature_name.clone())
                                .collect();
                            res.sequence_matches = Some(names.clone());
                            fusion_input.sequence_matches = Some(names.clone());
                            if fusion.is_none() {
                                res.malicious = true;
                                res.reason = format!("behavior_sequence:{}", names.join(","));
                                execute_rollback(&mut res);
                                res.duration_ms = start.elapsed().as_millis();
                                if let Some(tx) = &progress {
                                    try_send_progress(tx, ScanProgress::LayerCompleted(
                                        path.clone(),
                                        "sequence".to_string(),
                                    ));
                                }
                                cache_result(&mut res);
                                finish(&path);
                                return res;
                            }
                        }
                        // Tolerant chains are weaker correlation: record them
                        // for fusion but never short-circuit to malicious here.
                        let tolerant_matches = s.match_sequence_tolerant(&kinds, 4, 24);
                        if !tolerant_matches.is_empty() {
                            let names: Vec<String> = tolerant_matches
                                .iter()
                                .map(|m| m.signature_name.clone())
                                .collect();
                            fusion_input.tolerant_sequence_matches = Some(names);
                        }
                    }

                    if (rep.timed_out
                        || !rep.files_changed.is_empty()
                        || !rep.network_connections.is_empty())
                        && fusion.is_none()
                    {
                        res.malicious = true;
                        res.reason = "sandbox_behavior".to_string();
                        execute_rollback(&mut res);
                        res.duration_ms = start.elapsed().as_millis();
                        if let Some(tx) = &progress {
                            try_send_progress(tx, ScanProgress::LayerCompleted(
                                path.clone(),
                                "sandbox".to_string(),
                            ));
                        }
                        cache_result(&mut res);
                        finish(&path);
                        return res;
                    }

                    if let Some(fusion) = &fusion {
                        match fusion.evaluate(&fusion_input) {
                            FusionDecision::Malicious { reason, rollback } => {
                                res.malicious = true;
                                res.reason = reason;
                                if rollback {
                                    execute_rollback(&mut res);
                                }
                                res.duration_ms = start.elapsed().as_millis();
                                if let Some(tx) = &progress {
                                    try_send_progress(tx, ScanProgress::LayerCompleted(
                                        path.clone(),
                                        "fusion".to_string(),
                                    ));
                                }
                                cache_result(&mut res);
                                finish(&path);
                                return res;
                            }
                            FusionDecision::Clean => {
                                // let the scan complete normally
                            }
                            FusionDecision::Suspicious { reason } => {
                                res.reason = reason;
                            }
                        }
                    }

                    if !threat_intel_alerts.is_empty() && fusion.is_none() {
                        res.malicious = true;
                        res.reason = format!(
                            "threat_intel:{}",
                            threat_intel_alerts.join("|")
                        );
                        res.duration_ms = start.elapsed().as_millis();
                        cache_result(&mut res);
                        finish(&path);
                        return res;
                    }
                }

                if sandbox_stage_enabled {
                    if let Some(tx) = &progress {
                        try_send_progress(tx, ScanProgress::LayerCompleted(
                            path.clone(),
                            "sandbox".to_string(),
                        ));
                    }
                }

                // no layer flagged it
                res.duration_ms = start.elapsed().as_millis();
                cache_result(&mut res);
                if let Some(tx) = &progress {
                    try_send_progress(tx, ScanProgress::Completed(path.clone()));
                }
                res
            })
            .collect::<Vec<_>>()
        })
        .await
        .map_err(|error| {
            let message = format!("scan worker task failed: {error}");
            if error.is_panic() {
                log::error!("{}", message);
            } else {
                log::warn!("{}", message);
            }
            ScanError::Internal(message)
        })?;

        for result in &scanned {
            let bytes = std::fs::metadata(&result.path)
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            crate::metrics::record_scan_result(
                result.duration_ms,
                bytes,
                result.error.is_some(),
                result.malicious,
            );
            if let Some(report) = &result.sandbox {
                crate::metrics::record_sandbox(report);
            }
        }
        Ok(scanned)
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Progress is telemetry, not a work queue. Drop high-frequency layer updates
/// when the consumer is behind, while keeping the sender non-blocking so a
/// slow GUI or IPC client cannot stall the scan workers.
fn try_send_progress(tx: &Sender<ScanProgress>, progress: ScanProgress) {
    match tx.try_send(progress) {
        Ok(()) => {}
        Err(TrySendError::Full(progress)) => {
            if !matches!(progress, ScanProgress::LayerCompleted(_, _)) {
                log::debug!("scan progress channel is full; dropping non-layer update");
            }
        }
        Err(TrySendError::Closed(_)) => {}
    }
}

fn read_static_analysis_bytes(
    path: &Path,
    file_size: u64,
    cancelled: &AtomicBool,
) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    if file_size <= MAX_STATIC_ANALYSIS_BYTES as u64 {
        let mut bytes = Vec::with_capacity(file_size as usize);
        let mut buffer = [0u8; 1024 * 1024];
        loop {
            if cancelled.load(AtomicOrdering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "static analysis cancelled",
                ));
            }
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        return Ok(bytes);
    }

    let window_size = MAX_STATIC_ANALYSIS_BYTES / STATIC_ANALYSIS_WINDOWS;
    let last_offset = file_size.saturating_sub(window_size as u64);
    let mut sample =
        Vec::with_capacity(MAX_STATIC_ANALYSIS_BYTES + 32 * (STATIC_ANALYSIS_WINDOWS - 1));
    for index in 0..STATIC_ANALYSIS_WINDOWS {
        if cancelled.load(AtomicOrdering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "static analysis cancelled",
            ));
        }
        let offset = if STATIC_ANALYSIS_WINDOWS == 1 {
            0
        } else {
            last_offset.saturating_mul(index as u64) / (STATIC_ANALYSIS_WINDOWS - 1) as u64
        };
        file.seek(SeekFrom::Start(offset))?;
        let mut window = vec![0u8; window_size];
        let read = file.read(&mut window)?;
        window.truncate(read);
        sample.extend_from_slice(&window);
        if index + 1 < STATIC_ANALYSIS_WINDOWS {
            // Keep independent windows from forming artificial strings across
            // a boundary during textual heuristic and YARA matching.
            sample.extend_from_slice(&[0u8; 32]);
        }
    }
    Ok(sample)
}

#[cfg(test)]
fn expand_scan_paths(input_paths: Vec<PathBuf>) -> Vec<PathBuf> {
    expand_scan_paths_with_progress(input_paths, None)
}

fn configured_max_scan_files() -> usize {
    std::env::var("EVERBLOOM_MAX_SCAN_FILES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_SCAN_FILES)
        .clamp(1, MAX_ALLOWED_SCAN_FILES)
}

fn expand_scan_paths_with_progress(
    input_paths: Vec<PathBuf>,
    progress: Option<&Sender<ScanProgress>>,
) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let max_files = configured_max_scan_files();
    for path in input_paths {
        if files.len() >= max_files {
            warn!(
                "scan target expansion reached EVERBLOOM_MAX_SCAN_FILES={}; remaining targets were not queued",
                max_files
            );
            break;
        }
        if path.is_file() {
            files.push(path);
            continue;
        }
        if !path.is_dir() {
            warn!(
                "scan target does not exist or is inaccessible: {}",
                path.display()
            );
            continue;
        }

        for entry in WalkDir::new(&path).follow_links(false).into_iter() {
            if files.len() >= max_files {
                warn!(
                    "scan target expansion reached EVERBLOOM_MAX_SCAN_FILES={}; remaining files were not queued",
                    max_files
                );
                break;
            }
            match entry {
                Ok(entry) if entry.file_type().is_file() => {
                    let root = path.clone();
                    files.push(entry.into_path());
                    if let Some(tx) = progress {
                        if files.len() == 1 || files.len() % 256 == 0 {
                            try_send_progress(tx, ScanProgress::Enumerating(root, files.len()));
                        }
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    warn!(
                        "unable to enumerate scan target {}: {}",
                        path.display(),
                        error
                    );
                }
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

fn is_script_like(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "ps1"
                    | "psm1"
                    | "psd1"
                    | "bat"
                    | "cmd"
                    | "vbs"
                    | "vbe"
                    | "js"
                    | "jse"
                    | "wsf"
                    | "hta"
            )
        })
        .unwrap_or(false)
}

fn is_binary_heuristic_candidate(path: &Path, bytes: &[u8]) -> bool {
    if bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
    {
        return true;
    }

    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "exe"
                    | "dll"
                    | "sys"
                    | "scr"
                    | "cpl"
                    | "ocx"
                    | "com"
                    | "drv"
                    | "efi"
                    | "mui"
                    | "msi"
                    | "msp"
                    | "dat"
            )
        })
        .unwrap_or(false)
}

fn derive_behavior_events(report: &SandboxReport) -> Vec<BehaviorEvent> {
    let mut events = Vec::new();

    // A valid PE found in executable private memory is an unpacking signal,
    // not an automatic malware verdict. Keep it as an independent behavioral
    // event so fusion can correlate it with static, network, persistence, or
    // injection evidence.
    if report.unpacking.candidate_images > 0 {
        events.push(BehaviorEvent {
            kind: BehaviorEventKind::SuspiciousApiCall,
            detail: format!(
                "unpacking:memory_pe_candidate:status={}:confidence={:.2}",
                report.unpacking.status, report.unpacking.confidence
            ),
            process_id: report.target_pid,
        });
    }
    if report.unpacking.recovered_entry_points > 0 {
        events.push(BehaviorEvent {
            kind: BehaviorEventKind::SuspiciousApiCall,
            detail: format!(
                "unpacking:entry_point_recovered_candidate:count={}",
                report.unpacking.recovered_entry_points
            ),
            process_id: report.target_pid,
        });
    }

    for path in &report.files_changed {
        let detail = path.to_string_lossy().into_owned();
        events.push(BehaviorEvent {
            kind: BehaviorEventKind::FileWrite,
            detail: detail.clone(),
            process_id: report.target_pid,
        });

let lower = detail.to_lowercase();
        if is_persistence_path(&lower) {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::SuspiciousPersistence,
                detail: format!("startup file: {}", detail),
                process_id: report.target_pid,
            });
        }
    }

for reg in &report.registry_writes {
        let lower = reg.to_lowercase();
        events.push(BehaviorEvent {
            kind: BehaviorEventKind::RegistryWrite,
            detail: reg.clone(),
            process_id: report.target_pid,
        });

        if is_persistence_registry_key(&lower) {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::SuspiciousPersistence,
                detail: format!("persistence registry: {}", reg),
                process_id: report.target_pid,
            });
        }
        if lower.contains("system\\currentcontrolset\\services")
            || lower.contains("\\services\\")
            || lower.contains("\\services") && lower.contains("controlset")
        {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::ServiceTampering,
                detail: format!("service registry: {}", reg),
                process_id: report.target_pid,
            });
        }
    }

    for proc in &report.processes {
        events.push(BehaviorEvent {
            kind: BehaviorEventKind::ProcessCreate,
            detail: proc.clone(),
            process_id: report.target_pid,
        });
    }

    for net in &report.network_connections {
        // Kernel network events also fire for refused or loopback traffic,
        // which is ordinary (e.g. an HTTP probe to 127.0.0.1). Require an
        // unambiguous remote peer before we feed the fusion layer a network
        // event; this keeps a handful of AppContainer probes from tipping a
        // benign sample to "network" evidence.
        if is_loopback_or_ephemeral(net) {
            continue;
        }
        events.push(BehaviorEvent {
            kind: BehaviorEventKind::NetworkConnect,
            detail: net.clone(),
            process_id: report.target_pid,
        });
    }

for api in &report.api_calls {
        if is_sandbox_control_event(api) {
            continue;
        }
        let lower = api.to_lowercase();
        // Rich ETW telemetry forwarded by the sandbox monitor's kernel-event
        // parser. These entries already carry the concrete file path, registry
        // key, process image, or network target, and the acting pid appears at
        // the record tail, so each event is attributed to the process that
        // performed it rather than flattened onto the sample's main pid.
        if let Some(entry) = api.strip_prefix("etw:file:") {
            let (target, pid) = split_etw_target_and_pid(entry);
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::FileWrite,
                detail: target.to_string(),
                process_id: pid.or(report.target_pid),
            });
            continue;
        }
        if let Some(entry) = api.strip_prefix("etw:reg:") {
            let (target, pid) = split_etw_target_and_pid(entry);
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::RegistryWrite,
                detail: target.to_string(),
                process_id: pid.or(report.target_pid),
            });
            continue;
        }
        if let Some(entry) = api.strip_prefix("etw:process:") {
            let (target, pid) = split_etw_target_and_pid(entry);
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::ProcessCreate,
                detail: target.to_string(),
                process_id: pid.or(report.target_pid),
            });
            continue;
        }
        if let Some(entry) = api.strip_prefix("etw:net:") {
            let (target, pid) = split_etw_target_and_pid(entry);
            if !is_loopback_or_ephemeral(target) {
                events.push(BehaviorEvent {
                    kind: BehaviorEventKind::NetworkConnect,
                    detail: target.to_string(),
                    process_id: pid.or(report.target_pid),
                });
            }
            continue;
        }
        if lower.contains("writeprocessmemory")
            || lower.contains("virtualallo")
            || lower.contains("createremotethread")
            || lower.contains("openprocess")
        {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::SuspiciousApiCall,
                detail: api.clone(),
                process_id: report.target_pid,
            });
            // Enhanced anti-injection signal: if the same process also shows
            // remote-thread indicators, emit a dedicated injection event for
            // the fusion layer so it can correlate with persistence/network.
            if lower.contains("createremotethread") || lower.contains("remote") {
                events.push(BehaviorEvent {
                    kind: BehaviorEventKind::ProcessInject,
                    detail: format!("remote_thread_indicators:pid={:?}:api={}", report.target_pid, api),
                    process_id: report.target_pid,
                });
            }
        } else if lower.contains("dns")
            || lower.contains("getaddrinfo")
            || lower.contains("resolve")
        {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::DnsQuery,
                detail: api.clone(),
                process_id: report.target_pid,
            });
        } else if lower.contains("lsass")
            || lower.contains("sam")
            || lower.contains("dpapi")
            || lower.contains("mimikatz")
            || lower.contains("credential")
        {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::CredentialAccess,
                detail: api.clone(),
                process_id: report.target_pid,
            });
        } else if lower.contains("schtasks /create")
            || (lower.contains("reg add") && lower.contains("run"))
            || lower.contains("sc create")
            || lower.contains("create service")
            || lower.contains("service create")
        {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::SuspiciousPersistence,
                detail: api.clone(),
                process_id: report.target_pid,
            });
        } else if is_backup_destruction_indicator(&lower) {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::BackupDeletion,
                detail: api.clone(),
                process_id: report.target_pid,
            });
        } else if is_ransomware_indicator(&lower) {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::RansomwareEncryption,
                detail: api.clone(),
                process_id: report.target_pid,
            });
        } else if lower.contains("net stop")
            || lower.contains("sc stop")
            || lower.contains("disable service")
        {
            events.push(BehaviorEvent {
                kind: BehaviorEventKind::ServiceTampering,
                detail: api.clone(),
                process_id: report.target_pid,
            });
        }
    }
    events
}

/// Splits a rich ETW entry's trailing `(pid=... tid=... ...)` diagnostic tail
/// from the captured target, returning the target and the acting pid.
fn split_etw_target_and_pid(entry: &str) -> (&str, Option<u32>) {
    if let Some(pos) = entry.find(" (pid=") {
        let (target, tail) = entry.split_at(pos);
        let pid = tail
            .split("pid=")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse::<u32>().ok());
        (target, pid)
    } else {
        (entry, None)
    }
}

/// Remote-peer gate for kernel network telemetry. Loopback and link-local
/// exchanges are common in benign software (local services, health checks)
/// and must not alone drive a network verdict, especially while the sandbox
/// runs with no network capability.
fn is_loopback_or_ephemeral(connection: &str) -> bool {
    let mut parts = connection.rsplitn(2, ':');
    let Some(_port) = parts.next() else {
        return false;
    };
    let Some(host) = parts.next() else {
        return false;
    };
    host == "127.0.0.1"
        || host == "::1"
        || host == "0.0.0.0"
        || host == "::"
        || host.starts_with("169.254.")
        || host.starts_with("fe80:")
        || host.starts_with("[::1]")
}

/// Conservative ransomware marker. Requires an explicit crypto API name or a
/// self-describing "ransom(ware)" cue instead of any line containing the
/// "crypt" substring (which also matches benign crypt32.dll usage).
fn is_ransomware_indicator(lower: &str) -> bool {
    if lower.contains("ransom") {
        return true;
    }
    lower.contains("cryptencrypt")
        || lower.contains("bcryptencrypt")
        || lower.contains("ncryptencrypt")
        || lower.contains("encryptfile")
        || (lower.contains("encrypt") && lower.contains("rc4"))
        || (lower.contains("encrypt") && lower.contains("xor"))
}

/// Segment-aware startup-folder check for sandbox filesystem changes. An
/// exact "startup" path segment (or the canonical Shell:Startup location) is
/// persistence; a mere "startup" substring inside a filename is noise.
fn is_persistence_path(lower: &str) -> bool {
    if lower.contains("start menu\\programs\\startup")
        || lower.contains("shell:startup")
        || lower.contains("appdata\\roaming\\microsoft\\windows\\start menu")
    {
        return true;
    }
    lower
        .split(['\\', '/'])
        .any(|segment| segment.trim() == "startup" || segment.trim() == "startup.bat")
}

/// Segment-aware Run/RunOnce registry check. Uses exact "\run", "\runonce"
/// path segments instead of the "run" substring so keys like Software\Runners
/// or "StartupRunLog" stay benign.
fn is_persistence_registry_key(lower: &str) -> bool {
    if lower.contains("currentversion\\run")
        || lower.contains("currentversion\\runonce")
        || lower.contains("startupapproved\\run")
    {
        return true;
    }
    lower.split('\\').any(|segment| {
        let segment = segment.trim();
        matches!(segment, "run" | "runonce")
    })
}

fn is_backup_destruction_indicator(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("delete shadows") || lower.contains("shadowcopy delete") {
        return true;
    }
    if lower.contains("vssadmin")
        && lower.contains("delete")
        && (lower.contains("shadow") || lower.contains("shadowcopy"))
    {
        return true;
    }
    if lower.contains("wbadmin")
        && lower.contains("delete")
        && (lower.contains("catalog")
            || lower.contains("systemstatebackup")
            || lower.contains("backup"))
    {
        return true;
    }
    if lower.contains("diskshadow") && (lower.contains("delete") || lower.contains("reset")) {
        return true;
    }
    if lower.contains("wmic") && lower.contains("shadowcopy") && lower.contains("delete") {
        return true;
    }
    lower.contains("bcdedit")
        && lower.contains("recoveryenabled")
        && (lower.contains(" no") || lower.ends_with("no") || lower.contains(" 0"))
}

fn ransomware_file_burst(paths: &[PathBuf]) -> Option<(usize, usize)> {
    const HIGH_VOLUME: usize = 128;
    const MIXED_DOCUMENT_VOLUME: usize = 32;
    let mut families = std::collections::HashSet::new();
    for path in paths {
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        let extension = extension.to_ascii_lowercase();
        if matches!(
            extension.as_str(),
            "doc"
                | "docx"
                | "xls"
                | "xlsx"
                | "ppt"
                | "pptx"
                | "pdf"
                | "jpg"
                | "jpeg"
                | "png"
                | "zip"
                | "7z"
                | "txt"
                | "db"
                | "sqlite"
                | "wallet"
        ) {
            families.insert(extension);
        }
    }
    let changed_count = paths.len();
    ((changed_count >= HIGH_VOLUME)
        || (changed_count >= MIXED_DOCUMENT_VOLUME && families.len() >= 3))
        .then_some((changed_count, families.len()))
}

fn ransomware_slow_file_burst(paths: &[PathBuf]) -> Option<(usize, usize)> {
    const SLOW_DOCUMENT_VOLUME: usize = 24;
    let mut families = std::collections::HashSet::new();
    for path in paths {
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        let extension = extension.to_ascii_lowercase();
        if matches!(
            extension.as_str(),
            "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "pdf" | "jpg" | "jpeg" | "png"
        ) {
            families.insert(extension);
        }
    }
    let changed_count = paths.len();
    (changed_count >= SLOW_DOCUMENT_VOLUME && families.len() >= 4)
        .then_some((changed_count, families.len()))
}

fn is_sandbox_control_event(value: &str) -> bool {
    value.starts_with("isolation:")
        || value.starts_with("network:")
        || value.starts_with("clipboard:")
        || value.starts_with("vgpu:")
        || value.starts_with("host_mapping:")
        || value.starts_with("fallback:")
}

#[cfg(test)]
mod path_expansion_tests {
    use super::{
        expand_scan_paths, is_backup_destruction_indicator, is_loopback_or_ephemeral,
        is_persistence_path, is_persistence_registry_key, is_ransomware_indicator,
        ransomware_file_burst, ransomware_slow_file_burst, split_etw_target_and_pid,
        ScanProgress, ScanRequest, ScanVerdict, Scanner,
    };
    use crate::layers::clamav::ClamAvClient;
    use crate::layers::fusion::{FusionDecision, FusionInput};
    use crate::layers::yara::YaraScanner;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{atomic::AtomicBool, Arc};
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn default_production_fusion_is_attached_and_uses_normal_policy() {
        let scanner = Scanner::new().with_default_fusion();
        let fusion = scanner.fusion.as_ref().expect("production fusion attached");
        let input = FusionInput {
            path: "sample.bin".to_string(),
            sandbox_report: None,
            behavior_score: None,
            sequence_matches: None,
            tolerant_sequence_matches: None,
            sandbox_flags: Vec::new(),
            heuristic_score: Some(0.70),
            ai_score: Some(0.72),
            ai_threshold: Some(0.9),
            events: Vec::new(),
            hips_alerts: Vec::new(),
        };
        assert!(matches!(
            fusion.evaluate(&input),
            FusionDecision::Suspicious { ref reason }
                if reason.starts_with("fusion:static:stage=correlate:")
        ));
    }

    fn request(path: PathBuf) -> ScanRequest {
        ScanRequest {
            paths: vec![path],
            timeout_ms: 0,
            sandbox_enabled: false,
            yara_enabled: false,
            ai_enabled: false,
            heuristic_enabled: false,
            clamav_enabled: false,
            ai_threshold: 0.9,
            maximum_file_size: 128 * 1024 * 1024,
            cloud_enabled: false,
            cancelled: Arc::new(AtomicBool::new(false)),
            progress_tx: None,
        }
    }

#[test]
    fn etw_entry_pid_split_recovers_target_and_pid() {
        let entry = "C:\\Windows\\System32\\evil.exe (pid=1234 tid=7 provider=x id=12)";
        let (target, pid) = split_etw_target_and_pid(entry);
        assert_eq!(target, "C:\\Windows\\System32\\evil.exe");
        assert_eq!(pid, Some(1234));
    }

    #[test]
    fn etw_entry_without_pid_tail_returns_none() {
        let (target, pid) = split_etw_target_and_pid("HKLM\\Software\\Run");
        assert_eq!(target, "HKLM\\Software\\Run");
        assert_eq!(pid, None);
    }

    #[test]
    fn expands_directories_recursively_and_removes_duplicates() {
        let directory = tempdir().expect("temporary directory");
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).expect("nested directory");
        let first = directory.path().join("first.bin");
        let second = nested.join("second.bin");
        fs::write(&first, b"one").expect("first fixture");
        fs::write(&second, b"two").expect("second fixture");

        let expanded = expand_scan_paths(vec![directory.path().to_path_buf(), first.clone()]);

        assert_eq!(expanded, vec![first, second]);
    }

    #[tokio::test]
    async fn requested_unavailable_engine_is_an_explicit_error() {
        let directory = tempdir().expect("temporary directory");
        let sample = directory.path().join("sample.bin");
        fs::write(&sample, b"ordinary data").expect("sample fixture");
        let mut scan_request = request(sample);
        scan_request.yara_enabled = true;

        let results = Scanner::new()
            .scan_request(scan_request)
            .await
            .expect("scan result");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].reason, "engine_unavailable");
        assert!(results[0].error.is_some());
        assert!(!results[0].malicious);
        assert_eq!(results[0].verdict(), ScanVerdict::Incomplete);
    }

    #[tokio::test]
    async fn oversized_file_is_reported_instead_of_treated_as_clean() {
        let directory = tempdir().expect("temporary directory");
        let sample = directory.path().join("sample.bin");
        fs::write(&sample, b"larger than configured limit").expect("sample fixture");
        let mut scan_request = request(sample);
        scan_request.maximum_file_size = 4;

        let results = Scanner::new()
            .scan_request(scan_request)
            .await
            .expect("scan result");

        assert_eq!(results[0].reason, "scan_skipped_size");
        assert_eq!(results[0].verdict(), ScanVerdict::Skipped);
        assert!(results[0].error.is_some());
        assert!(!results[0].malicious);
    }

    #[tokio::test]
    async fn disabled_layers_do_not_emit_layer_completion_progress() {
        let directory = tempdir().expect("temporary directory");
        let sample = directory.path().join("sample.bin");
        fs::write(&sample, b"ordinary data").expect("sample fixture");
        let mut scan_request = request(sample);
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        scan_request.progress_tx = Some(tx);

        let results = Scanner::new()
            .scan_request(scan_request)
            .await
            .expect("scan result");

        assert_eq!(results.len(), 1);
        assert!(!results[0].malicious);

        let mut layers = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let ScanProgress::LayerCompleted(_, layer) = event {
                layers.push(layer);
            }
        }
        assert!(
            layers.is_empty(),
            "unexpected disabled layer progress: {layers:?}"
        );
    }

    #[tokio::test]
    async fn cookie_theft_static_chain_is_detected_without_reading_store_values() {
        let directory = tempdir().expect("temporary directory");
        let sample = directory.path().join("loader.ps1");
        fs::write(
            &sample,
            b"Network\\Cookies sqlite3 CryptUnProtectData Invoke-WebRequest base64",
        )
        .expect("cookie stealer fixture");

        let results = Scanner::new()
            .scan_request(request(sample))
            .await
            .expect("scan result");

        assert!(results[0].malicious);
        assert!(results[0].reason.starts_with("cookie_theft_detected:"));
        assert!(!results[0].reason.contains("base64"));
    }

    #[tokio::test]
    async fn browser_cookie_database_is_metadata_only() {
        let directory = tempdir().expect("temporary directory");
        let store = directory
            .path()
            .join("User Data")
            .join("Default")
            .join("Network");
        fs::create_dir_all(&store).expect("cookie store directory");
        let cookie_db = store.join("Cookies");
        fs::write(&cookie_db, b"encrypted_value=private_cookie").expect("cookie fixture");

        let results = Scanner::new()
            .scan_request(request(cookie_db))
            .await
            .expect("scan result");

        assert!(!results[0].malicious);
        assert_eq!(results[0].reason, "browser_cookie_store_metadata_only");
        assert!(!results[0].reason.contains("private_cookie"));
    }

    #[test]
    fn mixed_document_burst_is_ransomware_signal() {
        let paths = (0..32)
            .map(|index| match index % 3 {
                0 => PathBuf::from(format!("file-{index}.docx")),
                1 => PathBuf::from(format!("file-{index}.pdf")),
                _ => PathBuf::from(format!("file-{index}.jpg")),
            })
            .collect::<Vec<_>>();
        assert_eq!(ransomware_file_burst(&paths), Some((32, 3)));
    }

    #[test]
    fn slow_document_burst_requires_multiple_families() {
        let paths = (0..24)
            .map(|index| match index % 4 {
                0 => PathBuf::from(format!("file-{index}.docx")),
                1 => PathBuf::from(format!("file-{index}.xlsx")),
                2 => PathBuf::from(format!("file-{index}.pdf")),
                _ => PathBuf::from(format!("file-{index}.jpg")),
            })
            .collect::<Vec<_>>();
        assert_eq!(ransomware_slow_file_burst(&paths), Some((24, 4)));

        let single_family = (0..24)
            .map(|index| PathBuf::from(format!("file-{index}.docx")))
            .collect::<Vec<_>>();
        assert_eq!(ransomware_slow_file_burst(&single_family), None);
    }

#[test]
    fn backup_destruction_matching_requires_a_destructive_combination() {
        assert!(is_backup_destruction_indicator(
            "cmd.exe /c vssadmin.exe /quiet delete shadows /all"
        ));
        assert!(is_backup_destruction_indicator(
            "wmic shadowcopy delete nointeractive"
        ));
        assert!(is_backup_destruction_indicator(
            "bcdedit.exe /set {default} recoveryenabled no"
        ));
        assert!(!is_backup_destruction_indicator("vssadmin list shadows"));
        assert!(!is_backup_destruction_indicator("wbadmin get versions"));
    }

    #[test]
    fn persistence_matching_is_segment_aware() {
        assert!(is_persistence_registry_key(
            r"\registry\machine\software\microsoft\windows\currentversion\run"
        ));
        assert!(is_persistence_registry_key(
            r"\registry\user\s-1-5-21\software\microsoft\windows\currentversion\runonce"
        ));
        assert!(!is_persistence_registry_key(
            r"\registry\machine\software\acme\runners\state"
        ));
        assert!(!is_persistence_registry_key(
            r"\registry\machine\software\startuprunlog"
        ));
        assert!(is_persistence_path(
            r"c:\users\u\appdata\roaming\microsoft\windows\start menu\programs\startup\x.exe"
        ));
        assert!(is_persistence_path(r"session\startup\agent.bat"));
        assert!(!is_persistence_path(r"session\documents\startuphandbook.docx"));
        assert!(!is_persistence_path(r"session\run\note.txt"));
    }

    #[test]
    fn ransomware_indicator_requires_concrete_api_or_cue() {
        assert!(is_ransomware_indicator("call cryptencrypt aes-256"));
        assert!(is_ransomware_indicator("bcryptencrypt stream"));
        assert!(is_ransomware_indicator("ransomware payload staged"));
        assert!(!is_ransomware_indicator("load crypt32.dll"));
        assert!(!is_ransomware_indicator("cryptographic hashing of config"));
        assert!(!is_ransomware_indicator("window title: crypto wallet"));
    }

    #[test]
    fn loopback_network_peers_are_filtered() {
        assert!(is_loopback_or_ephemeral("127.0.0.1:445"));
        assert!(is_loopback_or_ephemeral("0.0.0.0:5353"));
        assert!(is_loopback_or_ephemeral("fe80::1:53"));
        assert!(!is_loopback_or_ephemeral("45.33.32.156:443"));
        assert!(!is_loopback_or_ephemeral("217.160.0.1:80"));
    }

    #[tokio::test]
    async fn configured_yara_rule_reaches_the_scanner_pipeline() {
        let directory = tempdir().expect("temporary directory");
        let rules_directory = directory.path().join("rules");
        fs::create_dir(&rules_directory).expect("rules directory");
        fs::write(
            rules_directory.join("test.yar"),
            r#"rule integration_marker {
                strings:
                    $marker = "EVERBLOOM_PIPELINE_TEST_MARKER"
                condition:
                    $marker
            }"#,
        )
        .expect("rule fixture");
        let sample = directory.path().join("sample.bin");
        fs::write(&sample, b"EVERBLOOM_PIPELINE_TEST_MARKER").expect("sample fixture");
        let mut scan_request = request(sample);
        scan_request.yara_enabled = true;
        let scanner =
            Scanner::new().with_yara(Arc::new(YaraScanner::new(&rules_directory).unwrap()));

        let results = scanner
            .scan_request(scan_request)
            .await
            .expect("scan result");

        assert!(results[0].malicious);
        assert!(results[0].reason.contains("integration_marker"));
    }

    #[tokio::test]
    async fn unavailable_clamav_never_blocks_or_flags_the_pipeline() {
        let directory = tempdir().expect("temporary directory");
        let sample = directory.path().join("sample.bin");
        fs::write(&sample, b"ordinary data").expect("sample fixture");
        let mut scan_request = request(sample);
        scan_request.clamav_enabled = true;
        // Port 1 on loopback refuses connections; the layer must degrade
        // quietly instead of producing an error or a detection.
        let client = Arc::new(ClamAvClient::new(
            "127.0.0.1:1".to_string(),
            Duration::from_millis(200),
            Duration::from_millis(500),
            1024 * 1024,
            1,
            Duration::from_secs(300),
        ));
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        scan_request.progress_tx = Some(tx);

        let results = Scanner::new()
            .with_clamav(client)
            .scan_request(scan_request)
            .await
            .expect("scan result");

        assert_eq!(results.len(), 1);
        assert!(!results[0].malicious);
        // An "unknown" reason stays explicitly incomplete rather than being
        // reported as clean while a configured layer could not run.
        assert_eq!(results[0].verdict(), ScanVerdict::Incomplete);
        assert_eq!(results[0].reason, "unknown");
        assert!(results.iter().all(|result| result.error.is_none()));

        let mut layers = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let ScanProgress::LayerCompleted(_, layer) = event {
                layers.push(layer);
            }
        }
        assert!(
            layers.contains(&"clamav".to_string()),
            "clamav layer completion progress missing: {layers:?}"
        );
    }
}
