use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Condvar, Mutex, OnceLock, RwLock,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use lazy_static::lazy_static;
use log::{error, info, warn};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::layers::heuristic::analyze_bytes;
use goblin::Object;

/// Model family used by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiModelKind {
    CNN,
    Transformer,
}

impl AiModelKind {
    pub fn from_env() -> Self {
        std::env::var("HELIOSAV_AI_MODEL_KIND")
            .ok()
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
            .map(|kind| match kind {
                "transformer" | "tf" => Self::Transformer,
                _ => Self::CNN,
            })
            .unwrap_or(Self::CNN)
    }

    pub fn default_model_path(&self) -> PathBuf {
        match self {
            Self::Transformer => PathBuf::from("pyas_transformer.onnx"),
            Self::CNN => PathBuf::from("heliosav_feature_cnn.onnx"),
        }
    }
}

/// AI inference model holder and runtime.
///
/// The model is stored as an optional runnable plan behind an `ArcSwapOption`
/// to allow lock-free hot-reload at runtime. Metadata remains separately
/// guarded because it is small and is only changed after a model compiles.
pub struct AiModel {
    model_path: Arc<RwLock<PathBuf>>,
    kind: AiModelKind,
    fallback: Option<Box<AiModel>>,
    ensemble: Arc<RwLock<bool>>,
    runnable: ArcSwapOption<TypedRunnableModel>,
    blend_primary: Arc<RwLock<f32>>,
    /// Optional feature name ordering loaded from `features.json` next to the model file.
    feature_map: Arc<RwLock<Option<Vec<String>>>>,
    /// Optional output interpretation/selection loaded from `model_contract.json`.
    model_contract: Arc<RwLock<ModelContract>>,
    /// User-managed models. Each member owns an independently loaded ONNX plan
    /// and its own feature-map/contract sidecars.
    additional_models: Arc<RwLock<Vec<EnsembleMember>>>,
    aggregation: Arc<RwLock<EnsembleStrategy>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum OutputKind {
    #[default]
    Auto,
    Probability,
    Logit,
}

#[derive(Debug, Clone, Default)]
struct ModelContract {
    output_index: Option<usize>,
    malicious_index: Option<usize>,
    output_kind: OutputKind,
}

#[derive(Debug, Error)]
pub enum AiError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("model load error: {0}")]
    Model(String),
    #[error("inference error: {0}")]
    Infer(String),
}

/// Result returned by AI inference.
#[derive(Debug, Clone)]
pub struct AiScore {
    pub score: f32, // 0.0 ..= 1.0
    /// Raw model scores used to build the aggregate. Keeping these values
    /// allows blend/ensemble changes to re-aggregate without another ONNX run.
    pub components: Vec<AiComponentScore>,
    /// True when the numerical score came from the heuristic fallback rather
    /// than a successfully executed ONNX model.
    pub is_fallback: bool,
    /// Structured enough for callers to expose the degraded state without
    /// parsing logs. The message never contains sample contents.
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AiComponentScore {
    pub id: String,
    pub score: f32,
    pub weight: f32,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct FeatureCacheKey {
    sample_sha256: [u8; 32],
    file_size: u64,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct NamedFeatureCacheKey {
    base: FeatureCacheKey,
    feature_map_sha256: [u8; 32],
}

struct FeatureCache {
    base: DashMap<FeatureCacheKey, [f32; 12]>,
    named: DashMap<NamedFeatureCacheKey, Arc<Vec<f32>>>,
}

impl FeatureCache {
    fn new() -> Self {
        Self {
            base: DashMap::new(),
            named: DashMap::new(),
        }
    }

    fn trim_if_needed(&self) {
        // The cache is intentionally bounded. Clearing a generation is cheap
        // compared with allowing an attacker to retain unbounded vectors by
        // submitting many distinct samples or feature maps.
        const MAX_ENTRIES: usize = 1024;
        if self.base.len() > MAX_ENTRIES {
            self.base.clear();
        }
        if self.named.len() > MAX_ENTRIES {
            self.named.clear();
        }
    }
}

lazy_static! {
    static ref FEATURE_CACHE: FeatureCache = FeatureCache::new();
    static ref AI_INFERENCE_ERRORS: AtomicU64 = AtomicU64::new(0);
    static ref AI_QUEUE_WAIT_US: AtomicU64 = AtomicU64::new(0);
    static ref AI_INFERENCE_TIME_US: AtomicU64 = AtomicU64::new(0);
    static ref AI_INFERENCE_REQUESTS: AtomicU64 = AtomicU64::new(0);
    static ref AI_QUEUE_REJECTIONS: AtomicU64 = AtomicU64::new(0);
    static ref MODEL_LOAD_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
    static ref AI_POOL: Option<rayon::ThreadPool> = {
        let available = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(2);
        let configured = std::env::var("HELIOSAV_AI_THREADS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(available.min(2))
            .clamp(1, available.max(1).min(4));
        match rayon::ThreadPoolBuilder::new()
            .num_threads(configured)
            .thread_name(|index| format!("ai-infer-{index}"))
            .build()
        {
            Ok(pool) => Some(pool),
            Err(error) => {
                error!("unable to create dedicated AI inference pool: {}", error);
                None
            }
        }
    };
}

/// Number of model execution failures since engine start. This is intentionally
/// a monotonic counter instead of a log-only signal so the GUI/service can
/// expose degraded AI health without scraping text logs.
pub fn ai_inference_error_count() -> u64 {
    AI_INFERENCE_ERRORS.load(Ordering::Relaxed)
}

/// Runtime counters for the bounded inference gate. Values are monotonic and
/// intentionally cheap to read from the NDJSON/diagnostic layer.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct AiRuntimeMetrics {
    pub inference_errors: u64,
    pub queue_wait_us: u64,
    pub inference_time_us: u64,
    pub inference_requests: u64,
    pub queue_rejections: u64,
}

pub fn ai_runtime_metrics() -> AiRuntimeMetrics {
    AiRuntimeMetrics {
        inference_errors: AI_INFERENCE_ERRORS.load(Ordering::Relaxed),
        queue_wait_us: AI_QUEUE_WAIT_US.load(Ordering::Relaxed),
        inference_time_us: AI_INFERENCE_TIME_US.load(Ordering::Relaxed),
        inference_requests: AI_INFERENCE_REQUESTS.load(Ordering::Relaxed),
        queue_rejections: AI_QUEUE_REJECTIONS.load(Ordering::Relaxed),
    }
}

struct AiPermitState {
    available: usize,
    capacity: usize,
}

static AI_PERMITS: OnceLock<(Mutex<AiPermitState>, Condvar)> = OnceLock::new();

fn ai_permits() -> &'static (Mutex<AiPermitState>, Condvar) {
    AI_PERMITS.get_or_init(|| {
        let available_parallelism = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(2);
        let capacity = std::env::var("HELIOSAV_AI_MAX_IN_FLIGHT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(available_parallelism.min(2))
            .clamp(1, available_parallelism.max(1).min(4));
        (
            Mutex::new(AiPermitState {
                available: capacity,
                capacity,
            }),
            Condvar::new(),
        )
    })
}

struct AiPermit;

impl Drop for AiPermit {
    fn drop(&mut self) {
        let (lock, wake) = ai_permits();
        if let Ok(mut state) = lock.lock() {
            state.available = (state.available + 1).min(state.capacity);
            wake.notify_one();
        }
    }
}

fn acquire_ai_permit(cancelled: &AtomicBool) -> Result<AiPermit, AiError> {
    const POLL: Duration = Duration::from_millis(25);
    let max_wait = std::env::var("HELIOSAV_AI_QUEUE_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(5_000)
        .clamp(100, 60_000);
    let deadline = Instant::now() + Duration::from_millis(max_wait);
    let queued_at = Instant::now();
    let (lock, wake) = ai_permits();
    let mut state = lock
        .lock()
        .map_err(|_| AiError::Infer("AI inference permit lock poisoned".to_string()))?;
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return Err(AiError::Infer(
                "inference cancelled while queued".to_string(),
            ));
        }
        if state.available > 0 {
            state.available -= 1;
            AI_QUEUE_WAIT_US.fetch_add(
                queued_at.elapsed().as_micros().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            return Ok(AiPermit);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            AI_QUEUE_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            return Err(AiError::Infer(
                "AI inference queue is full; request was not scheduled".to_string(),
            ));
        }
        let wait_for = remaining.min(POLL);
        let (next_state, _) = wake
            .wait_timeout(state, wait_for)
            .map_err(|_| AiError::Infer("AI inference permit wait failed".to_string()))?;
        state = next_state;
    }
}

/// How scores from multiple loaded models are combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnsembleStrategy {
    #[default]
    WeightedMean,
    MaxRisk,
    MajorityVote,
}

impl EnsembleStrategy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "weighted_mean" | "weighted-mean" | "mean" | "average" => Some(Self::WeightedMean),
            "max_risk" | "max-risk" | "max" | "conservative" => Some(Self::MaxRisk),
            "majority_vote" | "majority-vote" | "vote" => Some(Self::MajorityVote),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WeightedMean => "weighted_mean",
            Self::MaxRisk => "max_risk",
            Self::MajorityVote => "majority_vote",
        }
    }
}

/// Public model registry information returned to the admin/UI layer.
#[derive(Debug, Clone, Serialize)]
pub struct AiModelInfo {
    pub id: String,
    pub role: String,
    pub path: String,
    pub kind: String,
    pub weight: f32,
    pub enabled: bool,
    pub loaded: bool,
    pub feature_dim: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiModelValidationReport {
    pub usable: bool,
    pub path: String,
    pub size_bytes: Option<u64>,
    pub kind: String,
    pub feature_dim: Option<usize>,
    pub input_count: Option<usize>,
    pub output_count: Option<usize>,
    pub input0: Option<String>,
    pub output0: Option<String>,
    pub dry_run_score: Option<f32>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ModelRegistryReport {
    pub loaded: usize,
    pub skipped: Vec<String>,
    pub strategy: String,
}

#[derive(Clone)]
struct EnsembleMember {
    info: AiModelInfo,
    model: Arc<AiModel>,
}

#[derive(Debug, Clone, Deserialize)]
struct ModelRegistryEntry {
    id: String,
    path: String,
    kind: Option<String>,
    weight: Option<f32>,
    enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct ModelRegistryFile {
    strategy: Option<String>,
    #[serde(default)]
    models: Vec<ModelRegistryEntry>,
}

use tract_onnx::prelude::*;

/// Summary returned after a config reload describing applied changes.
#[derive(Debug, Clone)]
pub struct ConfigReloadSummary {
    pub changed_keys: Vec<String>,
    pub previous_ensemble: bool,
    pub new_ensemble: bool,
    pub previous_blend: f32,
    pub new_blend: f32,
    pub loaded_models: usize,
    pub skipped_models: Vec<String>,
    pub strategy: String,
}

impl AiModel {
    /// Create a new AiModel and attempt to load the model from `model_path`.
    pub fn new<P: AsRef<Path>>(model_path: P) -> Result<Self, AiError> {
        Self::new_with_kind(model_path, AiModelKind::from_env())
    }

    pub fn new_with_kind<P: AsRef<Path>>(
        model_path: P,
        kind: AiModelKind,
    ) -> Result<Self, AiError> {
        let p = validate_onnx_model_file(model_path.as_ref())?;
        let model_path = Arc::new(RwLock::new(p.clone()));
        let m = Self {
            model_path: model_path.clone(),
            kind,
            fallback: None,
            ensemble: Arc::new(RwLock::new(
                std::env::var("HELIOSAV_AI_ENSEMBLE")
                    .ok()
                    .map(|v| {
                        matches!(
                            v.trim().to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes" | "on"
                        )
                    })
                    .unwrap_or(true),
            )),
            runnable: ArcSwapOption::empty(),
            blend_primary: Arc::new(RwLock::new(
                std::env::var("HELIOSAV_AI_BLEND_PRIMARY")
                    .ok()
                    .and_then(|v| v.parse::<f32>().ok())
                    .map(|f| f.clamp(0.0, 1.0))
                    .unwrap_or(0.7),
            )),
            feature_map: Arc::new(RwLock::new(None)),
            model_contract: Arc::new(RwLock::new(ModelContract::default())),
            additional_models: Arc::new(RwLock::new(Vec::new())),
            aggregation: Arc::new(RwLock::new(EnsembleStrategy::default())),
        };
        // attempt to load a features.json next to the model if present
        let _ = m.load_feature_map_from_model_dir();
        m.load_model_contract_from_path(&p)?;
        m.reload_model().map(|_| m)
    }

    pub fn with_fallback<P: AsRef<Path>>(
        mut self,
        fallback_path: P,
        fallback_kind: AiModelKind,
    ) -> Result<Self, AiError> {
        let fallback_model = Self::new_with_kind(fallback_path, fallback_kind)?;
        self.fallback = Some(Box::new(fallback_model));
        Ok(self)
    }
    /// Attach a fallback model in-place without consuming `self`.
    pub fn attach_fallback<P: AsRef<Path>>(
        &mut self,
        fallback_path: P,
        fallback_kind: AiModelKind,
    ) -> Result<(), AiError> {
        let fallback_model = Self::new_with_kind(fallback_path, fallback_kind)?;
        self.fallback = Some(Box::new(fallback_model));
        Ok(())
    }

    /// Attach an already constructed fallback model instance in-place.
    pub fn attach_fallback_model(&mut self, fallback: AiModel) {
        self.fallback = Some(Box::new(fallback));
    }

    pub fn set_aggregation_strategy(&self, strategy: EnsembleStrategy) {
        *self.aggregation.write().expect("aggregation lock poisoned") = strategy;
    }

    pub fn aggregation_strategy(&self) -> EnsembleStrategy {
        *self.aggregation.read().expect("aggregation lock poisoned")
    }

    /// Re-aggregate raw per-model scores under the current ensemble settings.
    /// Returns `None` when the cached component set is not compatible with the
    /// current model registry; callers must then perform a full AI inference.
    pub fn aggregate_cached_components(&self, components: &[(String, f32, f32)]) -> Option<f32> {
        if components.is_empty() {
            return None;
        }
        if !self.get_ensemble() {
            return components
                .iter()
                .find(|(id, _, _)| id == "primary")
                .or_else(|| components.first())
                .map(|(_, score, _)| score.clamp(0.0, 1.0));
        }

        let extra_models = self
            .additional_models
            .read()
            .expect("additional model lock poisoned");
        let has_extra_models = extra_models.iter().any(|member| member.info.enabled);
        let mut scores = Vec::with_capacity(components.len());
        for (id, score, original_weight) in components {
            let weight = match id.as_str() {
                "primary" => {
                    if has_extra_models {
                        1.0
                    } else {
                        self.get_blend_primary()
                    }
                }
                "fallback" => {
                    if self.fallback.is_none() {
                        return None;
                    }
                    if has_extra_models {
                        1.0
                    } else {
                        (1.0 - self.get_blend_primary()).max(0.0)
                    }
                }
                custom_id => {
                    let Some(member) = extra_models
                        .iter()
                        .find(|member| member.info.enabled && member.info.id == custom_id)
                    else {
                        return None;
                    };
                    member.info.weight
                }
            };
            let weight = if weight.is_finite() {
                weight.max(0.0)
            } else {
                original_weight.max(0.0)
            };
            scores.push((*score, weight));
        }
        Some(aggregate_scores(self.aggregation_strategy(), &scores))
    }

    fn describe_model(
        id: &str,
        role: &str,
        model: &AiModel,
        weight: f32,
        enabled: bool,
    ) -> AiModelInfo {
        AiModelInfo {
            id: id.to_string(),
            role: role.to_string(),
            path: model.model_path().to_string_lossy().into_owned(),
            kind: format!("{:?}", model.model_kind()),
            weight,
            enabled,
            loaded: model.runnable.load().is_some(),
            feature_dim: model.feature_map().map(|map| map.len()).or(Some(12)),
        }
    }

    /// Return the primary, legacy fallback, and user-managed model entries.
    pub fn model_registry(&self) -> Vec<AiModelInfo> {
        let primary_weight = self.get_blend_primary();
        let mut models = vec![Self::describe_model(
            "primary",
            "primary",
            self,
            primary_weight,
            true,
        )];
        if let Some(fallback) = self.fallback.as_ref() {
            models.push(Self::describe_model(
                "fallback",
                "fallback",
                fallback,
                (1.0 - primary_weight).max(0.0),
                true,
            ));
        }
        models.extend(
            self.additional_models
                .read()
                .expect("additional model lock poisoned")
                .iter()
                .map(|member| member.info.clone()),
        );
        models
    }

    /// Validate whether an ONNX model can be used by HeliosAV's current
    /// feature-vector inference path without importing it into the registry.
    ///
    /// This is stronger than checking the file extension: the model is parsed,
    /// optimized, compiled, its optional sidecars are loaded, and a dry-run is
    /// executed with the feature vector shape that the scanner can provide.
    pub fn validate_model_for_scanner<P: AsRef<Path>>(
        path: P,
        kind: AiModelKind,
    ) -> AiModelValidationReport {
        let requested_path = path.as_ref();
        let mut report = AiModelValidationReport {
            usable: false,
            path: requested_path.to_string_lossy().into_owned(),
            size_bytes: None,
            kind: format!("{:?}", kind),
            feature_dim: None,
            input_count: None,
            output_count: None,
            input0: None,
            output0: None,
            dry_run_score: None,
            warnings: Vec::new(),
            errors: Vec::new(),
        };

        let canonical = match validate_onnx_model_file(requested_path) {
            Ok(path) => path,
            Err(error) => {
                report.errors.push(error.to_string());
                return report;
            }
        };
        report.path = canonical.to_string_lossy().into_owned();
        match fs::metadata(&canonical) {
            Ok(metadata) => report.size_bytes = Some(metadata.len()),
            Err(error) => report.warnings.push(format!(
                "unable to read model size after validation: {error}"
            )),
        }
        if let Some(parent) = canonical.parent() {
            if !parent.join("features.json").is_file() {
                report.warnings.push(
                    "features.json not found; the scanner will provide the built-in 12-feature vector"
                        .to_string(),
                );
            }
            if !parent.join("model_contract.json").is_file() {
                report.warnings.push(
                    "model_contract.json not found; output decoding will use automatic probability/logit heuristics"
                        .to_string(),
                );
            }
        }

        let model = match Self::new_with_kind(&canonical, kind) {
            Ok(model) => model,
            Err(error) => {
                report.errors.push(error.to_string());
                return report;
            }
        };
        let feature_dim = model.feature_map().map(|map| map.len()).unwrap_or(12);
        report.feature_dim = Some(feature_dim);
        if feature_dim == 0 {
            report
                .errors
                .push("feature vector is empty; features.json has no usable entries".to_string());
            return report;
        }
        if feature_dim > 4096 {
            report.warnings.push(format!(
                "feature vector has {feature_dim} entries; very large feature maps may slow scans"
            ));
        }

        let Some(runnable) = model.runnable.load_full() else {
            report
                .errors
                .push("model compiled but no runnable plan is loaded".to_string());
            return report;
        };
        report.input_count = Some(runnable.input_count());
        report.output_count = Some(runnable.output_count());
        report.input0 = runnable.input_fact(0).ok().map(describe_typed_fact);
        report.output0 = runnable.output_fact(0).ok().map(describe_typed_fact);
        if runnable.input_count() != 1 {
            report.errors.push(format!(
                "model requires {} inputs; HeliosAV currently supplies one feature tensor",
                runnable.input_count()
            ));
            return report;
        }
        if runnable.output_count() == 0 {
            report
                .errors
                .push("model has no outputs to decode as a malware score".to_string());
            return report;
        }

        let features = vec![0.0f32; feature_dim];
        match model.infer_vector(&features) {
            Ok(score) if score.is_finite() => {
                report.dry_run_score = Some(score.clamp(0.0, 1.0));
                report.usable = true;
            }
            Ok(score) => report
                .errors
                .push(format!("dry-run returned a non-finite score: {score}")),
            Err(error) => report
                .errors
                .push(format!("dry-run inference failed: {error}")),
        }
        report
    }

    /// Add a pre-existing model located inside the configured model directory.
    pub fn add_model<P: AsRef<Path>>(
        &self,
        id: &str,
        path: P,
        kind: AiModelKind,
        weight: f32,
        enabled: bool,
    ) -> Result<AiModelInfo, AiError> {
        validate_model_weight(weight)?;
        let safe_id = normalize_model_id(id, path.as_ref())?;
        let canonical = validate_onnx_model_file(path.as_ref())?;
        let mut members = self
            .additional_models
            .write()
            .expect("additional model lock poisoned");
        if members
            .iter()
            .any(|member| member.info.id == safe_id || Path::new(&member.info.path) == canonical)
        {
            return Err(AiError::Model(format!(
                "model id or path is already registered: {safe_id}"
            )));
        }
        let model = Arc::new(Self::new_with_kind(&canonical, kind)?);
        let info = Self::describe_model(&safe_id, "custom", &model, weight, enabled);
        members.push(EnsembleMember {
            info: info.clone(),
            model,
        });
        Ok(info)
    }

    /// Import a model into a user-writable model directory, copy its sidecars,
    /// validate it with tract, then register it atomically in the ensemble.
    pub fn import_model<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        source_path: P,
        model_root: Q,
        id: Option<&str>,
        kind: AiModelKind,
        weight: f32,
        enabled: bool,
    ) -> Result<AiModelInfo, AiError> {
        validate_model_weight(weight)?;
        let source = validate_onnx_model_file(source_path.as_ref())?;
        let safe_id = normalize_model_id(id.unwrap_or_default(), &source)?;
        let root = model_root.as_ref();
        fs::create_dir_all(root)?;
        let destination_dir = root.join("imported").join(&safe_id);
        if destination_dir.exists() {
            return Err(AiError::Model(format!(
                "import destination already exists: {}",
                destination_dir.display()
            )));
        }
        fs::create_dir_all(&destination_dir)?;
        let destination = destination_dir.join("model.onnx");
        let copy_result = (|| -> Result<(), AiError> {
            fs::copy(&source, &destination)?;
            if let Some(parent) = source.parent() {
                for sidecar in ["features.json", "model_contract.json"] {
                    let source_sidecar = parent.join(sidecar);
                    if source_sidecar.is_file() {
                        fs::copy(source_sidecar, destination_dir.join(sidecar))?;
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = copy_result {
            let _ = fs::remove_dir_all(&destination_dir);
            return Err(error);
        }

        match self.add_model(&safe_id, &destination, kind, weight, enabled) {
            Ok(info) => Ok(info),
            Err(error) => {
                let _ = fs::remove_dir_all(&destination_dir);
                Err(error)
            }
        }
    }

    pub fn remove_model(&self, id: &str) -> Result<bool, AiError> {
        let mut members = self
            .additional_models
            .write()
            .expect("additional model lock poisoned");
        let before = members.len();
        members.retain(|member| member.info.id != id);
        Ok(before != members.len())
    }

    pub fn update_model(
        &self,
        id: &str,
        weight: Option<f32>,
        enabled: Option<bool>,
    ) -> Result<bool, AiError> {
        if let Some(value) = weight {
            validate_model_weight(value)?;
        }
        let mut members = self
            .additional_models
            .write()
            .expect("additional model lock poisoned");
        let Some(member) = members.iter_mut().find(|member| member.info.id == id) else {
            return Ok(false);
        };
        if let Some(value) = weight {
            member.info.weight = value;
        }
        if let Some(value) = enabled {
            member.info.enabled = value;
        }
        Ok(true)
    }

    pub fn persist_model_registry<P: AsRef<Path>>(&self, path: P) -> Result<(), AiError> {
        let parent = path.as_ref().parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let models = self
            .additional_models
            .read()
            .expect("additional model lock poisoned")
            .iter()
            .map(|member| {
                serde_json::json!({
                    "id": member.info.id,
                    "path": member.info.path,
                    "kind": member.info.kind.to_ascii_lowercase(),
                    "weight": member.info.weight,
                    "enabled": member.info.enabled,
                })
            })
            .collect::<Vec<_>>();
        let value = serde_json::json!({
            "strategy": self.aggregation_strategy().as_str(),
            "models": models,
        });
        fs::write(
            path,
            serde_json::to_vec_pretty(&value)
                .map_err(|error| AiError::Model(format!("serialize model registry: {error}")))?,
        )?;
        Ok(())
    }

    pub fn load_model_registry_from_file<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        config_path: P,
        model_root: Q,
    ) -> Result<ModelRegistryReport, AiError> {
        let config_path = config_path.as_ref();
        let text = fs::read_to_string(config_path)?;
        let config: ModelRegistryFile = serde_json::from_str(&text)
            .map_err(|error| AiError::Model(format!("model registry parse: {error}")))?;
        let strategy = config
            .strategy
            .as_deref()
            .and_then(EnsembleStrategy::parse)
            .unwrap_or_else(|| self.aggregation_strategy());
        let root = model_root.as_ref().canonicalize().map_err(|error| {
            AiError::Model(format!("model registry root is not accessible: {error}"))
        })?;
        let config_parent = config_path.parent().unwrap_or_else(|| Path::new("."));
        let mut loaded = Vec::new();
        let mut skipped = Vec::new();
        let mut ids = HashSet::new();
        for entry in config.models {
            let id = match normalize_model_id(&entry.id, Path::new(&entry.path)) {
                Ok(value) => value,
                Err(error) => {
                    skipped.push(error.to_string());
                    continue;
                }
            };
            if !ids.insert(id.clone()) {
                skipped.push(format!("duplicate model id: {id}"));
                continue;
            }
            let raw_path = PathBuf::from(&entry.path);
            let path = if raw_path.is_absolute() {
                raw_path
            } else {
                config_parent.join(raw_path)
            };
            let canonical = match validate_onnx_model_file(&path) {
                Ok(value) if value.starts_with(&root) => value,
                Ok(_) => {
                    skipped.push(format!("model is outside registry root: {id}"));
                    continue;
                }
                Err(error) => {
                    skipped.push(format!("{id}: {error}"));
                    continue;
                }
            };
            let kind = parse_model_kind(entry.kind.as_deref()).unwrap_or(AiModelKind::CNN);
            let weight = entry.weight.unwrap_or(1.0);
            if let Err(error) = validate_model_weight(weight) {
                skipped.push(format!("{id}: {error}"));
                continue;
            }
            let enabled = entry.enabled.unwrap_or(true);
            match Self::new_with_kind(&canonical, kind) {
                Ok(model) => {
                    let model = Arc::new(model);
                    let info = Self::describe_model(&id, "custom", &model, weight, enabled);
                    loaded.push(EnsembleMember { info, model });
                }
                Err(error) => skipped.push(format!("{id}: {error}")),
            }
        }
        *self
            .additional_models
            .write()
            .expect("additional model lock poisoned") = loaded;
        self.set_aggregation_strategy(strategy);
        Ok(ModelRegistryReport {
            loaded: self
                .additional_models
                .read()
                .expect("additional model lock poisoned")
                .len(),
            skipped,
            strategy: strategy.as_str().to_string(),
        })
    }

    /// Load features.json from the same directory as the configured model path, if present.
    pub fn load_feature_map_from_model_dir(&self) -> Result<(), AiError> {
        let current_path = self
            .model_path
            .read()
            .expect("model_path lock poisoned")
            .clone();
        self.load_feature_map_from_path(&current_path)
    }

    fn load_feature_map_from_path<P: AsRef<Path>>(&self, path: P) -> Result<(), AiError> {
        let names = path
            .as_ref()
            .parent()
            .map(|parent| parent.join("features.json"))
            .filter(|path| path.is_file())
            .map(|path| {
                validate_sidecar_file(&path, "features.json")?;
                let mut text = String::new();
                File::open(&path)
                    .map_err(AiError::Io)?
                    .read_to_string(&mut text)
                    .map_err(AiError::Io)?;
                let value: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| AiError::Model(format!("features.json parse: {e}")))?;
                Ok::<Option<Vec<String>>, AiError>(value.as_array().map(|array| {
                    array
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                }))
            })
            .transpose()?
            .flatten();
        *self.feature_map.write().expect("feature_map lock poisoned") = names;
        Ok(())
    }

    /// Load optional output metadata next to a model.
    ///
    /// The sidecar is intentionally small so models exported by different toolchains can
    /// describe their output without requiring a new Rust build. Supported keys are:
    /// `output_index`, `malicious_index`, and `output_kind` (`auto`, `probability`, `logit`).
    /// The same keys may also appear under an `output` object.
    fn load_model_contract_from_path<P: AsRef<Path>>(&self, path: P) -> Result<(), AiError> {
        let Some(parent) = path.as_ref().parent() else {
            return Ok(());
        };
        let contract_path = parent.join("model_contract.json");
        if !contract_path.is_file() {
            let mut guard = self
                .model_contract
                .write()
                .expect("model contract lock poisoned");
            *guard = ModelContract::default();
            return Ok(());
        }

        let mut text = String::new();
        validate_sidecar_file(&contract_path, "model_contract.json")?;
        File::open(&contract_path)?.read_to_string(&mut text)?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| AiError::Model(format!("model_contract.json parse: {e}")))?;
        let output = value.get("output").and_then(serde_json::Value::as_object);

        let read_usize = |key: &str| {
            value
                .get(key)
                .or_else(|| output.and_then(|object| object.get(key)))
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
        };
        let output_kind = value
            .get("output_kind")
            .or_else(|| output.and_then(|object| object.get("kind")))
            .and_then(serde_json::Value::as_str)
            .map(|value| match value.trim().to_ascii_lowercase().as_str() {
                "probability" | "probabilities" | "prob" => OutputKind::Probability,
                "logit" | "logits" => OutputKind::Logit,
                _ => OutputKind::Auto,
            })
            .unwrap_or_default();

        let contract = ModelContract {
            output_index: read_usize("output_index"),
            malicious_index: read_usize("malicious_index"),
            output_kind,
        };
        *self
            .model_contract
            .write()
            .expect("model contract lock poisoned") = contract;
        Ok(())
    }

    /// Set the primary blend weight (0.0..1.0) used when `ensemble` is enabled.
    pub fn set_blend_primary(&self, weight: f32) {
        let mut guard = self.blend_primary.write().expect("blend lock poisoned");
        *guard = weight.clamp(0.0, 1.0);
    }

    /// Apply an optional feature mapping (from `features.json`) to the default 12-element vector,
    /// producing a vector ordered as the external model expects (unknown names filled with 0.0).
    pub fn apply_feature_mapping(&self, base: [f32; 12]) -> Vec<f32> {
        // default feature names in the canonical order produced by `extract_features`
        const DEFAULT_NAMES: [&str; 12] = [
            "coverage",
            "section_count",
            "import_count",
            "tls_present",
            "timestamp",
            "section_entropy",
            "printable_ratio",
            "null_ratio",
            "distinct_byte_ratio",
            "mean_byte",
            "entropy_norm",
            "large_flag",
        ];
        if let Some(map) = &*self.feature_map.read().expect("feature_map lock poisoned") {
            let mut out = Vec::with_capacity(map.len());
            for name in map.iter() {
                if let Some(pos) = DEFAULT_NAMES.iter().position(|n| n == name) {
                    out.push(base[pos]);
                } else {
                    out.push(0.0);
                }
            }
            out
        } else {
            base.to_vec()
        }
    }

    /// Load a new ONNX model from `path` and replace the current runnable atomically.
    pub fn load_model_from_path<P: AsRef<Path>>(&self, path: P) -> Result<(), AiError> {
        let p = validate_onnx_model_file(path.as_ref())?;
        info!("Hot-loading ONNX model from {}", p.display());
        let runnable = compile_model(&p)?;
        self.load_model_contract_from_path(&p)?;
        self.load_feature_map_from_path(&p)?;
        log_model_contract(&runnable, &p);
        self.runnable.store(Some(runnable));
        let mut path_guard = self.model_path.write().expect("model_path lock poisoned");
        *path_guard = p.clone();
        Ok(())
    }

    /// Get current primary blend weight (0.0..1.0).
    pub fn get_blend_primary(&self) -> f32 {
        *self.blend_primary.read().expect("blend lock poisoned")
    }

    /// Get current ensemble enabled flag.
    pub fn get_ensemble(&self) -> bool {
        *self.ensemble.read().expect("ensemble lock poisoned")
    }

    /// Reload runtime configuration from a JSON file. Supported keys include
    /// legacy ensemble settings plus `strategy` and a user model `models` list.
    /// Returns a `ConfigReloadSummary` listing applied changes and prior values.
    pub fn reload_config_from_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<ConfigReloadSummary, AiError> {
        let p = path.as_ref();
        let mut buf = String::new();
        std::fs::File::open(p)
            .map_err(AiError::Io)?
            .read_to_string(&mut buf)
            .map_err(AiError::Io)?;
        let v: serde_json::Value =
            serde_json::from_str(&buf).map_err(|e| AiError::Model(format!("json parse: {}", e)))?;

        let mut changed = Vec::new();
        let previous_ensemble = *self.ensemble.read().expect("ensemble lock poisoned");
        let previous_blend = *self.blend_primary.read().expect("blend lock poisoned");
        let mut new_ensemble = previous_ensemble;
        let mut new_blend = previous_blend;
        let previous_strategy = self.aggregation_strategy();
        let mut loaded_models = self
            .additional_models
            .read()
            .expect("additional model lock poisoned")
            .len();
        let mut skipped_models = Vec::new();

        if let Some(e) = v.get("ensemble") {
            if let Some(b) = e.as_bool() {
                if b != previous_ensemble {
                    self.set_ensemble(b);
                    changed.push("ensemble".to_string());
                    new_ensemble = b;
                }
            }
        }
        if let Some(bp) = v.get("blend_primary") {
            if let Some(f) = bp.as_f64() {
                let f32v = (f as f32).clamp(0.0, 1.0);
                if (f32v - previous_blend).abs() > f32::EPSILON {
                    self.set_blend_primary(f32v);
                    changed.push("blend_primary".to_string());
                    new_blend = f32v;
                }
            }
        }

        if let Some(strategy) = v.get("strategy").and_then(serde_json::Value::as_str) {
            let parsed = EnsembleStrategy::parse(strategy).ok_or_else(|| {
                AiError::Model(format!("unsupported ensemble strategy: {strategy}"))
            })?;
            if parsed != previous_strategy {
                self.set_aggregation_strategy(parsed);
                changed.push("strategy".to_string());
            }
        }
        if v.get("models").is_some() {
            let root = p.parent().unwrap_or_else(|| Path::new("."));
            let report = self.load_model_registry_from_file(p, root)?;
            loaded_models = report.loaded;
            skipped_models = report.skipped;
            changed.push("models".to_string());
        }

        Ok(ConfigReloadSummary {
            changed_keys: changed,
            previous_ensemble,
            new_ensemble,
            previous_blend,
            new_blend,
            loaded_models,
            skipped_models,
            strategy: self.aggregation_strategy().as_str().to_string(),
        })
    }

    /// Set ensemble flag at runtime.
    pub fn set_ensemble(&self, enabled: bool) {
        let mut guard = self.ensemble.write().expect("ensemble lock poisoned");
        *guard = enabled;
    }

    pub fn with_ensemble(self, enabled: bool) -> Self {
        if let Ok(mut guard) = self.ensemble.write() {
            *guard = enabled;
        }
        self
    }

    pub fn model_kind(&self) -> AiModelKind {
        self.kind
    }

    pub fn model_path(&self) -> PathBuf {
        self.model_path
            .read()
            .expect("model_path lock poisoned")
            .clone()
    }

    /// Return a stable cache-context token for the currently loaded model
    /// graph and ensemble membership. File metadata is included so replacing
    /// an ONNX file at the same path invalidates old scan evidence.
    pub fn model_version(&self) -> u64 {
        let mut digest = Sha256::new();
        let update_path = |digest: &mut Sha256, path: &Path| {
            digest.update(path.to_string_lossy().as_bytes());
            digest.update([0]);
            if let Ok(metadata) = fs::metadata(path) {
                digest.update(metadata.len().to_le_bytes());
                if let Ok(modified) = metadata.modified() {
                    if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
                        digest.update(duration.as_secs().to_le_bytes());
                        digest.update(duration.subsec_nanos().to_le_bytes());
                    }
                }
            }
        };
        update_path(&mut digest, &self.model_path());
        digest.update([match self.kind {
            AiModelKind::CNN => 1,
            AiModelKind::Transformer => 2,
        }]);
        if let Some(fallback) = self.fallback.as_deref() {
            digest.update(fallback.model_version().to_le_bytes());
        }
        if let Ok(models) = self.additional_models.read() {
            for member in models.iter() {
                digest.update(member.info.id.as_bytes());
                digest.update([0]);
                update_path(&mut digest, Path::new(&member.info.path));
                digest.update(member.info.weight.to_bits().to_le_bytes());
                digest.update([u8::from(member.info.enabled)]);
            }
        }
        let digest: [u8; 32] = digest.finalize().into();
        u64::from_le_bytes(
            digest[..8]
                .try_into()
                .expect("SHA-256 prefix has eight bytes"),
        )
    }

    pub fn feature_map(&self) -> Option<Vec<String>> {
        self.feature_map
            .read()
            .expect("feature_map lock poisoned")
            .clone()
    }

    /// Load or reload the ONNX model into a runnable plan.
    /// Supports INT8 quantized models transparently via tract.
    pub fn reload_model(&self) -> Result<(), AiError> {
        let path = self
            .model_path
            .read()
            .expect("model_path lock poisoned")
            .clone();
        let path = validate_onnx_model_file(&path)?;
        info!("Loading ONNX model from {}", path.display());
        let runnable = compile_model(&path)?;

        self.load_model_contract_from_path(&path)?;
        self.load_feature_map_from_path(&path)?;
        log_model_contract(&runnable, &path);
        self.runnable.store(Some(runnable));
        info!("Model loaded successfully");
        Ok(())
    }

    /// Preprocess a file blob into 12 bounded numeric features.
    pub fn extract_features(blob: &[u8]) -> [f32; 12] {
        Self::extract_features_with_size(blob, blob.len() as u64)
    }

    fn extract_features_with_size(blob: &[u8], file_size: u64) -> [f32; 12] {
        let mut features = [0f32; 12];
        // How much of the file is represented by this bounded sample.
        features[0] = (blob.len() as f64 / file_size.max(1) as f64).min(1.0) as f32;

        // format specific: attempt to parse using goblin
        if let Ok(obj) = Object::parse(blob) {
            match obj {
                Object::PE(pe) => {
                    features[1] = (pe.sections.len() as f32 / 32.0).min(1.0);
                    features[2] = (pe.imports.len() as f32 / 256.0).min(1.0);
                    // TLS presence
                    if let Some(optional_header) = &pe.header.optional_header {
                        if optional_header
                            .data_directories
                            .get_tls_table()
                            .as_ref()
                            .map(|d| d.size > 0)
                            .unwrap_or(false)
                        {
                            features[3] = 1.0;
                        }
                        features[4] =
                            timestamp_anomaly_score(pe.header.coff_header.time_date_stamp);
                    }
                    // entropy estimate on available raw data
                    let mut entropy = 0f32;
                    for s in &pe.sections {
                        let start = s.pointer_to_raw_data as usize;
                        let size = s.size_of_raw_data as usize;
                        if let Some(end) = start.checked_add(size) {
                            if end <= blob.len() && size > 0 {
                                entropy = crate::layers::heuristic::entropy(&blob[start..end]);
                                break;
                            }
                        }
                    }
                    features[5] = (entropy / 8.0).clamp(0.0, 1.0);
                }
                Object::Elf(elf) => {
                    features[1] = (elf.section_headers.len() as f32 / 64.0).min(1.0);
                    features[2] = (elf.libraries.len() as f32 / 128.0).min(1.0);
                    features[3] = 0.0; // TLS not typical here
                    features[4] = 0.0;
                    features[5] = 0.0;
                }
                Object::Mach(goblin::mach::Mach::Binary(mach)) => {
                    features[1] = (mach.segments.len() as f32 / 32.0).min(1.0);
                    features[2] = (mach.libs.len() as f32 / 128.0).min(1.0);
                }
                _ => {}
            }
        }

        // statistical features
        let printable = blob
            .iter()
            .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count() as f32
            / blob.len().max(1) as f32;
        features[6] = printable; // printable ratio
        let nulls = blob.iter().filter(|b| **b == 0).count() as f32 / blob.len().max(1) as f32;
        features[7] = nulls;
        // number of distinct byte values
        let mut seen = [false; 256];
        for &b in blob {
            seen[b as usize] = true;
        }
        features[8] = seen.iter().filter(|v| **v).count() as f32 / 256.0;
        // mean byte value
        let sum: usize = blob.iter().map(|b| *b as usize).sum();
        features[9] = sum as f32 / blob.len().max(1) as f32 / 255.0;
        // simple entropy approximation using heuristic module
        features[10] = crate::layers::heuristic::entropy(blob) / 8.0; // normalize to 0..=1
                                                                      // file size flag for small/large
        features[11] = if file_size > 1024 * 1024 { 1.0 } else { 0.0 };

        features
    }

    fn extract_model_features(&self, blob: &[u8], file_size: u64) -> Vec<f32> {
        let cache_key = feature_cache_key(blob, file_size);
        let base = if let Some(features) = FEATURE_CACHE.base.get(&cache_key) {
            *features
        } else {
            let features = Self::extract_features_with_size(blob, file_size);
            FEATURE_CACHE.base.insert(cache_key, features);
            FEATURE_CACHE.trim_if_needed();
            features
        };
        let Some(names) = self
            .feature_map
            .read()
            .expect("feature_map lock poisoned")
            .clone()
        else {
            return base.to_vec();
        };
        let named_key = NamedFeatureCacheKey {
            base: cache_key,
            feature_map_sha256: feature_map_digest(&names),
        };
        if let Some(features) = FEATURE_CACHE.named.get(&named_key) {
            return features.as_ref().clone();
        }
        let features = extract_named_features(blob, file_size, &names, base);
        FEATURE_CACHE
            .named
            .insert(named_key, Arc::new(features.clone()));
        FEATURE_CACHE.trim_if_needed();
        features
    }

    #[allow(dead_code)]
    fn score_tensor(output: &Tensor) -> Result<f32, AiError> {
        Self::score_tensor_with_contract(output, None, OutputKind::Auto)
    }

    fn score_tensor_with_contract(
        output: &Tensor,
        malicious_index: Option<usize>,
        output_kind: OutputKind,
    ) -> Result<f32, AiError> {
        // ONNX exporters commonly emit f16, f32, f64, integer, or quantized tensors.
        // Convert numeric output to f32 once, then keep the probability logic consistent.
        let output = output
            .cast_to::<f32>()
            .map_err(|error| AiError::Infer(format!("unsupported model output type: {error}")))?;
        let view = output
            .to_plain_array_view::<f32>()
            .map_err(|error| AiError::Infer(format!("unsupported model output: {error}")))?;
        let values = view
            .as_slice()
            .ok_or_else(|| AiError::Infer("output not contiguous".to_string()))?;
        if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
            return Err(AiError::Infer(
                "model output is empty or non-finite".to_string(),
            ));
        }
        if values.len() == 1 {
            let value = values[0];
            return match output_kind {
                OutputKind::Probability => Ok(value.clamp(0.0, 1.0)),
                OutputKind::Logit => Ok(1.0 / (1.0 + (-value).exp())),
                OutputKind::Auto => Ok(if (0.0..=1.0).contains(&value) {
                    value
                } else {
                    1.0 / (1.0 + (-value).exp())
                }),
            };
        }

        let malicious_index = malicious_index.unwrap_or(if values.len() == 2 {
            1
        } else {
            values.len() - 1
        });
        if malicious_index >= values.len() {
            return Err(AiError::Infer(format!(
                "malicious_index {} is outside output length {}",
                malicious_index,
                values.len()
            )));
        }

        let all_probabilities = values.iter().all(|value| (0.0..=1.0).contains(value));
        if matches!(output_kind, OutputKind::Probability)
            || (matches!(output_kind, OutputKind::Auto)
                && all_probabilities
                && (values.iter().sum::<f32>() - 1.0).abs() < 0.01)
        {
            return Ok(values[malicious_index].clamp(0.0, 1.0));
        }

        // Otherwise treat the complete vector as logits. This handles binary and
        // multi-class classifiers without silently ignoring classes after index 1.
        let maximum = values.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let normalizer = values
            .iter()
            .map(|value| (*value - maximum).exp())
            .sum::<f32>();
        Ok(((values[malicious_index] - maximum).exp() / normalizer).clamp(0.0, 1.0))
    }

    fn score_outputs(outputs: &TVec<TValue>, contract: &ModelContract) -> Result<f32, AiError> {
        if outputs.is_empty() {
            return Err(AiError::Infer("model returned no outputs".to_string()));
        }

        let mut indexes = Vec::with_capacity(outputs.len());
        if let Some(index) = contract.output_index {
            indexes.push(index);
        } else {
            indexes.extend(0..outputs.len());
        }

        let mut last_error = None;
        for index in indexes {
            let Some(output) = outputs.get(index) else {
                last_error = Some(AiError::Infer(format!(
                    "output_index {} is outside output count {}",
                    index,
                    outputs.len()
                )));
                continue;
            };
            match Self::score_tensor_with_contract(
                output,
                contract.malicious_index,
                contract.output_kind,
            ) {
                Ok(score) => return Ok(score),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| AiError::Infer("no decodable model output".to_string())))
    }

    /// Run inference on a single feature vector, returning a score 0.0..1.0.
    #[allow(dead_code)]
    fn infer_features(&self, features: &[f32; 12]) -> Result<f32, AiError> {
        self.infer_vector(features)
    }

    fn infer_sample_from_model(&self, buf: &[u8], file_size: u64) -> Result<AiScore, AiError> {
        let mapped = self.extract_model_features(buf, file_size);
        match self.infer_vector(&mapped) {
            Ok(score) => Ok(AiScore {
                score,
                components: vec![AiComponentScore {
                    id: "primary".to_string(),
                    score,
                    weight: 1.0,
                }],
                is_fallback: false,
                fallback_reason: None,
            }),
            Err(e) => {
                AI_INFERENCE_ERRORS.fetch_add(1, Ordering::Relaxed);
                let model_path = self.model_path().display().to_string();
                warn!(
                    "AI inference failed for model {}: {}. Falling back to heuristic",
                    model_path, e
                );
                let reason = format!("model {} inference failed: {}", model_path, e);
                match analyze_bytes(buf) {
                    Ok(h) => Ok(AiScore {
                        score: h.score,
                        components: vec![AiComponentScore {
                            id: "primary".to_string(),
                            score: h.score,
                            weight: 1.0,
                        }],
                        is_fallback: true,
                        fallback_reason: Some(reason),
                    }),
                    Err(heuristic_error) => Ok(AiScore {
                        score: 0.0,
                        components: vec![AiComponentScore {
                            id: "primary".to_string(),
                            score: 0.0,
                            weight: 1.0,
                        }],
                        is_fallback: true,
                        fallback_reason: Some(format!(
                            "{}; heuristic fallback failed: {}",
                            reason, heuristic_error
                        )),
                    }),
                }
            }
        }
    }

    /// Infer from an arbitrary-length feature vector.
    ///
    /// A concrete ONNX input shape is authoritative. For dynamic inputs, common flat,
    /// sequence, and 4-D singleton layouts are tried. The input tensor is converted to
    /// the dtype declared by the model, including f16/f64 and integer/quantized tensors.
    pub fn infer_vector(&self, features: &[f32]) -> Result<f32, AiError> {
        if let Some(runnable) = self.runnable.load_full() {
            if features.is_empty() {
                return Err(AiError::Infer("feature vector is empty".to_string()));
            }
            if runnable.input_count() != 1 {
                return Err(AiError::Infer(format!(
                    "model requires {} inputs; the scanner supplies one feature tensor",
                    runnable.input_count()
                )));
            }

            let input_fact = runnable
                .input_fact(0)
                .map_err(|error| AiError::Infer(format!("read model input contract: {error}")))?;
            let input_dtype = input_fact.datum_type;
            if !input_dtype.is_number() {
                return Err(AiError::Infer(format!(
                    "unsupported model input type {input_dtype:?}; expected a numeric tensor"
                )));
            }
            let shapes = input_shape_candidates(input_fact, features.len())?;
            let contract = self
                .model_contract
                .read()
                .expect("model contract lock poisoned")
                .clone();
            let mut last_error = None;

            for shape in shapes {
                let shape_label = format_shape(&shape);
                let tensor = match tensor_from_features(features, &shape, input_dtype) {
                    Ok(tensor) => tensor,
                    Err(error) => {
                        last_error = Some(error.to_string());
                        continue;
                    }
                };
                match runnable.run(tvec!(tensor.into())) {
                    Ok(outputs) => match Self::score_outputs(&outputs, &contract) {
                        Ok(score) => return Ok(score),
                        Err(error) => last_error = Some(format!("{shape_label}: {error}")),
                    },
                    Err(error) => {
                        last_error = Some(format!("runnable run {shape_label}: {error}"));
                    }
                }
            }

            Err(AiError::Infer(last_error.unwrap_or_else(|| {
                "no compatible input shape succeeded".to_string()
            })))
        } else {
            Err(AiError::Model("no model loaded".to_string()))
        }
    }

    /// Run inference for a single file path using a bounded head/tail sample.
    /// Falls back to the alternate model when configured, and can aggregate
    /// any number of user-managed models when ensemble mode is enabled.
    pub fn infer_path<P: AsRef<Path>>(&self, path: P) -> Result<AiScore, AiError> {
        self.infer_path_with_cancel(path, &AtomicBool::new(false))
    }

    /// Cooperative cancellation boundary for the scanner orchestrator. ONNX
    /// runtimes cannot safely interrupt a native graph mid-call, so the
    /// cancellation token is checked before sampling and immediately before
    /// dispatching work to the dedicated inference pool.
    pub fn infer_path_with_cancel<P: AsRef<Path>>(
        &self,
        path: P,
        cancelled: &AtomicBool,
    ) -> Result<AiScore, AiError> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(AiError::Infer("inference cancelled".to_string()));
        }
        let path_ref = path.as_ref();
        let (sample, file_size) = read_feature_sample(path_ref, 64 * 1024)?;
        if cancelled.load(Ordering::Relaxed) {
            return Err(AiError::Infer("inference cancelled".to_string()));
        }
        let _permit = acquire_ai_permit(cancelled)?;
        let run = || self.infer_sample_ensemble(&sample, file_size);
        let started = Instant::now();
        match AI_POOL.as_ref() {
            Some(pool) => {
                let result = pool.install(run);
                AI_INFERENCE_TIME_US.fetch_add(
                    started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                    Ordering::Relaxed,
                );
                AI_INFERENCE_REQUESTS.fetch_add(1, Ordering::Relaxed);
                result
            }
            None => {
                let result = run();
                AI_INFERENCE_TIME_US.fetch_add(
                    started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                    Ordering::Relaxed,
                );
                AI_INFERENCE_REQUESTS.fetch_add(1, Ordering::Relaxed);
                result
            }
        }
    }

    fn infer_sample_ensemble(&self, sample: &[u8], file_size: u64) -> Result<AiScore, AiError> {
        let ensemble_enabled = self.get_ensemble();
        if !ensemble_enabled {
            let primary = self.infer_sample_from_model(sample, file_size);
            let Some(fallback) = self.fallback.as_ref() else {
                return primary;
            };
            return match primary {
                Ok(score) => Ok(score),
                Err(primary_error) => fallback
                    .infer_sample_from_model(sample, file_size)
                    .map_err(|_| primary_error),
            };
        }

        let extra_models = self
            .additional_models
            .read()
            .expect("additional model lock poisoned")
            .iter()
            .filter(|member| member.info.enabled)
            .cloned()
            .collect::<Vec<_>>();
        let fallback = self.fallback.as_deref();
        let ((primary_result, fallback_result), extra_results) = rayon::join(
            || {
                rayon::join(
                    || self.infer_sample_from_model(sample, file_size),
                    || fallback.map(|model| model.infer_sample_from_model(sample, file_size)),
                )
            },
            || {
                extra_models
                    .par_iter()
                    .map(|member| {
                        (
                            member.info.id.clone(),
                            member.info.weight,
                            member.model.infer_sample_from_model(sample, file_size),
                        )
                    })
                    .collect::<Vec<_>>()
            },
        );

        let mut scores = Vec::with_capacity(2 + extra_results.len());
        let mut components = Vec::with_capacity(2 + extra_results.len());
        let mut any_fallback = false;
        let mut fallback_reasons = Vec::new();
        let mut first_error = None;
        match primary_result {
            Ok(score) => {
                any_fallback |= score.is_fallback;
                if let Some(reason) = score.fallback_reason {
                    fallback_reasons.push(reason);
                }
                let weight = if extra_models.is_empty() {
                    self.get_blend_primary()
                } else {
                    1.0
                };
                components.push(AiComponentScore {
                    id: "primary".to_string(),
                    score: score.score,
                    weight,
                });
                scores.push((score.score, weight));
            }
            Err(error) => first_error = Some(error),
        }
        if let Some(result) = fallback_result {
            match result {
                Ok(score) => {
                    any_fallback |= score.is_fallback;
                    if let Some(reason) = score.fallback_reason {
                        fallback_reasons.push(reason);
                    }
                    let weight = if extra_models.is_empty() {
                        (1.0 - self.get_blend_primary()).max(0.0)
                    } else {
                        1.0
                    };
                    components.push(AiComponentScore {
                        id: "fallback".to_string(),
                        score: score.score,
                        weight,
                    });
                    scores.push((score.score, weight));
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        for (id, weight, result) in extra_results {
            match result {
                Ok(score) => {
                    any_fallback |= score.is_fallback;
                    if let Some(reason) = score.fallback_reason {
                        fallback_reasons.push(format!("{}: {}", id, reason));
                    }
                    components.push(AiComponentScore {
                        id,
                        score: score.score,
                        weight,
                    });
                    scores.push((score.score, weight));
                }
                Err(error) => warn!("additional AI model {} failed: {}", id, error),
            }
        }
        if scores.is_empty() {
            return Err(first_error
                .unwrap_or_else(|| AiError::Infer("all configured AI models failed".to_string())));
        }
        Ok(AiScore {
            score: aggregate_scores(self.aggregation_strategy(), &scores),
            components,
            is_fallback: any_fallback,
            fallback_reason: (!fallback_reasons.is_empty()).then(|| fallback_reasons.join("; ")),
        })
    }

    /// Batch inference across multiple paths in parallel.
    /// Returns Vec<AiScore> in input order.
    pub fn infer_batch(&self, paths: Vec<PathBuf>) -> Vec<AiScore> {
        let run = || {
            paths
                .into_par_iter()
                .map(|p| match self.infer_path(&p) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("infer_path error {}: {}", p.display(), e);
                        AiScore {
                            score: 0.0,
                            components: Vec::new(),
                            is_fallback: true,
                            fallback_reason: Some(e.to_string()),
                        }
                    }
                })
                .collect()
        };
        match AI_POOL.as_ref() {
            Some(pool) => pool.install(run),
            None => run(),
        }
    }
}

pub(crate) const MAX_IMPORTED_MODEL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MODEL_SIDECAR_BYTES: u64 = 1 * 1024 * 1024;
const DEFAULT_MODEL_LOAD_TIMEOUT_MS: u64 = 30_000;

struct ModelLoadGuard;

impl ModelLoadGuard {
    fn acquire() -> Result<Self, AiError> {
        MODEL_LOAD_IN_PROGRESS
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| AiError::Model("another ONNX model load is already in progress".into()))
    }
}

impl Drop for ModelLoadGuard {
    fn drop(&mut self) {
        MODEL_LOAD_IN_PROGRESS.store(false, Ordering::Release);
    }
}

fn model_load_timeout() -> Duration {
    Duration::from_millis(
        std::env::var("HELIOSAV_AI_MODEL_LOAD_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MODEL_LOAD_TIMEOUT_MS)
            .clamp(1_000, 120_000),
    )
}

fn compile_model(path: &Path) -> Result<Arc<TypedRunnableModel>, AiError> {
    let path = path.to_path_buf();
    let guard = ModelLoadGuard::acquire()?;
    let timeout = model_load_timeout();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("ai-model-load".to_string())
        .spawn(move || {
            let result = (|| {
                let model = tract_onnx::onnx()
                    .model_for_path(&path)
                    .map_err(|error| AiError::Model(format!("parse ONNX model: {error}")))?;
                let optimized = model
                    .into_optimized()
                    .map_err(|error| AiError::Model(format!("optimize ONNX model: {error}")))?;
                let runnable = optimized
                    .into_runnable()
                    .map_err(|error| AiError::Model(format!("compile ONNX model: {error}")))?;
                Ok::<Arc<TypedRunnableModel>, AiError>(runnable)
            })();
            drop(guard);
            let _ = sender.send(result);
        })
        .map_err(|error| AiError::Model(format!("spawn model load worker: {error}")))?;

    receiver.recv_timeout(timeout).map_err(|error| {
        AiError::Model(match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => {
                format!("ONNX model load timed out after {} ms", timeout.as_millis())
            }
            std::sync::mpsc::RecvTimeoutError::Disconnected => {
                "ONNX model load worker disconnected".to_string()
            }
        })
    })?
}

fn validate_sidecar_file(path: &Path, name: &str) -> Result<(), AiError> {
    let size = fs::metadata(path)?.len();
    if size > MAX_MODEL_SIDECAR_BYTES {
        return Err(AiError::Model(format!(
            "{name} exceeds the {} MiB safety limit",
            MAX_MODEL_SIDECAR_BYTES / (1024 * 1024)
        )));
    }
    Ok(())
}

fn validate_model_weight(weight: f32) -> Result<(), AiError> {
    if !weight.is_finite() || weight < 0.0 {
        return Err(AiError::Model(
            "model weight must be finite and non-negative".to_string(),
        ));
    }
    Ok(())
}

fn aggregate_scores(strategy: EnsembleStrategy, scores: &[(f32, f32)]) -> f32 {
    if scores.is_empty() {
        return 0.0;
    }
    match strategy {
        EnsembleStrategy::MaxRisk => scores
            .iter()
            .map(|(score, _)| *score)
            .fold(0.0f32, f32::max)
            .clamp(0.0, 1.0),
        EnsembleStrategy::MajorityVote => {
            let total_weight: f32 = scores.iter().map(|(_, weight)| weight.max(0.0)).sum();
            if total_weight <= f32::EPSILON {
                let positives = scores.iter().filter(|(score, _)| *score >= 0.5).count();
                return if positives * 2 >= scores.len() {
                    1.0
                } else {
                    0.0
                };
            }
            let positive_weight: f32 = scores
                .iter()
                .filter(|(score, _)| *score >= 0.5)
                .map(|(_, weight)| weight.max(0.0))
                .sum();
            if positive_weight * 2.0 >= total_weight {
                1.0
            } else {
                0.0
            }
        }
        EnsembleStrategy::WeightedMean => {
            let positive_weight: f32 = scores
                .iter()
                .map(|(score, weight)| score.clamp(0.0, 1.0) * weight.max(0.0))
                .sum();
            let total_weight: f32 = scores.iter().map(|(_, weight)| weight.max(0.0)).sum();
            if total_weight <= f32::EPSILON {
                scores.iter().map(|(score, _)| *score).sum::<f32>() / scores.len() as f32
            } else {
                positive_weight / total_weight
            }
            .clamp(0.0, 1.0)
        }
    }
}

fn parse_model_kind(value: Option<&str>) -> Option<AiModelKind> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "transformer" | "tf" => Some(AiModelKind::Transformer),
        "cnn" | "mlp" | "classifier" => Some(AiModelKind::CNN),
        _ => None,
    }
}

fn normalize_model_id(requested: &str, path: &Path) -> Result<String, AiError> {
    let candidate = if requested.trim().is_empty() {
        path.file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("custom-model")
    } else {
        requested.trim()
    };
    if candidate.len() > 64
        || candidate == "."
        || candidate == ".."
        || candidate
            .chars()
            .any(|value| !(value.is_ascii_alphanumeric() || matches!(value, '-' | '_' | '.')))
    {
        return Err(AiError::Model(
            "model id must use only ASCII letters, numbers, '-', '_' or '.' and be <=64 characters"
                .to_string(),
        ));
    }
    Ok(candidate.to_string())
}

pub(crate) fn validate_onnx_model_file(path: &Path) -> Result<PathBuf, AiError> {
    let canonical = path
        .canonicalize()
        .map_err(|error| AiError::Model(format!("model path is not accessible: {error}")))?;
    if !canonical.is_file() {
        return Err(AiError::Model(
            "model path must be a regular file".to_string(),
        ));
    }
    if !canonical
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("onnx"))
    {
        return Err(AiError::Model(
            "only .onnx model files may be loaded".to_string(),
        ));
    }
    let size = fs::metadata(&canonical)?.len();
    if size == 0 || size > MAX_IMPORTED_MODEL_BYTES {
        return Err(AiError::Model(format!(
            "model size must be between 1 byte and {} MiB",
            MAX_IMPORTED_MODEL_BYTES / (1024 * 1024)
        )));
    }
    Ok(canonical)
}

fn input_shape_candidates(
    input_fact: &TypedFact,
    feature_len: usize,
) -> Result<Vec<Vec<usize>>, AiError> {
    if let Some(shape) = input_fact.shape.as_concrete() {
        let volume = shape
            .iter()
            .try_fold(1usize, |volume, dimension| volume.checked_mul(*dimension))
            .ok_or_else(|| AiError::Infer("model input shape volume overflow".to_string()))?;
        if volume != feature_len {
            return Err(AiError::Infer(format!(
                "model input shape {} contains {} elements, but the feature map has {}",
                format_shape(shape),
                volume,
                feature_len
            )));
        }
        return Ok(vec![shape.to_vec()]);
    }

    let mut shapes = Vec::new();
    let mut add_shape = |shape: Vec<usize>| {
        if !shapes.iter().any(|existing| existing == &shape) {
            shapes.push(shape);
        }
    };
    add_shape(vec![feature_len]);
    add_shape(vec![1, feature_len]);
    add_shape(vec![feature_len, 1]);
    add_shape(vec![1, feature_len, 1]);
    add_shape(vec![1, 1, feature_len]);
    add_shape(vec![1, feature_len, 1, 1]);
    add_shape(vec![1, 1, feature_len, 1]);
    add_shape(vec![1, 1, 1, feature_len]);
    add_shape(vec![feature_len, 1, 1, 1]);
    Ok(shapes)
}

fn tensor_from_features(
    features: &[f32],
    shape: &[usize],
    datum_type: DatumType,
) -> Result<Tensor, AiError> {
    let input = tract_onnx::prelude::tract_ndarray::ArrayD::from_shape_vec(
        tract_onnx::prelude::tract_ndarray::IxDyn(shape),
        features.to_vec(),
    )
    .map_err(|error| AiError::Infer(format!("construct input {}: {error}", format_shape(shape))))?;
    let tensor: Tensor = input.into();
    tensor
        .cast_to_dt(datum_type)
        .map(|tensor| tensor.into_owned())
        .map_err(|error| AiError::Infer(format!("convert input to {datum_type:?}: {error}")))
}

fn format_shape(shape: &[usize]) -> String {
    let dimensions = shape
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("[{dimensions}]")
}

fn describe_typed_fact(fact: &TypedFact) -> String {
    format!("dtype={:?}, shape={:?}", fact.datum_type, fact.shape)
}

fn log_model_contract(runnable: &Arc<TypedRunnableModel>, path: &Path) {
    let input = runnable
        .input_fact(0)
        .map(describe_typed_fact)
        .unwrap_or_else(|_| "unavailable".to_string());
    let output = runnable
        .output_fact(0)
        .map(describe_typed_fact)
        .unwrap_or_else(|_| "unavailable".to_string());
    info!(
        "ONNX model contract {}: inputs={}, outputs={}, input0={}, output0={}",
        path.display(),
        runnable.input_count(),
        runnable.output_count(),
        input,
        output
    );
    if runnable.input_count() != 1 {
        warn!(
            "ONNX model {} has multiple inputs; HeliosAV currently supplies one feature tensor",
            path.display()
        );
    }
}

fn feature_cache_key(blob: &[u8], file_size: u64) -> FeatureCacheKey {
    let digest = Sha256::digest(blob);
    let mut sample_sha256 = [0u8; 32];
    sample_sha256.copy_from_slice(&digest);
    FeatureCacheKey {
        sample_sha256,
        file_size,
    }
}

fn feature_map_digest(names: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for name in names {
        hasher.update(name.trim().to_ascii_lowercase().as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

fn extract_named_features(
    blob: &[u8],
    file_size: u64,
    names: &[String],
    base: [f32; 12],
) -> Vec<f32> {
    let mut dll_buckets = HashSet::new();
    let mut api_buckets = HashSet::new();
    let mut section_entropies = Vec::new();
    if let Ok(Object::PE(pe)) = Object::parse(blob) {
        for import in &pe.imports {
            dll_buckets.insert(stable_bucket(import.dll, 256));
            api_buckets.insert(stable_bucket(import.name.as_ref(), 1024));
        }
        for section in &pe.sections {
            let start = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;
            if let Some(end) = start.checked_add(size) {
                if end <= blob.len() && size > 0 {
                    section_entropies.push(crate::layers::heuristic::entropy(&blob[start..end]));
                }
            }
        }
    }

    let string_count = count_printable_strings(blob);
    let byte_histogram = byte_histogram(blob);
    let raw_entropy = crate::layers::heuristic::entropy(blob);
    let max_section_entropy = section_entropies.iter().copied().fold(0.0f32, f32::max);
    let mean_section_entropy = if section_entropies.is_empty() {
        0.0
    } else {
        section_entropies.iter().sum::<f32>() / section_entropies.len() as f32
    };
    let first_section_entropy = section_entropies.first().copied().unwrap_or(0.0);
    let head_entropy = window_entropy(blob, true);
    let tail_entropy = window_entropy(blob, false);
    let normalized_file_size = ((file_size.max(1) as f64 + 1.0).ln()
        / ((128.0_f64 * 1024.0 * 1024.0) + 1.0).ln())
    .clamp(0.0, 1.0) as f32;
    let file_size_log10 = (file_size.max(1) as f64).log10() as f32;
    let normalized_string_count = (string_count as f32 / 64.0).min(1.0);
    let dll_hash_density = dll_buckets.len() as f32 / 256.0;
    let api_hash_density = api_buckets.len() as f32 / 1024.0;
    let hash_density = (dll_buckets.len() as f32 + api_buckets.len() as f32) / 1280.0;
    names
        .iter()
        .map(|name| {
            let normalized = name.trim().to_ascii_lowercase();
            if let Some(index) = canonical_feature_index(&normalized) {
                return base[index];
            }
            if normalized == "entropy" {
                return base[10];
            }
            if normalized == "filesize" {
                return normalized_file_size;
            }
            if normalized == "stringcount" {
                return normalized_string_count;
            }
            if normalized == "entropy_raw" || normalized == "byte_entropy" {
                return raw_entropy;
            }
            if normalized == "file_size_log10" || normalized == "filesize_log10" {
                return file_size_log10;
            }
            if normalized == "file_size_mb" || normalized == "filesize_mb" {
                return file_size as f32 / (1024.0 * 1024.0);
            }
            if normalized == "section_count_raw" {
                return base[1] * 32.0;
            }
            if normalized == "import_count_raw" {
                return base[2] * 256.0;
            }
            if normalized == "max_section_entropy" {
                return max_section_entropy;
            }
            if normalized == "mean_section_entropy" {
                return mean_section_entropy;
            }
            if normalized == "section_entropy_raw" || normalized == "first_section_entropy" {
                return first_section_entropy;
            }
            if normalized == "head_entropy" {
                return head_entropy;
            }
            if normalized == "tail_entropy" || normalized == "pe_overlay_entropy" {
                return tail_entropy;
            }
            if normalized == "derived_entropy_filesize_product" {
                return base[10] * normalized_file_size;
            }
            if normalized == "derived_entropy_stringcount_product" {
                return base[10] * normalized_string_count;
            }
            if normalized == "derived_filesize_stringcount_product" {
                return normalized_file_size * normalized_string_count;
            }
            if normalized == "derived_dll_hash_density" {
                return dll_hash_density;
            }
            if normalized == "derived_api_hash_density" {
                return api_hash_density;
            }
            if normalized == "derived_hash_density" {
                return hash_density;
            }
            if normalized == "derived_entropy_hash_density" {
                return base[10] * hash_density;
            }
            if normalized == "derived_stringcount_hash_density" {
                return normalized_string_count * hash_density;
            }
            if let Some(index) = normalized
                .strip_prefix("bytehist_")
                .or_else(|| normalized.strip_prefix("byte_"))
                .and_then(|value| value.parse::<usize>().ok())
            {
                return byte_histogram.get(index).copied().unwrap_or(0.0);
            }
            if let Some(index) = normalized
                .strip_prefix("dllhash_")
                .and_then(|value| value.parse::<usize>().ok())
            {
                return if dll_buckets.contains(&index) {
                    1.0
                } else {
                    0.0
                };
            }
            if let Some(index) = normalized
                .strip_prefix("apihash_")
                .and_then(|value| value.parse::<usize>().ok())
            {
                return if api_buckets.contains(&index) {
                    1.0
                } else {
                    0.0
                };
            }
            0.0
        })
        .collect()
}

fn byte_histogram(blob: &[u8]) -> [f32; 256] {
    let mut histogram = [0.0f32; 256];
    let denominator = blob.len().max(1) as f32;
    for byte in blob {
        histogram[*byte as usize] += 1.0;
    }
    for value in histogram.iter_mut() {
        *value /= denominator;
    }
    histogram
}

fn window_entropy(blob: &[u8], head: bool) -> f32 {
    const WINDOW: usize = 4096;
    if blob.is_empty() {
        return 0.0;
    }
    let len = blob.len().min(WINDOW);
    if head {
        crate::layers::heuristic::entropy(&blob[..len])
    } else {
        crate::layers::heuristic::entropy(&blob[blob.len() - len..])
    }
}

fn canonical_feature_index(name: &str) -> Option<usize> {
    match name {
        "coverage" => Some(0),
        "section_count" => Some(1),
        "import_count" => Some(2),
        "tls_present" => Some(3),
        "timestamp" | "timestamp_anomaly" => Some(4),
        "section_entropy" => Some(5),
        "printable_ratio" => Some(6),
        "null_ratio" => Some(7),
        "distinct_byte_ratio" => Some(8),
        "mean_byte" => Some(9),
        "entropy_norm" => Some(10),
        "large_flag" => Some(11),
        _ => None,
    }
}

fn stable_bucket(value: &str, bucket_count: usize) -> usize {
    let mut hash = 14_695_981_039_346_656_037u64;
    for byte in value.trim().to_ascii_lowercase().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    (hash as usize) % bucket_count.max(1)
}

fn count_printable_strings(blob: &[u8]) -> usize {
    let mut count = 0;
    let mut run = 0;
    for byte in blob {
        if byte.is_ascii_graphic() || *byte == b' ' {
            run += 1;
        } else {
            if run >= 4 {
                count += 1;
            }
            run = 0;
        }
    }
    if run >= 4 {
        count += 1;
    }
    count
}

fn timestamp_anomaly_score(timestamp: u32) -> f32 {
    if timestamp == 0 {
        return 1.0;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let timestamp = timestamp as u64;
    let thirty_days = 60 * 60 * 24 * 30;
    let twenty_years = 60 * 60 * 24 * 365 * 20;
    if timestamp > now.saturating_add(thirty_days) {
        return 1.0;
    }
    if timestamp < now.saturating_sub(twenty_years) {
        return 0.75;
    }
    0.0
}

fn read_feature_sample(path: &Path, limit: usize) -> Result<(Vec<u8>, u64), AiError> {
    let file_size = std::fs::metadata(path)?.len();
    let mut file = File::open(path)?;
    if file_size <= limit as u64 {
        let mut sample = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut sample)?;
        return Ok((sample, file_size));
    }

    let half = limit / 2;
    let mut head = vec![0u8; half];
    let head_read = file.read(&mut head)?;
    head.truncate(head_read);
    file.seek(SeekFrom::End(-(half as i64)))?;
    let mut tail = vec![0u8; half];
    let tail_read = file.read(&mut tail)?;
    tail.truncate(tail_read);
    head.extend(tail);
    Ok((head, file_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    #[test]
    fn test_extract_features_quick() {
        let data = b"hello world".to_vec();
        let f = AiModel::extract_features(&data);
        assert_eq!(f.len(), 12);
        assert!(f.iter().all(|value| (0.0..=1.0).contains(value)));
    }

    #[test]
    fn test_score_tensor_supports_binary_logits() {
        let tensor: Tensor = tract_onnx::prelude::tract_ndarray::arr1(&[0.0f32, 2.0]).into();
        let score = AiModel::score_tensor(&tensor).expect("decode logits");
        assert!(score > 0.85 && score < 0.90, "score={score}");
    }

    #[test]
    fn test_score_tensor_accepts_non_f32_and_multiclass_outputs() {
        let probability: Tensor = tract_onnx::prelude::tract_ndarray::arr1(&[0.25f64]).into();
        let probability_score = AiModel::score_tensor(&probability).expect("decode f64");
        assert!((probability_score - 0.25).abs() < f32::EPSILON);

        let logits: Tensor = tract_onnx::prelude::tract_ndarray::arr1(&[0.0f32, 1.0, 3.0]).into();
        let score = AiModel::score_tensor_with_contract(&logits, Some(2), OutputKind::Logit)
            .expect("decode multiclass logits");
        assert!(score > 0.8, "score={score}");
    }

    #[test]
    fn test_model_input_shape_and_dtype_adaptation() {
        let fact = TypedFact::dt_shape(DatumType::F32, [1usize, 12]);
        assert_eq!(
            input_shape_candidates(&fact, 12).expect("static shape"),
            vec![vec![1, 12]]
        );

        let tensor = tensor_from_features(&[0.25, 0.75], &[1, 2], DatumType::F64)
            .expect("convert f32 features to f64");
        assert_eq!(tensor.datum_type(), DatumType::F64);
        assert_eq!(tensor.len(), 2);
    }

    #[test]
    fn test_model_contract_sidecar_selects_output_metadata() {
        let directory = tempdir().expect("temporary directory");
        let model_path = directory.path().join("third_party.onnx");
        let contract_path = directory.path().join("model_contract.json");
        let mut contract = File::create(contract_path).expect("create contract");
        writeln!(
            contract,
            "{{\"output_index\":1,\"malicious_index\":2,\"output_kind\":\"logit\"}}"
        )
        .expect("write contract");

        let model = AiModel {
            model_path: Arc::new(RwLock::new(model_path)),
            kind: AiModelKind::CNN,
            fallback: None,
            ensemble: Arc::new(RwLock::new(false)),
            runnable: ArcSwapOption::empty(),
            blend_primary: Arc::new(RwLock::new(0.7)),
            feature_map: Arc::new(RwLock::new(None)),
            model_contract: Arc::new(RwLock::new(ModelContract::default())),
            additional_models: Arc::new(RwLock::new(Vec::new())),
            aggregation: Arc::new(RwLock::new(EnsembleStrategy::default())),
        };
        model
            .load_model_contract_from_path(directory.path().join("third_party.onnx"))
            .expect("load contract");
        let contract = model.model_contract.read().expect("contract lock").clone();
        assert_eq!(contract.output_index, Some(1));
        assert_eq!(contract.malicious_index, Some(2));
        assert_eq!(contract.output_kind, OutputKind::Logit);
    }

    #[test]
    fn test_named_feature_map_preserves_dataset_features() {
        let model = AiModel {
            model_path: Arc::new(RwLock::new(PathBuf::from("nonexistent.onnx"))),
            kind: AiModelKind::CNN,
            fallback: None,
            ensemble: Arc::new(RwLock::new(false)),
            runnable: ArcSwapOption::empty(),
            blend_primary: Arc::new(RwLock::new(0.7)),
            feature_map: Arc::new(RwLock::new(Some(vec![
                "Entropy".to_string(),
                "FileSize".to_string(),
                "StringCount".to_string(),
            ]))),
            model_contract: Arc::new(RwLock::new(ModelContract::default())),
            additional_models: Arc::new(RwLock::new(Vec::new())),
            aggregation: Arc::new(RwLock::new(EnsembleStrategy::default())),
        };
        let vector = model.extract_model_features(b"a printable string", 4096);
        assert_eq!(vector.len(), 3);
        assert!(vector.iter().any(|value| *value > 0.0));
    }

    #[test]
    fn test_derived_named_features_match_bounded_runtime_formulas() {
        let mut base = [0.0f32; 12];
        base[10] = 0.5;
        let names = vec![
            "Entropy".to_string(),
            "FileSize".to_string(),
            "StringCount".to_string(),
            "derived_entropy_filesize_product".to_string(),
            "derived_entropy_stringcount_product".to_string(),
            "derived_hash_density".to_string(),
        ];
        let values = extract_named_features(b"a printable string", 4096, &names, base);
        assert_eq!(values.len(), names.len());
        assert!((0.0..=1.0).contains(&values[0]));
        assert!((0.0..=1.0).contains(&values[1]));
        assert!((0.0..=1.0).contains(&values[2]));
        assert!((0.0..=1.0).contains(&values[3]));
        assert!((0.0..=1.0).contains(&values[4]));
        assert_eq!(values[5], 0.0);
        assert!((values[3] - values[0] * values[1]).abs() < f32::EPSILON);
        assert!((values[4] - values[0] * values[2]).abs() < f32::EPSILON);
    }

    #[test]
    fn test_ensemble_aggregation_strategies() {
        let scores = [(0.2f32, 1.0f32), (0.8f32, 3.0f32), (0.6f32, 1.0f32)];
        assert!((aggregate_scores(EnsembleStrategy::WeightedMean, &scores) - 0.64).abs() < 0.001);
        assert_eq!(aggregate_scores(EnsembleStrategy::MaxRisk, &scores), 0.8);
        assert_eq!(
            aggregate_scores(EnsembleStrategy::MajorityVote, &scores),
            1.0
        );
        assert_eq!(
            EnsembleStrategy::parse("max-risk"),
            Some(EnsembleStrategy::MaxRisk)
        );
    }

    #[test]
    fn test_infer_fallback_heuristic() {
        // Create a small temp file and use a model path that doesn't exist so model load fails
        let mut tmp = NamedTempFile::new().expect("tmpfile");
        tmp.write_all(b"hello world").expect("write");
        let path = tmp.path().to_path_buf();

        // create AiModel with invalid model path, but construction tries to load and will error; create instance manually
        let model = AiModel {
            model_path: Arc::new(RwLock::new(PathBuf::from("nonexistent.onnx"))),
            kind: AiModelKind::CNN,
            fallback: None,
            ensemble: Arc::new(RwLock::new(false)),
            runnable: ArcSwapOption::empty(),
            blend_primary: Arc::new(RwLock::new(0.7)),
            feature_map: Arc::new(RwLock::new(None)),
            model_contract: Arc::new(RwLock::new(ModelContract::default())),
            additional_models: Arc::new(RwLock::new(Vec::new())),
            aggregation: Arc::new(RwLock::new(EnsembleStrategy::default())),
        };
        let score = model.infer_path(&path).expect("infer_path");
        assert!(score.score >= 0.0 && score.score <= 1.0);
        assert!(score.is_fallback);
        assert!(score.fallback_reason.is_some());
    }
}
