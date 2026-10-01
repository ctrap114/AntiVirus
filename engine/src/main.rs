#![cfg_attr(windows, windows_subsystem = "windows")]

use std::convert::Infallible;
use sha2::Digest;
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use everbloom_engine::ndjson::{
    run_ndjson, NdjsonCommandCallback, NdjsonResultCallback, NdjsonRuntime,
};
use everbloom_engine::{
    ai_inference_error_count, AiModel, AiModelKind, Allowlist, BehavioralScorer, EnsembleStrategy,
    HashMatcher, IpcServer, ScanCache, Scanner, SequenceMatcher, ThreatIntelMatcher, YaraScanner,
};
use hyper::body::HttpBody;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

#[cfg(windows)]
const DEFAULT_ENDPOINT: &str = r"\\.\pipe\everbloom_engine";
#[cfg(not(windows))]
const DEFAULT_ENDPOINT: &str = "/tmp/everbloom_engine.sock";

type ReloadCallback = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;
type HashImportCallback = Arc<dyn Fn(String) -> Result<String, String> + Send + Sync>;
type ModelCommandCallback = Arc<dyn Fn(String) -> Result<String, String> + Send + Sync>;

const MAX_ADMIN_BODY_SIZE: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminConfigPayload {
    ensemble: Option<bool>,
    blend_primary: Option<f32>,
    strategy: Option<String>,
}

#[derive(Serialize)]
struct AdminStatus {
    ensemble: bool,
    blend_primary: f32,
    model_kind: String,
    model_path: String,
    feature_map: Option<Vec<String>>,
    strategy: String,
    models: Vec<everbloom_engine::AiModelInfo>,
    ai_inference_errors: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminModelImportPayload {
    source_path: String,
    id: Option<String>,
    kind: Option<String>,
    weight: Option<f32>,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminModelConvertPayload {
    source_path: String,
    id: Option<String>,
    kind: Option<String>,
    features_path: Option<String>,
    target_opset: Option<u32>,
    output_index: Option<usize>,
    malicious_index: Option<usize>,
    output_kind: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminModelValidatePayload {
    source_path: String,
    kind: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminModelIdPayload {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminModelUpdatePayload {
    id: String,
    weight: Option<f32>,
    enabled: Option<bool>,
}

async fn handle_admin_request(
    req: Request<Body>,
    model: Arc<everbloom_engine::layers::ai::AiModel>,
    admin_token: Arc<String>,
    model_root: Arc<PathBuf>,
    cache: Arc<ScanCache>,
) -> Result<Response<Body>, Infallible> {
    if !authorized(&req, admin_token.as_str()) {
        return Ok(response_with_status(
            StatusCode::UNAUTHORIZED,
            "missing or invalid admin token",
        ));
    }

    let path = req.uri().path();
    match (req.method(), path) {
        (&Method::GET, "/admin/ai") => {
            let body = serde_json::to_string(&AdminStatus {
                ensemble: model.get_ensemble(),
                blend_primary: model.get_blend_primary(),
                model_kind: format!("{:?}", model.model_kind()),
                model_path: model.model_path().to_string_lossy().to_string(),
                feature_map: model.feature_map(),
                strategy: model.aggregation_strategy().as_str().to_string(),
                models: model.model_registry(),
                ai_inference_errors: ai_inference_error_count(),
            })
            .unwrap_or_else(|_| "{}".to_string());
            Ok(Response::new(Body::from(body)))
        }
        (&Method::GET, "/admin/ai/models") => {
            let body = serde_json::json!({
                "strategy": model.aggregation_strategy().as_str(),
                "models": model.model_registry(),
                "ai_inference_errors": ai_inference_error_count(),
            });
            Ok(Response::new(Body::from(body.to_string())))
        }
        (&Method::POST, "/admin/ai/models/validate") => {
            let whole = match read_limited_body(req.into_body()).await {
                Ok(body) => body,
                Err(response) => return Ok(response),
            };
            let payload = match serde_json::from_slice::<AdminModelValidatePayload>(&whole) {
                Ok(payload) => payload,
                Err(error) => {
                    return Ok(response_with_status(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid JSON: {error}"),
                    ))
                }
            };
            let kind = parse_admin_model_kind(payload.kind.as_deref()).unwrap_or(AiModelKind::CNN);
            let report =
                everbloom_engine::AiModel::validate_model_for_scanner(&payload.source_path, kind);
            Ok(Response::new(Body::from(
                serde_json::json!({
                    "success": true,
                    "validation": report,
                })
                .to_string(),
            )))
        }
        (&Method::POST, "/admin/ai") => {
            let whole = match read_limited_body(req.into_body()).await {
                Ok(body) => body,
                Err(response) => return Ok(response),
            };
            match serde_json::from_slice::<AdminConfigPayload>(&whole) {
                Ok(payload) => {
                    if payload
                        .blend_primary
                        .is_some_and(|value| !value.is_finite())
                    {
                        return Ok(response_with_status(
                            StatusCode::BAD_REQUEST,
                            "blend_primary must be a finite number",
                        ));
                    }
                    let mut summary_parts = Vec::new();
                    if let Some(ensemble) = payload.ensemble {
                        model.set_ensemble(ensemble);
                        summary_parts.push(format!("ensemble={}", ensemble));
                    }
                    if let Some(weight) = payload.blend_primary {
                        model.set_blend_primary(weight);
                        summary_parts
                            .push(format!("blend_primary={:.3}", model.get_blend_primary()));
                    }
                    if let Some(strategy) = payload.strategy {
                        let Some(strategy) = EnsembleStrategy::parse(&strategy) else {
                            return Ok(response_with_status(
                                StatusCode::BAD_REQUEST,
                                "unsupported ensemble strategy",
                            ));
                        };
                        model.set_aggregation_strategy(strategy);
                        summary_parts.push(format!("strategy={}", strategy.as_str()));
                    }
                    if !summary_parts.is_empty() {
                        cache.invalidate_decisions();
                    }
                    let status = serde_json::json!({
                        "updated": summary_parts,
                        "current": {
                            "ensemble": model.get_ensemble(),
                            "blend_primary": model.get_blend_primary(),
                            "strategy": model.aggregation_strategy().as_str(),
                        }
                    });
                    Ok(Response::new(Body::from(status.to_string())))
                }
                Err(err) => {
                    let mut resp = Response::new(Body::from(format!("Invalid JSON: {}", err)));
                    *resp.status_mut() = StatusCode::BAD_REQUEST;
                    Ok(resp)
                }
            }
        }
        (&Method::POST, "/admin/ai/models/import") => {
            let whole = match read_limited_body(req.into_body()).await {
                Ok(body) => body,
                Err(response) => return Ok(response),
            };
            let payload = match serde_json::from_slice::<AdminModelImportPayload>(&whole) {
                Ok(payload) => payload,
                Err(error) => {
                    return Ok(response_with_status(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid JSON: {error}"),
                    ))
                }
            };
            let kind = parse_admin_model_kind(payload.kind.as_deref()).unwrap_or(AiModelKind::CNN);
            let result = model
                .import_model(
                    &payload.source_path,
                    model_root.as_ref(),
                    payload.id.as_deref(),
                    kind,
                    payload.weight.unwrap_or(1.0),
                    payload.enabled.unwrap_or(true),
                )
                .and_then(|info| {
                    model
                        .persist_model_registry(model_root.join("models.json"))
                        .map(|_| info)
                });
            match result {
                Ok(info) => {
                    cache.invalidate_context();
                    Ok(Response::new(Body::from(
                        serde_json::json!({"success": true, "model": info}).to_string(),
                    )))
                }
                Err(error) => Ok(response_with_status(
                    StatusCode::BAD_REQUEST,
                    &error.to_string(),
                )),
            }
        }
        (&Method::POST, "/admin/ai/models/convert") => {
            let whole = match read_limited_body(req.into_body()).await {
                Ok(body) => body,
                Err(response) => return Ok(response),
            };
            let payload = match serde_json::from_slice::<AdminModelConvertPayload>(&whole) {
                Ok(payload) => payload,
                Err(error) => {
                    return Ok(response_with_status(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid JSON: {error}"),
                    ))
                }
            };
            let kind = parse_admin_model_kind(payload.kind.as_deref()).unwrap_or(AiModelKind::CNN);
            let options = everbloom_engine::ModelConversionOptions {
                source_path: PathBuf::from(payload.source_path),
                model_root: model_root.as_ref().clone(),
                id: payload.id,
                kind,
                features_json: payload.features_path.map(PathBuf::from),
                target_opset: payload.target_opset.or(Some(12)),
                output_index: payload.output_index.unwrap_or(0),
                malicious_index: payload.malicious_index.unwrap_or(1),
                output_kind: payload.output_kind.unwrap_or_else(|| "auto".to_string()),
            };
            match everbloom_engine::model_converter::convert_and_import_model(&model, &options)
                .and_then(|report| {
                    model
                        .persist_model_registry(model_root.join("models.json"))
                        .map_err(everbloom_engine::ModelConversionError::from)
                        .map(|_| report)
                }) {
                Ok(report) => {
                    cache.invalidate_context();
                    Ok(Response::new(Body::from(
                        serde_json::json!({"success": true, "conversion": report}).to_string(),
                    )))
                }
                Err(error) => Ok(response_with_status(
                    StatusCode::BAD_REQUEST,
                    &error.to_string(),
                )),
            }
        }
        (&Method::POST, "/admin/ai/models/update") => {
            let whole = match read_limited_body(req.into_body()).await {
                Ok(body) => body,
                Err(response) => return Ok(response),
            };
            let payload = match serde_json::from_slice::<AdminModelUpdatePayload>(&whole) {
                Ok(payload) => payload,
                Err(error) => {
                    return Ok(response_with_status(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid JSON: {error}"),
                    ))
                }
            };
            match model.update_model(&payload.id, payload.weight, payload.enabled) {
                Ok(true) => match model.persist_model_registry(model_root.join("models.json")) {
                    Ok(()) => {
                        cache.invalidate_context();
                        Ok(Response::new(Body::from(
                            serde_json::json!({"success": true, "models": model.model_registry()})
                                .to_string(),
                        )))
                    }
                    Err(error) => Ok(response_with_status(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &error.to_string(),
                    )),
                },
                Ok(false) => Ok(response_with_status(
                    StatusCode::NOT_FOUND,
                    "model id was not found",
                )),
                Err(error) => Ok(response_with_status(
                    StatusCode::BAD_REQUEST,
                    &error.to_string(),
                )),
            }
        }
        (&Method::POST, "/admin/ai/models/remove") => {
            let whole = match read_limited_body(req.into_body()).await {
                Ok(body) => body,
                Err(response) => return Ok(response),
            };
            let payload = match serde_json::from_slice::<AdminModelIdPayload>(&whole) {
                Ok(payload) => payload,
                Err(error) => {
                    return Ok(response_with_status(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid JSON: {error}"),
                    ))
                }
            };
            match model.remove_model(&payload.id) {
                Ok(true) => match model.persist_model_registry(model_root.join("models.json")) {
                    Ok(()) => {
                        cache.invalidate_context();
                        Ok(Response::new(Body::from(
                            serde_json::json!({"success": true, "models": model.model_registry()})
                                .to_string(),
                        )))
                    }
                    Err(error) => Ok(response_with_status(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &error.to_string(),
                    )),
                },
                Ok(false) => Ok(response_with_status(
                    StatusCode::NOT_FOUND,
                    "model id was not found",
                )),
                Err(error) => Ok(response_with_status(
                    StatusCode::BAD_REQUEST,
                    &error.to_string(),
                )),
            }
        }
        (&Method::POST, "/admin/ai/reload-model") => {
            let whole = match read_limited_body(req.into_body()).await {
                Ok(body) => body,
                Err(response) => return Ok(response),
            };
            match serde_json::from_slice::<serde_json::Value>(&whole) {
                Ok(v) => {
                    if let Some(mp) = v.get("model_path").and_then(|s| s.as_str()) {
                        let requested_path = match validate_model_path(mp, model_root.as_ref()) {
                            Ok(path) => path,
                            Err(error) => {
                                return Ok(response_with_status(StatusCode::BAD_REQUEST, &error));
                            }
                        };
                        let result = model.load_model_from_path(&requested_path);
                        match result {
                            Ok(_) => {
                                let mut resp = Response::new(Body::from(format!(
                                    "model reload ok: {}",
                                    requested_path.display()
                                )));
                                *resp.status_mut() = StatusCode::OK;
                                Ok(resp)
                            }
                            Err(e) => {
                                let mut resp =
                                    Response::new(Body::from(format!("model reload error: {}", e)));
                                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                Ok(resp)
                            }
                        }
                    } else {
                        let mut resp = Response::new(Body::from("missing model_path"));
                        *resp.status_mut() = StatusCode::BAD_REQUEST;
                        Ok(resp)
                    }
                }
                Err(err) => {
                    let mut resp = Response::new(Body::from(format!("Invalid JSON: {}", err)));
                    *resp.status_mut() = StatusCode::BAD_REQUEST;
                    Ok(resp)
                }
            }
        }
        _ => {
            let mut resp = Response::new(Body::from("Not Found"));
            *resp.status_mut() = StatusCode::NOT_FOUND;
            Ok(resp)
        }
    }
}

fn authorized(req: &Request<Body>, expected_token: &str) -> bool {
    let bearer = req
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let header_token = req
        .headers()
        .get("x-everbloom-admin-token")
        .and_then(|value| value.to_str().ok());
    bearer == Some(expected_token) || header_token == Some(expected_token)
}

async fn read_limited_body(mut body: Body) -> Result<Vec<u8>, Response<Body>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                return Err(response_with_status(
                    StatusCode::BAD_REQUEST,
                    &format!("unable to read request body: {error}"),
                ));
            }
        };
        if bytes.len().saturating_add(chunk.len()) > MAX_ADMIN_BODY_SIZE {
            return Err(response_with_status(
                StatusCode::PAYLOAD_TOO_LARGE,
                "admin request body is too large",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn response_with_status(status: StatusCode, body: &str) -> Response<Body> {
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = status;
    response
}

fn validate_model_path(raw_path: &str, model_root: &std::path::Path) -> Result<PathBuf, String> {
    let path = std::path::Path::new(raw_path);
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("model path is not accessible: {error}"))?;
    if !canonical.is_file() {
        return Err("model path must be a regular file".to_string());
    }
    if canonical
        .extension()
        .and_then(|value| value.to_str())
        .map(|extension| !extension.eq_ignore_ascii_case("onnx"))
        .unwrap_or(true)
    {
        return Err("only .onnx model files may be loaded".to_string());
    }
    let root = model_root
        .canonicalize()
        .map_err(|error| format!("model root is not accessible: {error}"))?;
    if !canonical.starts_with(&root) {
        return Err("model path is outside the configured model directory".to_string());
    }
    Ok(canonical)
}

fn parse_admin_model_kind(value: Option<&str>) -> Option<AiModelKind> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "transformer" | "tf" => Some(AiModelKind::Transformer),
        "cnn" | "mlp" | "classifier" => Some(AiModelKind::CNN),
        _ => None,
    }
}

fn validate_hash_database_path(raw_path: &str) -> Result<PathBuf, String> {
    let raw_path = raw_path.trim();
    if raw_path.is_empty() {
        return Err("hash database path is empty".to_string());
    }
    let path = Path::new(raw_path)
        .canonicalize()
        .map_err(|error| format!("hash database is not accessible: {error}"))?;
    if !path.is_file() {
        return Err("hash database must be a regular file".to_string());
    }
    const MAX_IMPORT_SIZE: u64 = 512 * 1024 * 1024;
    let size = std::fs::metadata(&path)
        .map_err(|error| format!("unable to inspect hash database: {error}"))?
        .len();
    if size > MAX_IMPORT_SIZE {
        return Err(format!(
            "hash database is too large ({} bytes, limit {} bytes)",
            size, MAX_IMPORT_SIZE
        ));
    }
    Ok(path)
}

fn persist_imported_hash_database(path: &Path) -> Result<PathBuf, String> {
    let import_dir = std::env::var_os("EVERBLOOM_HASH_IMPORT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data/imported_hashes"));
    std::fs::create_dir_all(&import_dir)
        .map_err(|error| format!("unable to create hash import directory: {error}"))?;

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "hash database has no usable file name".to_string())?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(path, &mut hasher);
    let source_tag = format!("{:016x}", std::hash::Hasher::finish(&hasher));
    let destination = import_dir.join(format!("{source_tag}-{file_name}"));
    if path != destination {
        std::fs::copy(path, &destination)
            .map_err(|error| format!("unable to store imported hash database: {error}"))?;
    }
    Ok(destination)
}

fn append_imported_hash_paths(paths: &mut Vec<PathBuf>) {
    let import_dir = std::env::var_os("EVERBLOOM_HASH_IMPORT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data/imported_hashes"));
    let Ok(entries) = std::fs::read_dir(import_dir) else {
        return;
    };
    paths.extend(
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file()),
    );
}

fn build_scanner() -> (
    Scanner,
    Option<ReloadCallback>,
    Option<Arc<everbloom_engine::layers::ai::AiModel>>,
    Option<HashImportCallback>,
) {
    if everbloom_engine::protection_state::driver_enabled() {
        if let Err(error) = everbloom_engine::apply_configured_protection_rules() {
            log::warn!("failed to load configured protection rules: {}", error);
        }
    } else {
        log::info!("configured protection rules skipped: driver layer is disabled or unavailable");
    }
    let cache = Arc::new(ScanCache::new(
        std::env::var("EVERBLOOM_SCAN_CACHE_SIZE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4096),
    ));
    let mut scanner = Scanner::new()
        .with_cache(cache.clone())
        .with_behavioral(Arc::new(BehavioralScorer::default()))
        .with_sequence(Arc::new(SequenceMatcher::default()))
        .with_default_fusion();
    log::info!("production ProtectionFusion attached (response_level=normal)");
    // The resident clamd client is attached whenever the engine starts. It
    // only performs network work for scans when EVERBLOOM_CLAMAV (or a
    // per-request scan option) enables the layer, and its retry cooldown
    // keeps batch scans fast while clamd is unavailable.
    let clamav_client = Arc::new(everbloom_engine::layers::clamav::ClamAvClient::from_environment());
    let clamav_status = clamav_client.probe();
    log::info!(
        "clamav layer endpoint={} available={} {}",
        clamav_client.endpoint(),
        clamav_status.available,
        clamav_status.message
    );
    scanner = scanner.with_clamav(clamav_client);
    match Allowlist::load_from_environment() {
        Ok(allowlist) => {
            log::info!(
                "allowlist enabled={} builtin_system_processes={}",
                allowlist.is_enabled(),
                allowlist.builtin_system_processes_enabled()
            );
            scanner = scanner.with_allowlist(Arc::new(allowlist));
        }
        Err(error) => log::warn!("allowlist was not loaded: {}", error),
    }
    let rules_path = std::env::var_os("EVERBLOOM_RULES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data/rules"));
    if rules_path.is_dir() {
        if let Ok(yara) = YaraScanner::new(&rules_path) {
            scanner = scanner.with_yara(Arc::new(yara));
        }
    }

    let model_kind = std::env::var("EVERBLOOM_AI_MODEL_KIND")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .map(|kind| match kind.as_str() {
            "transformer" | "tf" => everbloom_engine::layers::ai::AiModelKind::Transformer,
            _ => everbloom_engine::layers::ai::AiModelKind::CNN,
        })
        .unwrap_or(everbloom_engine::layers::ai::AiModelKind::CNN);
    let primary_path = std::env::var_os("EVERBLOOM_AI_MODEL")
        .map(PathBuf::from)
        .unwrap_or_else(|| model_kind.default_model_path());
    let fallback_kind = match model_kind {
        everbloom_engine::layers::ai::AiModelKind::CNN => {
            everbloom_engine::layers::ai::AiModelKind::Transformer
        }
        everbloom_engine::layers::ai::AiModelKind::Transformer => {
            everbloom_engine::layers::ai::AiModelKind::CNN
        }
    };
    let fallback_path = std::env::var_os("EVERBLOOM_AI_FALLBACK_MODEL")
        .map(PathBuf::from)
        .unwrap_or_else(|| fallback_kind.default_model_path());
    let ensemble = std::env::var("EVERBLOOM_AI_ENSEMBLE")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true);

    let mut candidates = Vec::new();
    let mut add_candidate = |path: PathBuf, kind: everbloom_engine::layers::ai::AiModelKind| {
        if !candidates
            .iter()
            .any(|(existing_path, existing_kind)| existing_path == &path && *existing_kind == kind)
        {
            candidates.push((path, kind));
        }
    };
    add_candidate(primary_path.clone(), model_kind);
    add_candidate(fallback_path.clone(), fallback_kind);
    add_candidate(model_kind.default_model_path(), model_kind);
    add_candidate(fallback_kind.default_model_path(), fallback_kind);
    let mut model = None;
    for (candidate_path, candidate_kind) in candidates {
        if !candidate_path.is_file() {
            continue;
        }
        match AiModel::new_with_kind(&candidate_path, candidate_kind) {
            Ok(loaded) => {
                model = Some(loaded);
                break;
            }
            Err(error) => log::warn!(
                "unable to load AI model {}: {}",
                candidate_path.display(),
                error
            ),
        }
    }

    let model_root = std::env::var_os("EVERBLOOM_AI_MODEL_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            primary_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let model_registry_path = std::env::var_os("EVERBLOOM_AI_MODELS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| model_root.join("models.json"));

    let model_arc = model.map(|mut model| {
        // Attach fallback model in-place to avoid moving the primary model.
        if fallback_path.is_file() && fallback_path != model.model_path() {
            if let Ok(fallback) = AiModel::new_with_kind(&fallback_path, fallback_kind) {
                model.attach_fallback_model(fallback);
            }
        }
        if model_registry_path.is_file() {
            match model.load_model_registry_from_file(&model_registry_path, &model_root) {
                Ok(report) => log::info!(
                    "loaded user AI model registry: loaded={} skipped={} strategy={}",
                    report.loaded,
                    report.skipped.len(),
                    report.strategy
                ),
                Err(error) => log::warn!(
                    "unable to load user AI model registry {}: {}",
                    model_registry_path.display(),
                    error
                ),
            }
        }
        Arc::new(model.with_ensemble(ensemble))
    });
    if let Some(model_arc) = &model_arc {
        scanner = scanner.with_ai(model_arc.clone());
    } else {
        log::warn!("no usable AI model was found; AI layer disabled");
    }
    let db_paths = std::env::var_os("EVERBLOOM_HASH_DB")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_else(|| {
            vec![
                PathBuf::from("data/local_hashes.sqlite"),
                PathBuf::from("data/HashDB.db"),
                PathBuf::from("hashdb/HashDB.db"),
                PathBuf::from("data/local_hashes.csv"),
                PathBuf::from("data/local_hashes.json"),
                PathBuf::from("data/local_hashes.jsonl"),
                PathBuf::from("data/local_hashes.txt"),
                PathBuf::from("data/local_hashes.dat"),
            ]
        });
    let mut db_paths = db_paths;
    append_imported_hash_paths(&mut db_paths);

    let threat_db_paths = std::env::var_os("EVERBLOOM_THREAT_INTEL_DB")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_else(|| db_paths.clone());
    let mut threat_intel_path = None;
    let mut threat_intel_matcher = None;
    for db_path in threat_db_paths
        .iter()
        .filter(|path| path.is_file() && is_sqlite_hash_database(path))
    {
        let matcher = Arc::new(ThreatIntelMatcher::with_default_confidence());
        match matcher.load_from_sqlite_db(db_path) {
            Ok(count) if count > 0 => {
                log::info!(
                    "loaded {} active network IOCs from {}",
                    count,
                    db_path.display()
                );
                scanner = scanner.with_threat_intel(matcher.clone());
                threat_intel_path = Some(db_path.clone());
                threat_intel_matcher = Some(matcher);
                break;
            }
            Ok(_) => {}
            Err(error) => log::warn!(
                "unable to load threat intelligence from {}: {}",
                db_path.display(),
                error
            ),
        }
    }

    if everbloom_engine::public_feeds::public_feeds_enabled() {
        let matcher = if let Some(matcher) = threat_intel_matcher.clone() {
            matcher
        } else {
            let matcher = Arc::new(ThreatIntelMatcher::with_default_confidence());
            scanner = scanner.with_threat_intel(matcher.clone());
            threat_intel_matcher = Some(matcher.clone());
            matcher
        };
        let public_db_path = everbloom_engine::public_feeds::default_cache_path();
        match everbloom_engine::public_feeds::load_cached(&matcher, &public_db_path) {
            Ok(count) if count > 0 => log::info!(
                "loaded {} cached public threat-intel records from {}",
                count,
                public_db_path.display()
            ),
            Ok(_) => {}
            Err(error) => log::warn!(
                "unable to load cached public threat intelligence from {}: {}",
                public_db_path.display(),
                error
            ),
        }
        let interval = everbloom_engine::public_feeds::update_interval();
        if let Err(error) =
            everbloom_engine::public_feeds::spawn_updater(matcher, public_db_path, interval)
        {
            log::warn!("unable to start public threat-intel updater: {}", error);
        }
    } else {
        log::info!("public threat-intel feeds disabled by EVERBLOOM_THREAT_INTEL_PUBLIC_FEEDS");
    }

    let hash_paths = db_paths
        .into_iter()
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    let matcher = Arc::new(HashMatcher::new_with_label(None, "local_db".to_string()));
    let mut loaded_hash_paths = Vec::new();
    let mut loaded_hash_count = 0usize;
    for db_path in &hash_paths {
        match matcher.load_from_file(db_path) {
            Ok(count) if count > 0 => {
                loaded_hash_count += count;
                loaded_hash_paths.push(db_path.clone());
                log::info!(
                    "loaded {} hash records from {} (merged total records={})",
                    count,
                    db_path.display(),
                    loaded_hash_count
                );
            }
            Ok(_) => {}
            Err(error) => log::warn!(
                "unable to load hash database {}: {}",
                db_path.display(),
                error
            ),
        }
    }
    let has_loaded_hash_paths = !loaded_hash_paths.is_empty();
    scanner = scanner.with_hash(matcher.clone());
    let tracked_hash_paths = Arc::new(Mutex::new(loaded_hash_paths));
    let import_matcher = matcher.clone();
    let import_cache = cache.clone();
    let import_paths = tracked_hash_paths.clone();
    let hash_import: HashImportCallback = Arc::new(move |command: String| {
        let raw_path = command
            .strip_prefix("import_hash_database:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "invalid hash database import command".to_string())?;
        let path = validate_hash_database_path(raw_path)?;
        let stored_path = match persist_imported_hash_database(&path) {
            Ok(path) => path,
            Err(error) => {
                log::warn!("hash database persistence unavailable: {}", error);
                path.clone()
            }
        };
        let count = import_matcher
            .load_from_file(&stored_path)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("hash database contains no valid entries".to_string());
        }
        {
            let mut paths = import_paths
                .lock()
                .map_err(|_| "hash database import path state is unavailable".to_string())?;
            if !paths.iter().any(|item| item == &stored_path) {
                paths.push(stored_path.clone());
            }
        }
        import_cache.invalidate_context();
        Ok(format!(
            "hash database imported: {} ({} records)",
            stored_path.display(),
            count
        ))
    });
    if has_loaded_hash_paths {
        let reload_paths = tracked_hash_paths.clone();
        let reload_matcher = matcher.clone();
        let reload_threat_path = threat_intel_path.clone();
        let reload_threat_matcher = threat_intel_matcher.clone();
        let reload_cache = cache.clone();
        let callback: ReloadCallback = Arc::new(move || {
            let mut replaced = false;
            let mut total = 0usize;
            let paths = reload_paths
                .lock()
                .map_err(|_| "hash database path state is unavailable".to_string())?
                .clone();
            for path in &paths {
                if !path.is_file() {
                    continue;
                }
                if !replaced {
                    match reload_matcher.replace_from_file(path) {
                        Ok(count) if count > 0 => {
                            total += count;
                            replaced = true;
                        }
                        Ok(_) | Err(_) => continue,
                    }
                } else {
                    total += reload_matcher
                        .load_from_file(path)
                        .map_err(|error| error.to_string())?;
                }
            }
            if !replaced || total == 0 {
                return Err("replacement hash databases contain no valid entries".to_string());
            }
            if let (Some(path), Some(threat_matcher)) =
                (reload_threat_path.as_ref(), reload_threat_matcher.as_ref())
            {
                threat_matcher
                    .replace_from_sqlite_db(path)
                    .map_err(|error| error.to_string())?;
            }
            reload_cache.clear();
            Ok(())
        });
        return (
            scanner,
            Some(callback),
            model_arc.clone(),
            Some(hash_import),
        );
    }

    (scanner, None, model_arc, Some(hash_import))
}

fn configured_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn is_sqlite_hash_database(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "sqlite" | "sqlite3" | "db"
            )
        })
}

fn use_ndjson_transport() -> bool {
    let command_line = std::env::args().skip(1).collect::<Vec<_>>();
    if command_line
        .iter()
        .any(|value| matches!(value.as_str(), "--ndjson" | "--stdio"))
    {
        return true;
    }
    if command_line
        .iter()
        .any(|value| matches!(value.as_str(), "--legacy-ipc" | "--socket"))
    {
        return false;
    }

    match std::env::var("EVERBLOOM_ENGINE_TRANSPORT")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "ndjson" | "stdio" => true,
        "ipc" | "socket" | "legacy" => false,
        _ => std::env::var_os("EVERBLOOM_IPC_ENDPOINT").is_none(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    everbloom_engine::logging::initialize();
    everbloom_engine::logging::install_panic_hook();

    // Engine binary integrity self-check: compute SHA-256 of this binary
    // (resolved from std::env::current_exe()) and compare against an embedded
    // manifest hash. If the binary has been tampered with (e.g., patched,
    // replaced by malware), exit with a clear error so no malicious engine
    // instance can proceed.
    if let Ok(manifest_path) = std::env::var("EVERBLOOM_BINARY_INTEGRITY_MANIFEST") {
        if std::path::Path::new(&manifest_path).is_file() {
            let binary_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
            if binary_path.is_file() {
                use std::io::Read;
                let mut file = std::fs::File::open(&binary_path).map_err(|e| {
                    format!("failed to open engine binary for integrity check: {}", e)
                })?;
                let mut hasher = sha2::Sha256::new();
                let mut buffer = [0u8; 65536];
                loop {
                    let bytes_read = file.read(&mut buffer).map_err(|e| {
                        format!("failed to read engine binary: {}", e)
                    })?;
                    if bytes_read == 0 { break; }
                    hasher.update(&buffer[..bytes_read]);
                }
                let binary_hash_hex = format!("{:x}", hasher.finalize());
                let manifest_content = std::fs::read_to_string(&manifest_path).map_err(|e| {
                    format!("failed to read integrity manifest {}: {}", manifest_path, e)
                })?;
                for line in manifest_content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue; }
                    let parts: Vec<&str> = line.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        let expected_hash = parts[1].trim();
                        let binary_name = binary_path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown_binary");
                        if parts[0].trim() == binary_name {
                            if binary_hash_hex != expected_hash {
                                log::error!("ENGINE INTEGRITY CHECK FAILED: binary {} expected hash {} but computed {}", binary_name, expected_hash, binary_hash_hex);
                                return Err(format!("engine binary integrity mismatch: {} (expected {})", binary_path.display(), expected_hash).into());
                            } else {
                                log::info!("engine binary integrity verified: {} -> {}", binary_name, binary_hash_hex);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    // Out-of-band driver diagnostic. Probes the kernel control device, prints
    // the negotiated capability set and exits without starting the IPC server
    // or any protection worker. This exists so the driver can be verified at
    // runtime on a test machine with a single command, instead of having to
    // read the capability negotiation out of engine startup logs. It is the
    // only supported way to answer "is the kernel enforcement actually live".
    //
    // This binary is linked as a GUI-subsystem executable, so PowerShell does
    // not wait for it and never observes its exit code, and println! goes to a
    // console that may not exist. Callers that need the verdict therefore pass
    // --driver-status-report <path> and read the file instead of the exit code.
    let cli_all: Vec<String> = std::env::args().skip(1).collect();
    if cli_all.iter().any(|arg| arg == "--driver-status") {
        let report_path = cli_all
            .iter()
            .position(|arg| arg == "--driver-status-report")
            .and_then(|index| cli_all.get(index + 1))
            .cloned();

        let bridge = everbloom_engine::driver_bridge::DriverBridge::new();
        let (lines, exit_code) = match bridge.probe_capabilities() {
            Ok(capabilities) => {
                let compatible = capabilities.is_compatible();
                let mut lines = vec![
                    "device: present".to_string(),
                    format!("compatible: {}", compatible),
                    format!("capability_flags: 0x{:x}", capabilities.capability_flags),
                    format!("kernel_model: {}", capabilities.has_kernel_model()),
                    format!("protocol_version: {}", capabilities.protocol_version),
                    format!("policy_version: {}", capabilities.policy_version),
                    format!(
                        "protection_protocol_version: {}",
                        capabilities.protection_protocol_version
                    ),
                    format!("event_version: {}", capabilities.event_version),
                    format!("max_target_chars: {}", capabilities.max_target_chars),
                    format!("max_payload_bytes: {}", capabilities.max_payload_bytes),
                    format!("max_event_batch: {}", capabilities.max_event_batch),
                    format!("summary: {}", capabilities.summary()),
                ];
                if !compatible {
                    lines.push(
                        "error: driver is running but its protocol is incompatible with this engine"
                            .to_string(),
                    );
                }
                (lines, if compatible { 0 } else { 4 })
            }
            Err(error) => (
                vec![
                    "device: absent".to_string(),
                    format!("reason: {}", error),
                    "hint: \\\\.\\EverbloomSecurity only exists once the driver is installed, signed and running; see driver/package/README.md".to_string(),
                ],
                3,
            ),
        };

        for line in &lines {
            println!("{}", line);
        }
        if let Some(path) = report_path {
            let mut body = lines.join("\n");
            body.push('\n');
            if let Err(error) = std::fs::write(&path, body) {
                eprintln!("failed to write driver status report to {path}: {error}");
            }
        }
        std::process::exit(exit_code);
    }

    // Watchdog: best-effort host-level process health monitor (prototype).
    // When the `watchdog` module is rebuilt with full process-enumeration
    // support (`sysinfo` or OS-level APIs), this block can be re-enabled.
    log::info!("watchdog module prototype loaded; process health monitor available when module rebuilt.");

    // Out-of-band AI training mode: runs the synthetic-corpus experiment and
    // exits without touching the IPC server, so the GUI can drive it as a
    // plain child process while the engine keeps serving scans.
    let cli_args: Vec<String> = std::env::args().skip(1).collect();
    if cli_args.iter().any(|arg| arg == "--train-synthetic") {
        return match everbloom_engine::training::run_training_cli(&cli_args) {
            Ok(report_json) => {
                use std::io::Write as _;
                println!("{{\"type\":\"result\"}}");
                println!("{report_json}");
                let _ = std::io::stdout().flush();
                Ok(())
            }
            Err(error) => {
                use std::io::Write as _;
                eprintln!("training failed: {error}");
                let _ = std::io::stderr().flush();
                std::process::exit(1);
            }
        };
    }

    match everbloom_engine::driver_bridge::reload_vulnerable_driver_names_from_default_locations() {
        Ok(Some(count)) => log::info!("vulnerable driver list loaded: {} total names", count),
        Ok(None) => log::info!("using built-in vulnerable driver list"),
        Err(error) => log::warn!(
            "unable to load vulnerable driver update; using built-in list: {}",
            error
        ),
    }

    let ndjson_transport = use_ndjson_transport();
    let endpoint = std::env::var_os("EVERBLOOM_IPC_ENDPOINT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ENDPOINT));
    let r3_enabled = configured_bool("EVERBLOOM_R3_PROTECTION", true);
    let mut driver_enabled = configured_bool("EVERBLOOM_DRIVER_PROTECTION", false);
    let integrity = everbloom_engine::driver_integrity::verify_configured_driver();
    if !integrity.allows_driver_use() {
        log::error!(
            "{}; driver protection will remain disabled",
            integrity.summary()
        );
        driver_enabled = false;
    } else if std::env::var_os("EVERBLOOM_DRIVER_PATH").is_some() {
        log::info!("{}", integrity.summary());
    }
    let driver_bridge = everbloom_engine::driver_bridge::DriverBridge::new();
    if driver_enabled {
        match driver_bridge.probe_capabilities() {
            Ok(capabilities) if capabilities.is_compatible() => {
                log::info!("driver capabilities negotiated: {}", capabilities.summary());
            }
            Ok(capabilities) => {
                log::warn!(
                    "driver protocol is incompatible ({}); driver protection will remain disabled",
                    capabilities.summary()
                );
                driver_enabled = false;
            }
            Err(error) if error.is_unavailable() => {
                log::info!(
                    "driver device is not installed or started; driver protection disabled: {}",
                    error.unavailable_message()
                );
                driver_enabled = false;
            }
            Err(error) => {
                log::warn!(
                    "driver capability query unavailable; continuing with legacy fail-open bridge: {}",
                    error
                );
            }
        }
    }
    everbloom_engine::protection_state::set_modes(r3_enabled, driver_enabled);
    // Start user-mode protection independently of the transport. Previously
    // the HIPS/ETW workers were only started in the NDJSON branch, leaving
    // legacy sessions without the R3 protection layer.
    everbloom_engine::hips::start_hips_monitor();
    everbloom_engine::monitoring::start_user_event_collector();
    everbloom_engine::monitoring::start_driver_event_collector();
    if driver_enabled {
        match driver_bridge.set_protection_modes(r3_enabled, driver_enabled) {
            Ok(_) => log::info!(
                "protection modes initialized: r3={} driver={}",
                r3_enabled,
                driver_enabled
            ),
            Err(error) => {
                everbloom_engine::protection_state::set_driver_enabled(false);
                log::warn!("unable to initialize protection modes: {}", error);
            }
        }
        if driver_enabled {
            match driver_bridge.install_vulnerable_driver_policies() {
                Ok(count) => log::info!(
                    "vulnerable driver policies mirrored into kernel: {} basename rules",
                    count
                ),
                Err(error) => log::warn!(
                    "unable to mirror the dynamic vulnerable-driver list into kernel policy: {}",
                    error
                ),
            }
        }
    } else {
        everbloom_engine::protection_state::set_driver_enabled(false);
        log::info!(
            "protection modes initialized: r3={} driver=false (driver bridge skipped)",
            r3_enabled
        );
    }
    let (scanner, config_reload, model_opt, hash_import) = build_scanner();

    // Both transports share the same live control handlers. Keeping these
    // closures above the transport branch prevents the GUI's NDJSON settings
    // path from silently losing model/hash/protection management.
    let scan_cache = scanner
        .cache
        .clone()
        .unwrap_or_else(|| Arc::new(ScanCache::new(4096)));
    let model_command: Option<ModelCommandCallback> = if let Some(model) = model_opt.clone() {
        let model_root = std::env::var_os("EVERBLOOM_AI_MODEL_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                model
                    .model_path()
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .map(PathBuf::from)
            })
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let model_cache = scan_cache.clone();
        Some(Arc::new(move |source_path: String| {
            if let Some(strategy_name) = source_path.strip_prefix("set_ai_strategy:") {
                let strategy = EnsembleStrategy::parse(strategy_name)
                    .ok_or_else(|| "unsupported ensemble strategy".to_string())?;
                model.set_aggregation_strategy(strategy);
                model
                    .persist_model_registry(model_root.join("models.json"))
                    .map_err(|error| error.to_string())?;
                model_cache.invalidate_decisions();
                return Ok(format!(
                    "model aggregation strategy updated: {}",
                    strategy.as_str()
                ));
            }
            if let Some(payload) = source_path.strip_prefix("convert_model:") {
                let payload: serde_json::Value = serde_json::from_str(payload)
                    .map_err(|error| format!("invalid model conversion request: {error}"))?;
                let options = everbloom_engine::ModelConversionOptions {
                    source_path: PathBuf::from(
                        payload
                            .get("source_path")
                            .and_then(|value| value.as_str())
                            .ok_or_else(|| "missing source_path".to_string())?,
                    ),
                    model_root: model_root.clone(),
                    id: payload
                        .get("id")
                        .and_then(|value| value.as_str())
                        .map(str::to_string),
                    kind: parse_admin_model_kind(
                        payload.get("kind").and_then(|value| value.as_str()),
                    )
                    .unwrap_or(AiModelKind::CNN),
                    features_json: payload
                        .get("features_path")
                        .and_then(|value| value.as_str())
                        .map(PathBuf::from),
                    target_opset: payload
                        .get("target_opset")
                        .and_then(|value| value.as_u64())
                        .and_then(|value| u32::try_from(value).ok())
                        .or(Some(12)),
                    output_index: payload
                        .get("output_index")
                        .and_then(|value| value.as_u64())
                        .and_then(|value| usize::try_from(value).ok())
                        .unwrap_or(0),
                    malicious_index: payload
                        .get("malicious_index")
                        .and_then(|value| value.as_u64())
                        .and_then(|value| usize::try_from(value).ok())
                        .unwrap_or(1),
                    output_kind: payload
                        .get("output_kind")
                        .and_then(|value| value.as_str())
                        .unwrap_or("auto")
                        .to_string(),
                };
                let report =
                    everbloom_engine::model_converter::convert_and_import_model(&model, &options)
                        .map_err(|error| error.to_string())?;
                model
                    .persist_model_registry(model_root.join("models.json"))
                    .map_err(|error| error.to_string())?;
                model_cache.invalidate_context();
                return Ok(format!(
                    "model converted and imported: {} ({})",
                    report.model.id, report.converted_path
                ));
            }
            let source_path = source_path
                .strip_prefix("import_model:")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "invalid model import command".to_string())?;
            let info = model
                .import_model(source_path, &model_root, None, AiModelKind::CNN, 1.0, true)
                .map_err(|error| error.to_string())?;
            model
                .persist_model_registry(model_root.join("models.json"))
                .map_err(|error| error.to_string())?;
            model_cache.invalidate_context();
            Ok(format!("model imported: {} ({})", info.id, info.path))
        }))
    } else {
        None
    };
let ndjson_runtime = NdjsonRuntime {
        config_reload: config_reload
            .clone()
            .map(|callback| callback as NdjsonResultCallback),
        hash_import: hash_import
            .clone()
            .map(|callback| callback as NdjsonCommandCallback),
        model_command: model_command
            .clone()
            .map(|callback| callback as NdjsonCommandCallback),
        allowlist: scanner.allowlist.clone(),
    };
    if ndjson_transport {
        log::info!("starting resident NDJSON stdin/stdout engine transport");
        let result = run_ndjson(Arc::new(scanner), ndjson_runtime).await;
        match &result {
            Ok(()) => log::info!(
                "RUST_ENGINE_EXIT transport=ndjson reason=protocol_loop_return status=success"
            ),
            Err(error) => log::error!(
                "RUST_ENGINE_EXIT transport=ndjson reason=protocol_loop_error status=error error={}",
                error
            ),
        }
        result?;
        return Ok(());
    }

    log::info!(
        "starting legacy framed IPC engine transport at {}",
        endpoint.display()
    );
    let mut server = IpcServer::new(endpoint, Arc::new(scanner), config_reload);
    if let Some(importer) = hash_import {
        server = server.with_hash_import_command(importer);
    }
    if let Some(importer) = model_command {
        server = server.with_model_command(importer);
    }
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    #[cfg(windows)]
    if let Ok(parent_pid) = std::env::var("EVERBLOOM_PARENT_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(())
    {
        let parent_shutdown = shutdown_tx.clone();
        tokio::task::spawn_blocking(move || unsafe {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};
            const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
            let handle = OpenProcess(SYNCHRONIZE_ACCESS, 0, parent_pid);
            if !handle.is_null() {
                WaitForSingleObject(handle, u32::MAX);
                CloseHandle(handle);
                let _ = parent_shutdown.send(true);
            }
        });
    }

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = shutdown_tx.send(true);
        }
    });

    // Spawn a simple file-based config watcher if EVERBLOOM_AI_CONFIG is set.
    if let Some(cfg) = std::env::var_os("EVERBLOOM_AI_CONFIG") {
        if let Some(model_arc) = model_opt.clone() {
            let cfg_path = PathBuf::from(cfg);
            if cfg_path.is_file() {
                let watcher_model = model_arc.clone();
                let watcher_cache = scan_cache.clone();
                std::thread::spawn(move || {
                    use std::time::Duration;
                    let mut last_mtime = std::time::UNIX_EPOCH;
                    loop {
                        if let Ok(meta) = std::fs::metadata(&cfg_path) {
                            if let Ok(mtime) = meta.modified() {
                                if mtime > last_mtime {
                                    last_mtime = mtime;
                                    match watcher_model.reload_config_from_file(&cfg_path) {
                                        Ok(summary) => {
                                            if summary
                                                .changed_keys
                                                .iter()
                                                .any(|key| key == "models")
                                            {
                                                watcher_cache.invalidate_context();
                                            } else {
                                                watcher_cache.invalidate_decisions();
                                            }
                                            log::info!("AI runtime config reloaded from {}: changed={:?} previous_ensemble={} new_ensemble={} previous_blend={} new_blend={} loaded_models={} skipped_models={} strategy={}", cfg_path.display(), summary.changed_keys, summary.previous_ensemble, summary.new_ensemble, summary.previous_blend, summary.new_blend, summary.loaded_models, summary.skipped_models.len(), summary.strategy);
                                        }
                                        Err(e) => {
                                            log::warn!(
                                                "failed reloading AI config {}: {}",
                                                cfg_path.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        std::thread::sleep(Duration::from_secs(5));
                    }
                });
            }
        }
    }

    // Spawn an optional HTTP admin interface if EVERBLOOM_ADMIN_HTTP_ADDR is set.
    if let Some(addr) = std::env::var_os("EVERBLOOM_ADMIN_HTTP_ADDR") {
        if let Some(model_arc) = model_opt.clone() {
            match std::env::var("EVERBLOOM_ADMIN_TOKEN") {
                Ok(token) if !token.trim().is_empty() => {
                    let addr = addr.to_string_lossy().to_string();
                    let parsed_addr: Option<SocketAddr> = match addr.parse() {
                        Ok(parsed) => Some(parsed),
                        Err(error) => {
                            log::error!(
                                "invalid EVERBLOOM_ADMIN_HTTP_ADDR '{}': {}",
                                addr,
                                error
                            );
                            None
                        }
                    };
                    if let Some(parsed_addr) = parsed_addr {
                        let model_clone = model_arc.clone();
                        let admin_token = Arc::new(token);
                        let model_root = Arc::new(
                            std::env::var_os("EVERBLOOM_AI_MODEL_DIR")
                                .map(PathBuf::from)
                                .or_else(|| {
                                    model_clone
                                        .model_path()
                                        .parent()
                                        .filter(|path| !path.as_os_str().is_empty())
                                        .map(PathBuf::from)
                                })
                                .or_else(|| std::env::current_dir().ok())
                                .unwrap_or_else(|| PathBuf::from(".")),
                        );
                        let admin_cache = scan_cache.clone();
                        tokio::spawn(async move {
                        let make_service = make_service_fn(move |_| {
                            let model = model_clone.clone();
                            let token = admin_token.clone();
                            let root = model_root.clone();
                            let cache = admin_cache.clone();
                            async move {
                                Ok::<_, Infallible>(service_fn(move |req| {
                                    handle_admin_request(
                                        req,
                                        model.clone(),
                                        token.clone(),
                                        root.clone(),
                                        cache.clone(),
                                    )
                                }))
                            }
                        });
                        let server = Server::bind(&parsed_addr).serve(make_service);
                        log::info!("AI admin HTTP server listening on {}", parsed_addr);
                        if let Err(e) = server.await {
                            log::error!("AI admin HTTP server error: {}", e);
                        }
                        });
                    }
                }
                Ok(_) => log::error!(
                    "EVERBLOOM_ADMIN_HTTP_ADDR is set but EVERBLOOM_ADMIN_TOKEN is empty; admin HTTP disabled"
                ),
                Err(_) => log::error!(
                    "EVERBLOOM_ADMIN_HTTP_ADDR is set but EVERBLOOM_ADMIN_TOKEN is missing; admin HTTP disabled"
                ),
            }
        }
    }

    server.run(shutdown_rx).await?;
    Ok(())
}

#[cfg(test)]
mod production_wiring_tests {
    use super::build_scanner;

    #[test]
    fn production_builder_attaches_fusion_before_transport_selection() {
        // `main()` hands this scanner to both NDJSON and legacy IPC, so this
        // tests the actual production construction path rather than only the
        // reusable Scanner helper.
        let (scanner, _, _, _) = build_scanner();
        assert!(
            scanner.fusion.is_some(),
            "main.rs::build_scanner must attach ProductionFusion before either transport starts"
        );
    }
}
