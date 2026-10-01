//! Safe bridge to the bundled ONNX normalizer.
//!
//! ONNX conversion is deliberately kept out of the scanner hot path. The
//! converter is a separate, bounded Python tool that only rewrites a model
//! graph and emits sidecars. Rust owns the destination directory, process
//! timeout, post-conversion tract validation, and atomic registration.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use thiserror::Error;

use crate::layers::ai::{AiError, AiModel, AiModelInfo, AiModelKind, AiModelValidationReport};

const DEFAULT_CONVERSION_TIMEOUT_MS: u64 = 60_000;
const MAX_CONVERSION_TIMEOUT_MS: u64 = 300_000;
const MAX_CONVERTER_OUTPUT_BYTES: usize = 32 * 1024;
const CONVERTER_SCRIPT: &str = "convert_onnx_for_everbloom.py";

#[derive(Debug, Clone)]
pub struct ModelConversionOptions {
    pub source_path: PathBuf,
    pub model_root: PathBuf,
    pub id: Option<String>,
    pub kind: AiModelKind,
    pub features_json: Option<PathBuf>,
    pub target_opset: Option<u32>,
    pub output_index: usize,
    pub malicious_index: usize,
    pub output_kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelConversionReport {
    pub source_path: String,
    pub converted_path: String,
    pub validation: AiModelValidationReport,
    pub warnings: Vec<String>,
    pub model: AiModelInfo,
}

#[derive(Debug, Error)]
pub enum ModelConversionError {
    #[error("model conversion I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("model conversion failed: {0}")]
    Conversion(String),
    #[error("converted model validation failed: {0}")]
    Validation(String),
    #[error("model import failed: {0}")]
    Model(#[from] AiError),
}

pub fn convert_and_import_model(
    model: &AiModel,
    options: &ModelConversionOptions,
) -> Result<ModelConversionReport, ModelConversionError> {
    let source = crate::layers::ai::validate_onnx_model_file(&options.source_path)
        .map_err(ModelConversionError::Model)?;
    let safe_id = normalize_conversion_id(options.id.as_deref(), &source)?;
    let root = options.model_root.canonicalize().or_else(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            fs::create_dir_all(&options.model_root)?;
            options.model_root.canonicalize()
        } else {
            Err(error)
        }
    })?;
    let destination_dir = root.join("imported").join(&safe_id);
    if destination_dir.exists() {
        return Err(ModelConversionError::Conversion(format!(
            "conversion destination already exists: {}",
            destination_dir.display()
        )));
    }
    fs::create_dir_all(&destination_dir)?;
    let destination = destination_dir.join("model.onnx");

    let result = (|| {
        let script = locate_converter_script()?;
        let python = locate_python()?;
        let mut args = vec![
            script.to_string_lossy().into_owned(),
            "--source".to_string(),
            source.to_string_lossy().into_owned(),
            "--destination".to_string(),
            destination.to_string_lossy().into_owned(),
            "--output-index".to_string(),
            options.output_index.to_string(),
            "--malicious-index".to_string(),
            options.malicious_index.to_string(),
            "--output-kind".to_string(),
            normalize_output_kind(&options.output_kind)?,
        ];
        if let Some(opset) = options.target_opset {
            args.extend(["--target-opset".to_string(), opset.to_string()]);
        } else {
            args.push("--no-opset-conversion".to_string());
        }
        let features = options
            .features_json
            .clone()
            .or_else(|| source.parent().map(|parent| parent.join("features.json")))
            .filter(|path| path.is_file());
        if let Some(features) = features {
            args.extend([
                "--features-json".to_string(),
                features.to_string_lossy().into_owned(),
            ]);
        }
        let converter_output = run_converter(&python, &args)?;
        let warnings = serde_json::from_str::<serde_json::Value>(converter_output.trim())
            .ok()
            .and_then(|value| value.get("warnings").cloned())
            .and_then(|value| value.as_array().cloned())
            .map(|values| {
                values
                    .into_iter()
                    .filter_map(|value| value.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let validation = AiModel::validate_model_for_scanner(&destination, options.kind);
        if !validation.usable {
            return Err(ModelConversionError::Validation(
                validation
                    .errors
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "converted model is not usable by EverbloomSecurity".to_string()),
            ));
        }
        let info = model.add_model(&safe_id, &destination, options.kind, 1.0, true)?;
        Ok(ModelConversionReport {
            source_path: source.to_string_lossy().into_owned(),
            converted_path: destination.to_string_lossy().into_owned(),
            validation,
            warnings,
            model: info,
        })
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&destination_dir);
    }
    result
}

fn normalize_conversion_id(
    requested: Option<&str>,
    source: &Path,
) -> Result<String, ModelConversionError> {
    let candidate = requested
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| source.file_stem().and_then(|value| value.to_str()))
        .unwrap_or("converted-model");
    if candidate.len() > 64
        || candidate == "."
        || candidate == ".."
        || candidate
            .chars()
            .any(|value| !(value.is_ascii_alphanumeric() || matches!(value, '-' | '_' | '.')))
    {
        return Err(ModelConversionError::Conversion(
            "model id must use only ASCII letters, numbers, '-', '_' or '.' and be <=64 characters"
                .to_string(),
        ));
    }
    Ok(candidate.to_string())
}

fn normalize_output_kind(value: &str) -> Result<String, ModelConversionError> {
    let value = value.trim().to_ascii_lowercase();
    if matches!(value.as_str(), "auto" | "probability" | "logit") {
        Ok(value)
    } else {
        Err(ModelConversionError::Conversion(
            "output kind must be auto, probability, or logit".to_string(),
        ))
    }
}

fn locate_converter_script() -> Result<PathBuf, ModelConversionError> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("EVERBLOOM_MODEL_CONVERTER_SCRIPT") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("tools").join(CONVERTER_SCRIPT));
            candidates.push(parent.join(CONVERTER_SCRIPT));
        }
    }
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current.join("tools").join(CONVERTER_SCRIPT));
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            ModelConversionError::Conversion(format!(
                "{CONVERTER_SCRIPT} was not found; set EVERBLOOM_MODEL_CONVERTER_SCRIPT"
            ))
        })
}

fn locate_python() -> Result<String, ModelConversionError> {
    let candidates = if let Some(value) = std::env::var_os("EVERBLOOM_PYTHON") {
        vec![value.to_string_lossy().into_owned()]
    } else if cfg!(windows) {
        vec!["python.exe".to_string(), "python".to_string()]
    } else {
        vec!["python3".to_string(), "python".to_string()]
    };
    for candidate in candidates {
        if Command::new(&candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(candidate);
        }
    }
    Err(ModelConversionError::Conversion(
        "Python with the 'onnx' package is required for model conversion; set EVERBLOOM_PYTHON"
            .to_string(),
    ))
}

fn conversion_timeout() -> Duration {
    Duration::from_millis(
        std::env::var("EVERBLOOM_MODEL_CONVERSION_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_CONVERSION_TIMEOUT_MS)
            .clamp(1_000, MAX_CONVERSION_TIMEOUT_MS),
    )
}

fn run_converter(python: &str, args: &[String]) -> Result<String, ModelConversionError> {
    let mut child = Command::new(python)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| ModelConversionError::Conversion(format!("start converter: {error}")))?;
    let timeout = conversion_timeout();
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ModelConversionError::Conversion(format!(
                "converter timed out after {} ms",
                timeout.as_millis()
            )));
        }
        thread::sleep(Duration::from_millis(25));
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let details = if output.stderr.is_empty() {
        output.stdout
    } else {
        output.stderr
    };
    let details = String::from_utf8_lossy(&details);
    let details = details
        .chars()
        .take(MAX_CONVERTER_OUTPUT_BYTES)
        .collect::<String>();
    Err(ModelConversionError::Conversion(format!(
        "converter exited with {}: {}",
        output.status,
        details.trim()
    )))
}
