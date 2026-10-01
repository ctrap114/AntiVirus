//! Everbloom Evaluation Harness - end-to-end detection quality measurement.
//!
//! `tools/run_quality_baseline.py` can time YARA and score an ONNX model, but
//! it never runs the pipeline that actually decides a verdict. It therefore
//! cannot answer the questions that matter for detection quality:
//!
//! ```text
//! 1000 green installers      -> false positive rate?
//! 1000 known malicious files -> true positive rate?
//! 500 unseen families        -> detection rate?
//! this rule                  -> how many false positives does it contribute?
//! this fusion threshold      -> how do TP / FN / FP move?
//! ```
//!
//! This harness closes that gap. It reuses the production `Scanner` type and
//! detector implementations, but assembles an explicit evaluation profile;
//! it does not call the binary's `main.rs::build_scanner()` and therefore is
//! not automatically identical to every production-loaded database, allowlist
//! or optional service. Production now also attaches the Normal
//! `ProtectionFusion` policy by default. Run with and without `--no-fusion`
//! to measure fusion's incremental effect while keeping the harness profile
//! fixed. Each sample receives an `AttributionRecord` with its verdict and
//! evidence combination.
//!
//! ```text
//! manifest -> evaluation Scanner profile -> enabled layers -> optional Fusion
//!          -> verdict -> AttributionRecord -> metrics -> optional gate
//!
//! Production uses `main.rs::build_scanner()` and shares the same Fusion
//! implementation/default policy, but can have additional environment-loaded
//! databases and services.
//! ```
//!
//! Usage
//! -----
//! ```text
//! cargo run --release --example eval_harness -- \
//!     --manifest corpus/manifest.jsonl \
//!     --records-out artifacts/quality-baseline/records.jsonl \
//!     --json-out artifacts/quality-baseline/summary.json
//! ```
//!
//! Manifest formats (auto-detected by extension):
//!
//! * `.jsonl` - one object per line:
//!   `{"path": "...", "label": "malicious|benign", "family": "...", "category": "..."}`
//! * `.json`  - either the same objects in a top-level array, or wrapped in a
//!   `{"samples": [...]}` document (the shape `tests/corpus/manifest.json`
//!   already uses).
//! * `.csv`   - header row with the same column names.
//!
//! `label` accepts a word (`malicious` / `benign`), a number (`1` / `0`) or a
//! boolean, because every corpus in this repository spells it differently.
//! Only `path` is required. `label` is optional, and an *unrecognised* label is
//! treated as unlabelled rather than as benign - silently defaulting unknown
//! samples to clean is the easiest way to publish a flattering FP rate.
//!
//! Exit codes: 0 = ran (and passed any configured gate), 1 = gate failed,
//! 2 = usage error, 3 = the manifest could not be read.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use everbloom_engine::attribution::{
    AttributionRecord, EvaluationSummary, GateLimits, ATTRIBUTION_SCHEMA_VERSION,
};
use everbloom_engine::layers::ai::{AiModel, AiModelKind};
use everbloom_engine::layers::behavior::BehavioralScorer;
use everbloom_engine::layers::cache::ScanCache;
use everbloom_engine::layers::fusion::{FusionResponseLevel, ProtectionFusion};
use everbloom_engine::layers::sequence::SequenceMatcher;
use everbloom_engine::layers::yara::YaraScanner;
use everbloom_engine::{ScanRequest, Scanner};
use serde::Deserialize;

const USAGE: &str = "\
Everbloom evaluation harness

USAGE:
    eval_harness --manifest <file> [options]

REQUIRED:
    --manifest <file>        .jsonl or .csv corpus manifest

OUTPUT:
    --records-out <file>     write one AttributionRecord JSON object per line
    --json-out <file>        write the aggregate EvaluationSummary as JSON

LAYERS (default: every layer that can be resolved is enabled):
    --rules <dir>            YARA rules directory          [data/rules]
    --model <file>           ONNX model                    [everbloom_feature_cnn.onnx]
    --model-kind <cnn|transformer>                         [cnn]
    --no-yara                disable the YARA layer
    --no-ai                  disable the AI layer
    --no-fusion              leave ProtectionFusion unattached
    --response-level <aggressive|normal|relaxed>           [normal]
    --sandbox                enable the sandbox layer (slow; needs isolation)
    --sandbox-timeout-ms <n>                               [5000]
    --ai-threshold <f>       per-request AI threshold      [0.5]
    --timeout-ms <n>         per-request scan timeout      [60000]
    --no-cache               scan without the result cache

GATE (all optional; a breached limit makes the run exit non-zero):
    --max-fp-rate <f>
    --max-fn-rate <f>
    --max-p95-ms <f>
    --min-labelled <n>       refuse to report rates below this sample count

MISC:
    --quiet                  only print the summary
    -h, --help
";

#[derive(Debug)]
struct Options {
    manifest: PathBuf,
    records_out: Option<PathBuf>,
    json_out: Option<PathBuf>,
    rules: PathBuf,
    model: PathBuf,
    model_kind: AiModelKind,
    yara: bool,
    ai: bool,
    fusion: bool,
    response_level: FusionResponseLevel,
    sandbox: bool,
    sandbox_timeout_ms: u64,
    ai_threshold: f32,
    timeout_ms: u64,
    cache: bool,
    gate: GateLimits,
    quiet: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            manifest: PathBuf::new(),
            records_out: None,
            json_out: None,
            rules: PathBuf::from("data/rules"),
            model: PathBuf::from("everbloom_feature_cnn.onnx"),
            model_kind: AiModelKind::CNN,
            yara: true,
            ai: true,
            fusion: true,
            response_level: FusionResponseLevel::Normal,
            sandbox: false,
            sandbox_timeout_ms: 5000,
            ai_threshold: 0.5,
            timeout_ms: 60_000,
            cache: true,
            gate: GateLimits::default(),
            quiet: false,
        }
    }
}

fn usage_error(message: &str) -> ! {
    eprintln!("error: {message}\n\n{USAGE}");
    std::process::exit(2);
}

fn parse_options() -> Options {
    let mut options = Options::default();
    let mut args = std::env::args().skip(1);

    // A value-taking flag is always followed by its value; a trailing flag
    // with no value is a usage error rather than a silent default.
    fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
        match args.next() {
            Some(item) => item,
            None => usage_error(&format!("{flag} requires a value")),
        }
    }
    fn number<T: std::str::FromStr>(args: &mut impl Iterator<Item = String>, flag: &str) -> T {
        let raw = value(args, flag);
        raw.parse().unwrap_or_else(|_| {
            usage_error(&format!("{flag} expects a number, got {raw:?}"))
        })
    }

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--manifest" => options.manifest = PathBuf::from(value(&mut args, &arg)),
            "--records-out" => options.records_out = Some(PathBuf::from(value(&mut args, &arg))),
            "--json-out" => options.json_out = Some(PathBuf::from(value(&mut args, &arg))),
            "--rules" => options.rules = PathBuf::from(value(&mut args, &arg)),
            "--model" => options.model = PathBuf::from(value(&mut args, &arg)),
            "--model-kind" => {
                let raw = value(&mut args, &arg);
                options.model_kind = match raw.to_ascii_lowercase().as_str() {
                    "cnn" => AiModelKind::CNN,
                    "transformer" | "tf" => AiModelKind::Transformer,
                    _ => usage_error(&format!("--model-kind expects cnn or transformer, got {raw:?}")),
                };
            }
            "--response-level" => {
                let raw = value(&mut args, &arg);
                options.response_level = match raw.to_ascii_lowercase().as_str() {
                    "aggressive" => FusionResponseLevel::Aggressive,
                    "normal" => FusionResponseLevel::Normal,
                    "relaxed" => FusionResponseLevel::Relaxed,
                    _ => usage_error(&format!(
                        "--response-level expects aggressive, normal or relaxed, got {raw:?}"
                    )),
                };
            }
            "--no-yara" => options.yara = false,
            "--no-ai" => options.ai = false,
            "--no-fusion" => options.fusion = false,
            "--sandbox" => options.sandbox = true,
            "--sandbox-timeout-ms" => options.sandbox_timeout_ms = number(&mut args, &arg),
            "--ai-threshold" => options.ai_threshold = number(&mut args, &arg),
            "--timeout-ms" => options.timeout_ms = number(&mut args, &arg),
            "--no-cache" => options.cache = false,
            "--max-fp-rate" => options.gate.max_fp_rate = Some(number(&mut args, &arg)),
            "--max-fn-rate" => options.gate.max_fn_rate = Some(number(&mut args, &arg)),
            "--max-p95-ms" => options.gate.max_p95_ms = Some(number(&mut args, &arg)),
            "--min-labelled" => options.gate.min_labelled = Some(number(&mut args, &arg)),
            "--quiet" => options.quiet = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => usage_error(&format!("unrecognised argument {other:?}")),
        }
    }

    if options.manifest.as_os_str().is_empty() {
        usage_error("--manifest is required");
    }
    options
}

/// One corpus entry. `path` is the only required column.
#[derive(Debug, Clone, serde::Deserialize)]
struct ManifestEntry {
    path: String,
    #[serde(default, deserialize_with = "de_optional_label")]
    label: Option<String>,
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

/// Labels arrive as `"malicious"`, `1`, or `true` depending on who produced
/// the corpus. Normalising here keeps the metric code working on one type
/// instead of three.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum RawLabel {
    Text(String),
    Integer(i64),
    /// Some corpora serialise the label as a float (`0.0` / `1.0`); without
    /// this arm those rows fail to parse and the whole manifest is rejected.
    Float(f64),
    Boolean(bool),
}

fn de_optional_label<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<RawLabel>::deserialize(deserializer)?;
    Ok(raw.map(|value| match value {
        RawLabel::Text(text) => text,
        RawLabel::Integer(number) => number.to_string(),
        RawLabel::Float(number) => number.to_string(),
        RawLabel::Boolean(flag) => flag.to_string(),
    }))
}

/// A corpus file that wraps its rows in a `samples` array, as
/// `tests/corpus/manifest.json` does.
#[derive(Debug, serde::Deserialize)]
struct ManifestDocument {
    samples: Vec<ManifestEntry>,
}

fn load_manifest(path: &Path) -> Result<Vec<ManifestEntry>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match extension.as_str() {
        "csv" => {
            let mut reader = csv::ReaderBuilder::new()
                .trim(csv::Trim::All)
                .flexible(true)
                .from_reader(raw.as_bytes());
            let mut entries = Vec::new();
            for record in reader.deserialize::<ManifestEntry>() {
                entries.push(record.map_err(|error| format!("{}: {error}", path.display()))?);
            }
            Ok(entries)
        }
        "json" => {
            // Accept both `{"samples": [...]}` and a bare top-level array.
            if let Ok(document) = serde_json::from_str::<ManifestDocument>(&raw) {
                return Ok(document.samples);
            }
            serde_json::from_str::<Vec<ManifestEntry>>(&raw)
                .map_err(|error| format!("{}: {error}", path.display()))
        }
        _ => {
            // JSONL: one object per line, blank lines and // comments ignored.
            let mut entries = Vec::new();
            for (index, line) in raw.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with("//") {
                    continue;
                }
                let entry: ManifestEntry = serde_json::from_str(line)
                    .map_err(|error| format!("{}:{}: {error}", path.display(), index + 1))?;
                entries.push(entry);
            }
            Ok(entries)
        }
    }
}

/// Resolve a manifest path relative to the manifest's own directory so a
/// corpus can be moved without rewriting every row.
fn resolve(base: &Path, raw: &str) -> PathBuf {
    let candidate = PathBuf::from(raw);
    if candidate.is_absolute() {
        return candidate;
    }
    let joined = base.join(&candidate);
    if joined.is_file() {
        return joined;
    }
    candidate
}

fn build_scanner(options: &Options) -> Scanner {
    let mut scanner = Scanner::new()
        .with_behavioral(Arc::new(BehavioralScorer::default()))
        .with_sequence(Arc::new(SequenceMatcher::default()));

    if options.cache {
        scanner = scanner.with_cache(Arc::new(ScanCache::new(4096)));
    }

    if options.yara {
        if options.rules.is_dir() {
            match YaraScanner::new(&options.rules) {
                Ok(yara) => scanner = scanner.with_yara(Arc::new(yara)),
                Err(error) => eprintln!(
                    "warning: YARA rules at {} could not be loaded: {error}",
                    options.rules.display()
                ),
            }
        } else {
            eprintln!(
                "warning: YARA rules directory {} does not exist; layer disabled",
                options.rules.display()
            );
        }
    }

    if options.ai {
        if options.model.is_file() {
            match AiModel::new_with_kind(&options.model, options.model_kind) {
                Ok(model) => scanner = scanner.with_ai(Arc::new(model.with_ensemble(true))),
                Err(error) => eprintln!(
                    "warning: AI model {} could not be loaded: {error}",
                    options.model.display()
                ),
            }
        } else {
            eprintln!(
                "warning: AI model {} does not exist; layer disabled",
                options.model.display()
            );
        }
    }

    if options.fusion {
        // The harness shares Scanner and detector implementations with the
        // engine but assembles an explicit validation profile. Production now
        // uses Scanner::with_default_fusion() as well; keep --no-fusion as a
        // control for paired before/after measurements and historical wiring.
        scanner = scanner.with_fusion(Arc::new(
            ProtectionFusion::new()
                .with_behavioral(Arc::new(BehavioralScorer::default()))
                .with_sequence(Arc::new(SequenceMatcher::default()))
                .with_response_level(options.response_level),
        ));
    }

    scanner = scanner
        .with_sandbox_enabled(options.sandbox)
        .with_sandbox_timeout(options.sandbox_timeout_ms);

    scanner
}

fn main() {
    let options = parse_options();

    let manifest_path = options.manifest.clone();
    let base = manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let entries = match load_manifest(&manifest_path) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(3);
        }
    };
    if entries.is_empty() {
        eprintln!("error: manifest {} contains no samples", manifest_path.display());
        std::process::exit(3);
    }

    let mut paths = Vec::with_capacity(entries.len());
    let mut missing = 0usize;
    for entry in &entries {
        let path = resolve(&base, &entry.path);
        if !path.is_file() {
            eprintln!("warning: sample does not exist: {}", path.display());
            missing += 1;
        }
        paths.push(path);
    }

    if !options.quiet {
        println!("Everbloom evaluation harness (schema {ATTRIBUTION_SCHEMA_VERSION})");
        println!("  manifest   : {}", manifest_path.display());
        println!("  samples    : {} ({missing} missing on disk)", entries.len());
        println!("  rules      : {} ({})", options.rules.display(), if options.yara { "on" } else { "off" });
        println!("  model      : {} ({})", options.model.display(), if options.ai { "on" } else { "off" });
        println!(
            "  fusion     : {} ({:?})",
            if options.fusion { "attached" } else { "unattached" },
            options.response_level
        );
        println!("  sandbox    : {}", if options.sandbox { "on" } else { "off" });
        println!();
    }

    let scanner = build_scanner(&options);
    let request = ScanRequest {
        paths: paths.clone(),
        timeout_ms: options.timeout_ms,
        sandbox_enabled: options.sandbox,
        yara_enabled: options.yara,
        ai_enabled: options.ai,
        heuristic_enabled: true,
        clamav_enabled: false,
        ai_threshold: options.ai_threshold,
        maximum_file_size: 0,
        cloud_enabled: false,
        cancelled: Arc::new(AtomicBool::new(false)),
        progress_tx: None,
    };

    let results = match futures_block_on(scanner.scan_request(request)) {
        Ok(results) => results,
        Err(error) => {
            eprintln!("error: scan failed: {error}");
            std::process::exit(3);
        }
    };

    // Match records back to manifest rows by path. The scanner preserves input
    // order, but indexing by path keeps the join correct if that ever changes.
    let mut metadata: BTreeMap<String, &ManifestEntry> = BTreeMap::new();
    for entry in &entries {
        metadata.insert(resolve(&base, &entry.path).display().to_string(), entry);
    }

    let mut records = Vec::with_capacity(results.len());
    for result in &results {
        let key = result.path.display().to_string();
        let entry = metadata.get(&key);
        records.push(AttributionRecord::from_scan_result(
            result,
            entry.and_then(|item| item.label.as_deref()),
            entry.and_then(|item| item.family.as_deref()),
            entry.and_then(|item| item.category.as_deref()),
        ));
    }

    if let Some(path) = &options.records_out {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut buffer = String::new();
        for record in &records {
            match serde_json::to_string(record) {
                Ok(line) => {
                    buffer.push_str(&line);
                    buffer.push('\n');
                }
                Err(error) => eprintln!("warning: record could not be serialised: {error}"),
            }
        }
        if let Err(error) = std::fs::write(path, buffer) {
            eprintln!("error: cannot write {}: {error}", path.display());
            std::process::exit(3);
        }
        if !options.quiet {
            println!("Attribution records: {}", path.display());
        }
    }

    let summary = EvaluationSummary::from_records(&records);

    if let Some(path) = &options.json_out {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(&summary) {
            Ok(json) => {
                if let Err(error) = std::fs::write(path, json) {
                    eprintln!("error: cannot write {}: {error}", path.display());
                    std::process::exit(3);
                }
                if !options.quiet {
                    println!("Summary            : {}", path.display());
                }
            }
            Err(error) => eprintln!("warning: summary could not be serialised: {error}"),
        }
    }

    print_summary(&summary);

    let failures = summary.gate_failures(&options.gate);
    if !failures.is_empty() {
        println!();
        println!("GATE FAILED");
        for failure in &failures {
            println!("  - {failure}");
        }
        std::process::exit(1);
    }
}

/// Minimal executor for the single `scan_request` future.
///
/// The engine exposes an async API because the sandbox stage is async, but the
/// harness has exactly one future to drive and no need for a reactor. Building
/// a runtime here would drag tokio's worker threads into every measurement and
/// distort the latency numbers this tool exists to report.
fn futures_block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}

fn percent(value: Option<f64>) -> String {
    match value {
        Some(value) => format!("{:.4}", value),
        None => "n/a (no labelled samples in the denominator)".to_string(),
    }
}

fn print_summary(summary: &EvaluationSummary) {
    println!();
    println!("== Corpus ==");
    println!(
        "  samples {}  labelled {}  unlabelled {}",
        summary.total, summary.labelled, summary.unlabelled
    );

    for (name, matrix) in [("strict (Malicious only)", &summary.strict), ("tolerant (+ Suspicious)", &summary.tolerant)]
    {
        println!();
        println!("== Confusion - {name} ==");
        println!(
            "  TP {}  FP {}  TN {}  FN {}  undecided {}",
            matrix.true_positives,
            matrix.false_positives,
            matrix.true_negatives,
            matrix.false_negatives,
            matrix.undecided
        );
        println!("  precision {}  recall {}", percent(matrix.precision()), percent(matrix.recall()));
        println!(
            "  FP rate   {}  FN rate {}  accuracy {}",
            percent(matrix.false_positive_rate()),
            percent(matrix.false_negative_rate()),
            percent(matrix.accuracy())
        );
    }

    println!();
    println!("== Fusion branches (flagged samples) ==");
    if summary.fusion_branches.is_empty() {
        println!("  (none)");
    }
    for (branch, count) in &summary.fusion_branches {
        println!("  {branch:<28} {count}");
    }

    if !summary.false_positive_indicators.is_empty() {
        println!();
        println!("== Heuristic rules contributing to false positives ==");
        let mut ranked: Vec<_> = summary.false_positive_indicators.iter().collect();
        ranked.sort_by(|left, right| right.1.cmp(left.1).then(left.0.cmp(right.0)));
        for (rule, count) in ranked.iter().take(15) {
            println!("  {rule:<40} {count}");
        }
    }

    if !summary.false_positive_sources.is_empty() {
        println!();
        println!("== Sources firing on false positives ==");
        for (source, count) in &summary.false_positive_sources {
            println!("  {source:<28} {count}");
        }
    }

    if !summary.branch_by_category.is_empty() {
        println!();
        println!("== Branch by corpus category ==");
        for (category, branches) in &summary.branch_by_category {
            let rendered = branches
                .iter()
                .map(|(branch, count)| format!("{branch}={count}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!("  {category:<24} {rendered}");
        }
    }

    println!();
    println!("== Latency (ms) ==");
    let latency = &summary.latency;
    println!(
        "  n {}  total {}  mean {}  p50 {}  p95 {}  p99 {}  max {}",
        latency.count,
        latency.total_ms,
        latency
            .mean_ms
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "n/a".to_string()),
        latency
            .p50_ms
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "n/a".to_string()),
        latency
            .p95_ms
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "n/a".to_string()),
        latency
            .p99_ms
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "n/a".to_string()),
        latency
            .max_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
    );
}
