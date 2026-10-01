//! Detection attribution and offline evaluation support.
//!
//! A `ScanResult` answers "was this file flagged". It cannot answer the
//! question that actually drives detection-quality work: *which evidence
//! combination produced that flag, and how would the answer change if one
//! input changed.* This module turns a scan into an explainable decision
//! sample.
//!
//! Three ideas carry the design:
//!
//! 1. **Authority and confidence are different axes.** `Authority` says
//!    whether a source is allowed to change the verdict on its own.
//!    `confidence` says how trustworthy that source's own answer is. An exact
//!    hash is authoritative and near-certain; a broad YARA rule is equally
//!    authoritative (it short-circuits the pipeline) but its confidence
//!    depends entirely on how the rule was written. Collapsing the two into a
//!    single "trust" number is what lets one over-broad rule produce false
//!    positives that no ordinary allowlist can suppress.
//!
//! 2. **The fusion branch is the decision, not the score.** `ProtectionFusion`
//!    already encodes which rule fired into the `reason` string
//!    (`fusion:static:stage=correlate:heuristic=0.76:...`). Parsing it back
//!    into structure means metrics can be sliced by branch - "how many false
//!    positives came from `fusion:static`" - instead of only by verdict.
//!
//! 3. **Ground truth is optional, and absence is not a negative.** An
//!    unlabelled sample is excluded from every rate rather than counted as
//!    benign, because silently treating "unknown" as "clean" is the single
//!    easiest way to publish a flattering false-positive rate.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::scanner::{ScanResult, ScanVerdict};

/// Bumped whenever the record layout changes in a way that invalidates
/// previously exported attribution files.
pub const ATTRIBUTION_SCHEMA_VERSION: u32 = 1;

/// Whether a detection source may change the verdict by itself.
///
/// Authoritative sources short-circuit the pipeline: a match is reported as
/// malicious without asking the fusion stage. Evidence sources are scored
/// inputs that `ProtectionFusion` weighs against each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionAuthority {
    /// A match is treated as proof: exact hash, YARA rule, ClamAV signature,
    /// threat-intelligence IOC, strict ordered behaviour chain, driver block,
    /// and the explicitly named `high_confidence_override` gate.
    Authoritative,
    /// A scored signal that only contributes to the fusion decision:
    /// heuristics, the AI model, the behaviour score, the static sandbox,
    /// tolerant sequence chains, memory-snapshot indicators, HIPS alerts.
    Evidence,
}

/// How trustworthy a source's own answer is, independent of its authority.
///
/// This is a *classification*, not a probability: it describes what the number
/// means, so a consumer cannot accidentally compare a calibrated model output
/// with an uncalibrated rule sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBasis {
    /// Deterministic - the answer is a byte comparison, not a judgement.
    Deterministic,
    /// A curated signature whose quality depends on how it was authored.
    Signature,
    /// A trained model output; comparable only to other outputs of the same
    /// model version.
    Model,
    /// A hand-tuned weighted sum of rule hits; ordinal, not calibrated.
    RuleSum,
    /// A score produced by watching execution rather than reading bytes.
    Observed,
}

/// One source's contribution to a single decision.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceContribution {
    pub source: &'static str,
    pub authority: DetectionAuthority,
    pub confidence_basis: ConfidenceBasis,
    /// Whether this source produced any signal at all for this sample.
    pub fired: bool,
    /// The source's own score, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    /// Matched rule / family / indicator / chain names, capped for readability.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub detail: Vec<String>,
    /// Populated when the source was expected to run but could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
}

impl EvidenceContribution {
    fn new(source: &'static str) -> Self {
        let (authority, confidence_basis) = source_profile(source);
        Self {
            source,
            authority,
            confidence_basis,
            fired: false,
            score: None,
            detail: Vec::new(),
            unavailable: None,
        }
    }
}

/// Static profile table. Keeping this in one place means a source cannot be
/// classified as authoritative in the metrics and as evidence in the code.
pub fn source_profile(source: &str) -> (DetectionAuthority, ConfidenceBasis) {
    use ConfidenceBasis::*;
    use DetectionAuthority::*;
    match source {
        "hash" => (Authoritative, Deterministic),
        "yara" => (Authoritative, Signature),
        "clamav" => (Authoritative, Signature),
        "threat_intel" => (Authoritative, Signature),
        "sequence" => (Authoritative, Observed),
        "driver" => (Authoritative, Deterministic),
        "amsi" => (Authoritative, Signature),
        // The override is an authority *gate*, not a source: it decides only
        // because a named evidence score crossed a published threshold, so it
        // is reported separately from the `heuristic` / `ai` contributions
        // that fed it. Without this entry a consumer could not tell "fusion
        // corroborated two engines" apart from "one engine overrode fusion".
        "high_confidence_override" => (Authoritative, RuleSum),
        "heuristic" => (Evidence, RuleSum),
        "ai" => (Evidence, Model),
        "behavior" => (Evidence, Observed),
        "static_sandbox" => (Evidence, RuleSum),
        "sequence_tolerant" => (Evidence, Observed),
        "sandbox" => (Evidence, Observed),
        "memory_snapshot" => (Evidence, RuleSum),
        "hips" => (Evidence, Observed),
        _ => (Evidence, RuleSum),
    }
}

/// The fusion decision, decomposed.
#[derive(Debug, Clone, Serialize)]
pub struct FusionBreakdown {
    /// `driver`, `kaspersky_sequence`, `kaspersky_sequence_tolerant`, `atc`,
    /// `static_high`, `static`, `sandbox_flags`, `hips`, or `none` when the
    /// reason did not come from the fusion stage.
    pub branch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heuristic: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub combined: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corroboration: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<u32>,
    /// The published threshold a branch was compared against, when the reason
    /// carries one. Without it a reader sees "heuristic=0.85" and still cannot
    /// tell how far above or below the decision line the sample sat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f32>,
    /// Everything after the last `key=value` token: the matched chains,
    /// indicators or alerts that latched the branch.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub payload: Vec<String>,
    /// The unparsed reason, kept verbatim so a schema drift is visible rather
    /// than silently dropped.
    pub raw: String,
}

impl FusionBreakdown {
    /// Parse a scanner `reason` into a branch plus its named fields.
    ///
    /// Recognised shapes (see `layers::fusion::ProtectionFusion::evaluate`):
    ///
    /// ```text
    /// fusion:driver:stage=intervene:driver blocked ...
    /// fusion:kaspersky_sequence:stage=intervene:chain_a,chain_b
    /// fusion:kaspersky_sequence_tolerant:stage=correlate:events=3:score=0.42:a,b
    /// fusion:atc:0.76:stage=intervene:evidence=2:ind_a,ind_b
    /// fusion:static_high:stage=correlate:heuristic=0.90:ai=0.20:strongest=0.90
    /// fusion:static:stage=correlate:heuristic=0.76:ai=0.31:combined=0.49:corroboration=0.31
    /// fusion:high_confidence_override:stage=intervene:source=heuristic:score=0.85:threshold=0.80
    /// fusion:sandbox_flags:stage=intervene:files_changed,network_activity
    /// fusion:hips:stage=correlate:evidence=2:alert_a|alert_b
    /// ```
    pub fn parse(reason: &str) -> Self {
        let body = reason.strip_prefix("cached:").unwrap_or(reason);
        let mut breakdown = Self {
            branch: "none".to_string(),
            stage: None,
            heuristic: None,
            ai: None,
            combined: None,
            corroboration: None,
            evidence: None,
            threshold: None,
            payload: Vec::new(),
            raw: reason.to_string(),
        };

        let mut parts = body.split(':');
        if parts.next() != Some("fusion") {
            return breakdown;
        }
        let Some(branch) = parts.next() else {
            return breakdown;
        };
        breakdown.branch = branch.to_string();

        let mut tail: Option<String> = None;
        for token in parts {
            if let Some((key, value)) = token.split_once('=') {
                match key {
                    "stage" => breakdown.stage = Some(value.to_string()),
                    "heuristic" => breakdown.heuristic = value.parse().ok(),
                    "ai" => breakdown.ai = value.parse().ok(),
                    "combined" => breakdown.combined = value.parse().ok(),
                    "corroboration" => breakdown.corroboration = value.parse().ok(),
                    "strongest" => breakdown.heuristic = breakdown.heuristic.or(value.parse().ok()),
                    "score" => breakdown.combined = breakdown.combined.or(value.parse().ok()),
                    "events" | "evidence" => breakdown.evidence = value.parse().ok(),
                    "threshold" => breakdown.threshold = value.parse().ok(),
                    // `source=heuristic` names which engine tripped the
                    // high-confidence override; keep it as the payload so the
                    // record shows the gate *and* what opened it.
                    "source" => breakdown.payload = vec![value.to_string()],
                    _ => {}
                }
                continue;
            }
            if tail.is_some() {
                // A second free-form token: keep appending, the payload is a
                // comma/pipe separated list that may itself contain colons
                // (HIPS alerts carry " in pid 1234").
                tail = Some(format!("{}:{}", tail.unwrap_or_default(), token));
                continue;
            }
            // `fusion:atc:<score>:stage=...` puts a bare float before the
            // first key. Anything else free-form is the payload.
            if let Ok(score) = token.parse::<f32>() {
                if breakdown.branch == "atc" && breakdown.combined.is_none() {
                    breakdown.combined = Some(score);
                    continue;
                }
            }
            tail = Some(token.to_string());
        }

        if let Some(tail) = tail {
            breakdown.payload = tail
                .split([',', '|'])
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect();
        }
        breakdown
    }
}

/// What a scan looked like, per layer, plus ground truth.
#[derive(Debug, Clone, Serialize)]
pub struct AttributionRecord {
    pub schema: u32,
    pub sample: String,
    /// Ground-truth label exactly as supplied by the corpus manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Normalised ground truth: `true` malicious, `false` benign, `None` when
    /// the label was absent or unrecognised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_malicious: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Corpus bucket, e.g. `green_software`, `installer`, `packed_benign`.
    /// This is the slice that answers "which benign category enters
    /// `fusion:static` most often".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub verdict: String,
    pub malicious: bool,
    pub reason: String,
    pub fusion: FusionBreakdown,
    pub contributions: Vec<EvidenceContribution>,
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AttributionRecord {
    /// Build a record from a finished scan.
    pub fn from_scan_result(
        result: &ScanResult,
        label: Option<&str>,
        family: Option<&str>,
        category: Option<&str>,
    ) -> Self {
        let verdict = result.verdict();
        let fusion = FusionBreakdown::parse(&result.reason);

        let mut contributions = Vec::new();

        // --- authoritative sources -------------------------------------
        let mut yara = EvidenceContribution::new("yara");
        yara.detail = result
            .yara_matches
            .iter()
            .take(32)
            .map(|hit| {
                if hit.namespace.is_empty() {
                    hit.rule_name.clone()
                } else {
                    format!("{}:{}", hit.namespace, hit.rule_name)
                }
            })
            .collect();
        yara.fired = !yara.detail.is_empty();
        contributions.push(yara);

        let reason_body = result.reason.strip_prefix("cached:").unwrap_or(&result.reason);
        for source in ["hash", "clamav", "threat_intel", "amsi"] {
            let mut item = EvidenceContribution::new(source);
            if let Some(rest) = reason_body.strip_prefix(&format!("{source}:")) {
                item.fired = true;
                item.detail = vec![rest.to_string()];
            }
            contributions.push(item);
        }

        let mut driver = EvidenceContribution::new("driver");
        driver.fired = fusion.branch == "driver";
        if driver.fired {
            driver.detail = fusion.payload.clone();
        }
        contributions.push(driver);

        let mut sequence = EvidenceContribution::new("sequence");
        if fusion.branch == "kaspersky_sequence" {
            sequence.fired = true;
            sequence.detail = result.sequence_matches.clone().unwrap_or_default();
        }
        contributions.push(sequence);

        let mut tolerant = EvidenceContribution::new("sequence_tolerant");
        if fusion.branch == "kaspersky_sequence_tolerant" {
            tolerant.fired = true;
            tolerant.score = fusion.combined;
            tolerant.detail = fusion.payload.clone();
        }
        contributions.push(tolerant);

        // --- evidence sources ------------------------------------------
        let mut heuristic = EvidenceContribution::new("heuristic");
        heuristic.score = result.heuristic_score;
        heuristic.fired = result.heuristic_score.is_some();
        heuristic.detail = result.heuristic_indicators.iter().take(64).cloned().collect();
        contributions.push(heuristic);

        let mut ai = EvidenceContribution::new("ai");
        ai.score = result.ai_score;
        ai.fired = result.ai_score.is_some();
        ai.detail = result
            .ai_components
            .iter()
            .take(16)
            .map(|(name, score, weight)| format!("{name}={score:.3}@{weight:.2}"))
            .collect();
        // A degraded estimate must not be presented as a model score. The
        // number is kept (the scan still used it) but the source is marked
        // unavailable so triage can tell "the model said 0.47" apart from
        // "the model never ran and a heuristic stood in for it".
        ai.unavailable = result.ai_fallback_reason.clone();
        contributions.push(ai);

        // The high-confidence override is the single place an evidence source
        // is allowed to decide without corroboration. Recording it as its own
        // authoritative contribution keeps the two questions separable:
        // "which engine scored high?" (`heuristic` / `ai`) and "did a gate let
        // that score decide alone?" (this entry).
        let mut override_gate = EvidenceContribution::new("high_confidence_override");
        if fusion.branch == "high_confidence_override" {
            override_gate.fired = true;
            override_gate.score = fusion.combined.or(fusion.heuristic).or(fusion.ai);
            if let Some(threshold) = fusion.threshold {
                override_gate
                    .detail
                    .push(format!("threshold={threshold:.2}"));
            }
            override_gate.detail.extend(fusion.payload.iter().cloned());
        }
        contributions.push(override_gate);

        let mut behavior = EvidenceContribution::new("behavior");
        behavior.score = result.behavior_score;
        behavior.fired = result.behavior_score.is_some();
        contributions.push(behavior);

        let mut static_sandbox = EvidenceContribution::new("static_sandbox");
        if let Some(prediction) = &result.static_sandbox {
            static_sandbox.fired = !prediction.capabilities.is_empty();
            static_sandbox.score = Some(prediction.score);
            static_sandbox.detail = prediction
                .capabilities
                .iter()
                .take(32)
                .chain(prediction.attack_techniques.iter().take(16))
                .cloned()
                .collect();
        }
        contributions.push(static_sandbox);

        let mut sandbox = EvidenceContribution::new("sandbox");
        match &result.sandbox {
            Some(report) => {
                sandbox.fired = true;
                sandbox.detail = vec![
                    format!("files_changed={}", report.files_changed.len()),
                    format!("registry_writes={}", report.registry_writes.len()),
                    format!("network_connections={}", report.network_connections.len()),
                    format!("api_calls={}", report.api_calls.len()),
                    format!("isolation={}", report.isolation_backend),
                    format!("timed_out={}", report.timed_out),
                ];
                if !report.isolation_verified || !report.cleanup_verified {
                    sandbox.unavailable = Some("isolation or cleanup not verified".to_string());
                }
            }
            None => {
                if matches!(
                    reason_body,
                    "sandbox_unavailable" | "sandbox_unverified" | "engine_unavailable"
                ) {
                    sandbox.unavailable = Some(reason_body.to_string());
                }
            }
        }
        contributions.push(sandbox);

        let mut hips = EvidenceContribution::new("hips");
        if fusion.branch == "hips" {
            hips.fired = true;
            hips.detail = fusion.payload.clone();
        }
        contributions.push(hips);

        let mut process_state = EvidenceContribution::new("process_state");
        if let Some(state) = &result.process_state {
            process_state.fired = true;
            process_state.detail = vec![state.to_string()];
        }
        contributions.push(process_state);

        let mut rollback = EvidenceContribution::new("rollback");
        if let Some(actions) = &result.rollback_actions {
            rollback.fired = !actions.is_empty();
            rollback.detail = actions.iter().take(32).cloned().collect();
        }
        contributions.push(rollback);

        Self {
            schema: ATTRIBUTION_SCHEMA_VERSION,
            sample: result.path.display().to_string(),
            label: label.map(str::to_string),
            is_malicious: label.and_then(parse_label),
            family: family.map(str::to_string),
            category: category.map(str::to_string),
            verdict: verdict.as_str().to_string(),
            malicious: result.malicious,
            reason: result.reason.clone(),
            fusion,
            contributions,
            duration_ms: result.duration_ms,
            error: result.error.clone(),
        }
    }

    /// Sources that actually produced a signal, strongest authority first.
    pub fn fired_sources(&self) -> Vec<&str> {
        self.contributions
            .iter()
            .filter(|item| item.fired)
            .map(|item| item.source)
            .collect()
    }

    /// True when the sample was flagged at the intervention level.
    pub fn is_positive_strict(&self) -> bool {
        self.verdict == ScanVerdict::Malicious.as_str()
    }

    /// True when the sample reached at least the correlation stage. Counting
    /// these as positives is how threshold calibration trades recall against
    /// false positives without changing the fusion code.
    pub fn is_positive_tolerant(&self) -> bool {
        matches!(
            self.verdict.as_str(),
            v if v == ScanVerdict::Malicious.as_str() || v == ScanVerdict::Suspicious.as_str()
        )
    }

    /// True when the scan produced a usable decision at all.
    ///
    /// `Incomplete` needs care. The scanner maps a completed scan that raised
    /// no signal to `reason = "unknown"` and *deliberately* refuses to call it
    /// `Clean`, because "nothing was found" is not the same claim as "the file
    /// is proven clean" (see `ScanResult::verdict` and the scanner test that
    /// pins this). For detection-quality measurement the question is
    /// different: the engine raised no alarm, so the sample is a negative
    /// decision and must count towards the true-negative denominator.
    ///
    /// A record that carries an `error` is a genuinely undecided scan -
    /// unavailable engine, unverified sandbox, cancelled work - and stays
    /// excluded from every rate. `Skipped` (oversized) and `Cancelled` are
    /// excluded for the same reason: nothing was evaluated.
    pub fn is_decided(&self) -> bool {
        if self.error.is_some() {
            return false;
        }
        !matches!(
            self.verdict.as_str(),
            v if v == ScanVerdict::Skipped.as_str()
                || v == ScanVerdict::Error.as_str()
                || v == ScanVerdict::Cancelled.as_str()
        )
    }
}

/// Normalise a manifest label. `None` means "unrecognised", which is treated
/// as unlabelled rather than silently defaulted to benign.
pub fn parse_label(label: &str) -> Option<bool> {
    match label.trim().to_ascii_lowercase().as_str() {
        "malicious" | "malware" | "mal" | "bad" | "positive" | "1" | "true" => Some(true),
        "benign" | "clean" | "good" | "negative" | "0" | "false" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ConfusionMatrix {
    pub true_positives: u64,
    pub false_positives: u64,
    pub true_negatives: u64,
    pub false_negatives: u64,
    /// Labelled samples the scan could not decide; excluded from the rates.
    pub undecided: u64,
}

impl ConfusionMatrix {
    pub fn positives(&self) -> u64 {
        self.true_positives + self.false_positives
    }

    pub fn negatives(&self) -> u64 {
        self.true_negatives + self.false_negatives
    }

    pub fn precision(&self) -> Option<f64> {
        ratio(self.true_positives, self.positives())
    }

    pub fn recall(&self) -> Option<f64> {
        ratio(
            self.true_positives,
            self.true_positives + self.false_negatives,
        )
    }

    pub fn false_positive_rate(&self) -> Option<f64> {
        ratio(self.false_positives, self.negatives())
    }

    pub fn false_negative_rate(&self) -> Option<f64> {
        ratio(
            self.false_negatives,
            self.true_positives + self.false_negatives,
        )
    }

    pub fn accuracy(&self) -> Option<f64> {
        let total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives;
        ratio(
            self.true_positives + self.true_negatives,
            total,
        )
    }

    pub fn f1(&self) -> Option<f64> {
        let precision = self.precision()?;
        let recall = self.recall()?;
        if precision + recall == 0.0 {
            return Some(0.0);
        }
        Some(2.0 * precision * recall / (precision + recall))
    }
}

fn ratio(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    pub count: usize,
    pub total_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p50_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<u128>,
}

impl LatencyStats {
    pub fn from_durations(mut durations: Vec<u128>) -> Self {
        if durations.is_empty() {
            return Self {
                count: 0,
                total_ms: 0,
                mean_ms: None,
                p50_ms: None,
                p95_ms: None,
                p99_ms: None,
                max_ms: None,
            };
        }
        let total_ms: u128 = durations.iter().sum();
        let count = durations.len();
        durations.sort_unstable();
        let at = |quantile: f64| -> f64 {
            // Nearest-rank: index 0 for a single sample, never out of bounds.
            let rank = (quantile * count as f64).ceil().max(1.0) as usize;
            durations[rank.min(count) - 1] as f64
        };
        Self {
            count,
            total_ms,
            mean_ms: Some(total_ms as f64 / count as f64),
            p50_ms: Some(at(0.50)),
            p95_ms: Some(at(0.95)),
            p99_ms: Some(at(0.99)),
            max_ms: durations.last().copied(),
        }
    }
}

/// Aggregate metrics over a set of attribution records.
#[derive(Debug, Clone, Serialize)]
pub struct EvaluationSummary {
    pub schema: u32,
    pub total: usize,
    pub labelled: usize,
    pub unlabelled: usize,
    /// `Malicious` counts as positive.
    pub strict: ConfusionMatrix,
    /// `Malicious` or `Suspicious` counts as positive. The gap between the two
    /// matrices is the recall that threshold relaxation would buy, and the
    /// false positives it would cost.
    pub tolerant: ConfusionMatrix,
    /// How often each fusion branch produced a flagged verdict.
    pub fusion_branches: BTreeMap<String, u64>,
    /// False-positive counts per corpus category, per fusion branch.
    pub branch_by_category: BTreeMap<String, BTreeMap<String, u64>>,
    /// Among false positives, how many samples each source fired on. This is
    /// the "which layer is manufacturing the false positives" view.
    pub false_positive_sources: BTreeMap<String, u64>,
    /// Among false positives, how many samples each heuristic rule/family
    /// contributed to.
    pub false_positive_indicators: BTreeMap<String, u64>,
    /// Branches that missed malicious samples.
    pub false_negative_branches: BTreeMap<String, u64>,
    pub latency: LatencyStats,
}

impl EvaluationSummary {
    pub fn from_records(records: &[AttributionRecord]) -> Self {
        let mut strict = ConfusionMatrix::default();
        let mut tolerant = ConfusionMatrix::default();
        let mut fusion_branches: BTreeMap<String, u64> = BTreeMap::new();
        let mut branch_by_category: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        let mut false_positive_sources: BTreeMap<String, u64> = BTreeMap::new();
        let mut false_positive_indicators: BTreeMap<String, u64> = BTreeMap::new();
        let mut false_negative_branches: BTreeMap<String, u64> = BTreeMap::new();
        let mut durations = Vec::with_capacity(records.len());

        let mut labelled = 0usize;
        for record in records {
            durations.push(record.duration_ms);

            let flagged_strict = record.is_positive_strict();
            let flagged_tolerant = record.is_positive_tolerant();
            if flagged_tolerant {
                *fusion_branches
                    .entry(record.fusion.branch.clone())
                    .or_default() += 1;
                let category = record
                    .category
                    .clone()
                    .unwrap_or_else(|| "uncategorised".to_string());
                *branch_by_category
                    .entry(category)
                    .or_default()
                    .entry(record.fusion.branch.clone())
                    .or_default() += 1;
            }

            let Some(truth) = record.is_malicious else {
                continue;
            };
            labelled += 1;
            if !record.is_decided() {
                strict.undecided += 1;
                tolerant.undecided += 1;
                continue;
            }

            match (truth, flagged_strict) {
                (true, true) => strict.true_positives += 1,
                (true, false) => strict.false_negatives += 1,
                (false, true) => strict.false_positives += 1,
                (false, false) => strict.true_negatives += 1,
            }
            match (truth, flagged_tolerant) {
                (true, true) => tolerant.true_positives += 1,
                (true, false) => tolerant.false_negatives += 1,
                (false, true) => tolerant.false_positives += 1,
                (false, false) => tolerant.true_negatives += 1,
            }

            if truth && !flagged_strict {
                *false_negative_branches
                    .entry(record.fusion.branch.clone())
                    .or_default() += 1;
            }
            if !truth && flagged_strict {
                for source in record.fired_sources() {
                    *false_positive_sources.entry(source.to_string()).or_default() += 1;
                }
                // Count *samples* a rule contributed to, not occurrences: a
                // rule that fires twice inside one file is still one false
                // positive, and occurrence counting would rank noisy rules
                // above rules that genuinely mislead across the corpus.
                let mut families = std::collections::BTreeSet::new();
                for contribution in &record.contributions {
                    if contribution.source == "heuristic" {
                        for indicator in &contribution.detail {
                            // Collapse "many_sections: 12" to "many_sections"
                            // so the same rule aggregates across samples.
                            families.insert(
                                indicator
                                    .split([':', ' '])
                                    .next()
                                    .unwrap_or(indicator)
                                    .to_string(),
                            );
                        }
                    }
                }
                for family in families {
                    *false_positive_indicators.entry(family).or_default() += 1;
                }
            }
        }

        Self {
            schema: ATTRIBUTION_SCHEMA_VERSION,
            total: records.len(),
            labelled,
            unlabelled: records.len() - labelled,
            strict,
            tolerant,
            fusion_branches,
            branch_by_category,
            false_positive_sources,
            false_positive_indicators,
            false_negative_branches,
            latency: LatencyStats::from_durations(durations),
        }
    }

    /// Returns the reasons this summary should fail a CI gate, if any.
    pub fn gate_failures(&self, limits: &GateLimits) -> Vec<String> {
        let mut failures = Vec::new();
        if let (Some(actual), Some(limit)) = (self.strict.false_positive_rate(), limits.max_fp_rate) {
            if actual > limit {
                failures.push(format!(
                    "false positive rate {actual:.4} exceeds {limit:.4}"
                ));
            }
        }
        if let (Some(actual), Some(limit)) = (self.strict.false_negative_rate(), limits.max_fn_rate) {
            if actual > limit {
                failures.push(format!(
                    "false negative rate {actual:.4} exceeds {limit:.4}"
                ));
            }
        }
        if let (Some(actual), Some(limit)) = (self.latency.p95_ms, limits.max_p95_ms) {
            if actual > limit {
                failures.push(format!("p95 latency {actual:.1} ms exceeds {limit:.1} ms"));
            }
        }
        if let Some(minimum) = limits.min_labelled {
            if self.labelled < minimum {
                failures.push(format!(
                    "only {} labelled sample(s); {minimum} required for a meaningful rate",
                    self.labelled
                ));
            }
        }
        failures
    }
}

/// CI gate thresholds. Every field is optional; `None` disables that check.
#[derive(Debug, Clone, Copy, Default)]
pub struct GateLimits {
    pub max_fp_rate: Option<f64>,
    pub max_fn_rate: Option<f64>,
    pub max_p95_ms: Option<f64>,
    /// Refuse to report rates computed from a corpus smaller than this.
    pub min_labelled: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn record(
        verdict: ScanVerdict,
        reason: &str,
        label: Option<bool>,
        duration_ms: u128,
    ) -> AttributionRecord {
        let mut result = ScanResult {
            path: PathBuf::from("sample.bin"),
            malicious: verdict == ScanVerdict::Malicious,
            reason: reason.to_string(),
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
            duration_ms,
        };
        if matches!(verdict, ScanVerdict::Error | ScanVerdict::Skipped) {
            result.error = Some("unavailable".to_string());
        }
        AttributionRecord::from_scan_result(&result, None, None, None).with_label(label)
    }

    #[test]
    fn high_confidence_override_is_recorded_as_an_authoritative_gate() {
        // The override decides only because a named evidence score crossed a
        // published threshold. The record has to keep both facts separable:
        // which engine scored (evidence) and what let it decide alone (gate).
        let mut result = ScanResult {
            path: PathBuf::from("sample.bin"),
            malicious: true,
            reason: "fusion:high_confidence_override:stage=intervene:source=heuristic:score=0.85:threshold=0.80"
                .to_string(),
            yara_matches: Vec::new(),
            heuristic_score: Some(0.85),
            heuristic_indicators: vec!["api_injection_chain".to_string()],
            ai_score: Some(0.30),
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
        result.malicious = true;
        let record = AttributionRecord::from_scan_result(&result, None, None, None);

        assert_eq!(record.fusion.branch, "high_confidence_override");
        assert_eq!(record.fusion.threshold, Some(0.80));
        assert_eq!(record.fusion.payload, vec!["heuristic".to_string()]);
        assert_eq!(record.fusion.combined, Some(0.85));

        let gate = record
            .contributions
            .iter()
            .find(|item| item.source == "high_confidence_override")
            .expect("override gate is present");
        assert!(gate.fired);
        assert_eq!(gate.authority, DetectionAuthority::Authoritative);

        let heuristic = record
            .contributions
            .iter()
            .find(|item| item.source == "heuristic")
            .expect("heuristic contribution is present");
        assert_eq!(heuristic.authority, DetectionAuthority::Evidence);
        assert!(heuristic.fired);
    }

    #[test]
    fn override_gate_stays_silent_when_fusion_corroborated() {
        let record = record(
            ScanVerdict::Malicious,
            "fusion:static_high:stage=intervene:heuristic=1.00:ai=0.47:strongest=1.00",
            Some(true),
            1,
        );
        let gate = record
            .contributions
            .iter()
            .find(|item| item.source == "high_confidence_override")
            .expect("override gate is always reported");
        assert!(!gate.fired, "a corroborated branch must not look overridden");
    }

    impl AttributionRecord {
        fn with_label(mut self, label: Option<bool>) -> Self {
            self.is_malicious = label;
            self
        }
    }

    #[test]
    fn parses_every_fusion_branch_shape() {
        let cases: &[(&str, &str, Option<&str>)] = &[
            (
                "fusion:driver:stage=intervene:driver blocked image load",
                "driver",
                Some("intervene"),
            ),
            (
                "fusion:kaspersky_sequence:stage=intervene:ransom_chain,exfil_chain",
                "kaspersky_sequence",
                Some("intervene"),
            ),
            (
                "fusion:kaspersky_sequence_tolerant:stage=correlate:events=3:score=0.42:a,b",
                "kaspersky_sequence_tolerant",
                Some("correlate"),
            ),
            (
                "fusion:atc:0.76:stage=intervene:evidence=2:ind_a,ind_b",
                "atc",
                Some("intervene"),
            ),
            (
                "fusion:static_high:stage=correlate:heuristic=0.90:ai=0.20:strongest=0.90",
                "static_high",
                Some("correlate"),
            ),
            (
                "fusion:static:stage=correlate:heuristic=0.76:ai=0.31:combined=0.49:corroboration=0.31",
                "static",
                Some("correlate"),
            ),
            (
                "fusion:sandbox_flags:stage=intervene:files_changed,network_activity",
                "sandbox_flags",
                Some("intervene"),
            ),
            (
                "fusion:hips:stage=correlate:evidence=2:rwx region|api patch",
                "hips",
                Some("correlate"),
            ),
        ];

        for &(reason, branch, stage) in cases {
            let parsed = FusionBreakdown::parse(reason);
            assert_eq!(parsed.branch, branch, "branch for {reason}");
            assert_eq!(parsed.stage.as_deref(), stage, "stage for {reason}");
            assert_eq!(parsed.raw, reason);
        }
    }

    #[test]
    fn parses_static_branch_numbers() {
        let parsed = FusionBreakdown::parse(
            "fusion:static:stage=correlate:heuristic=0.76:ai=0.31:combined=0.49:corroboration=0.31",
        );
        assert_eq!(parsed.heuristic, Some(0.76));
        assert_eq!(parsed.ai, Some(0.31));
        assert_eq!(parsed.combined, Some(0.49));
        assert_eq!(parsed.corroboration, Some(0.31));
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn parses_atc_leading_score_and_payload() {
        let parsed = FusionBreakdown::parse("fusion:atc:0.76:stage=intervene:evidence=2:a,b");
        assert_eq!(parsed.branch, "atc");
        assert_eq!(parsed.combined, Some(0.76));
        assert_eq!(parsed.evidence, Some(2));
        assert_eq!(parsed.payload, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn keeps_hips_payload_that_contains_colons() {
        let parsed = FusionBreakdown::parse(
            "fusion:hips:stage=correlate:evidence=2:module baseline violation in pid 42|api patch",
        );
        assert_eq!(parsed.branch, "hips");
        assert_eq!(parsed.evidence, Some(2));
        assert_eq!(parsed.payload.len(), 2);
        assert!(parsed.payload[0].contains("pid 42"));
    }

    #[test]
    fn strips_cache_prefix_before_parsing() {
        let parsed = FusionBreakdown::parse(
            "cached:fusion:static:stage=correlate:heuristic=0.80:ai=0.80:combined=0.80:corroboration=0.80",
        );
        assert_eq!(parsed.branch, "static");
        assert_eq!(parsed.heuristic, Some(0.80));
        // The raw field keeps the prefix so a replayed decision is visible.
        assert!(parsed.raw.starts_with("cached:"));
    }

    #[test]
    fn non_fusion_reason_parses_to_none_branch() {
        for reason in ["clean", "hash:deadbeef", "scan_skipped_size", "cancelled"] {
            let parsed = FusionBreakdown::parse(reason);
            assert_eq!(parsed.branch, "none", "reason {reason}");
            assert_eq!(parsed.raw, reason);
        }
    }

    #[test]
    fn label_parsing_is_explicit_about_unknown() {
        assert_eq!(parse_label("malicious"), Some(true));
        assert_eq!(parse_label("MALWARE"), Some(true));
        assert_eq!(parse_label("benign"), Some(false));
        assert_eq!(parse_label(" clean "), Some(false));
        assert_eq!(parse_label("maybe"), None);
        assert_eq!(parse_label(""), None);
    }

    #[test]
    fn confusion_matrix_rates() {
        let matrix = ConfusionMatrix {
            true_positives: 8,
            false_positives: 2,
            true_negatives: 18,
            false_negatives: 2,
            undecided: 1,
        };
        assert_eq!(matrix.precision(), Some(0.8));
        assert_eq!(matrix.recall(), Some(0.8));
        assert_eq!(matrix.false_positive_rate(), Some(0.1));
        assert_eq!(matrix.false_negative_rate(), Some(0.2));
        assert_eq!(matrix.accuracy(), Some(26.0 / 30.0));
        assert!((matrix.f1().unwrap() - 0.8).abs() < 1e-9);
    }

    #[test]
    fn empty_denominator_yields_none_not_zero() {
        let matrix = ConfusionMatrix::default();
        assert_eq!(matrix.precision(), None);
        assert_eq!(matrix.recall(), None);
        assert_eq!(matrix.false_positive_rate(), None);
        assert_eq!(matrix.accuracy(), None);
        assert_eq!(matrix.f1(), None);
    }

    #[test]
    fn latency_percentiles_use_nearest_rank() {
        let stats = LatencyStats::from_durations(vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        assert_eq!(stats.count, 10);
        assert_eq!(stats.total_ms, 550);
        assert_eq!(stats.mean_ms, Some(55.0));
        assert_eq!(stats.p50_ms, Some(50.0));
        assert_eq!(stats.p95_ms, Some(100.0));
        assert_eq!(stats.max_ms, Some(100));

        let single = LatencyStats::from_durations(vec![7]);
        assert_eq!(single.p95_ms, Some(7.0));
        assert_eq!(single.p99_ms, Some(7.0));

        let empty = LatencyStats::from_durations(Vec::new());
        assert_eq!(empty.count, 0);
        assert_eq!(empty.p95_ms, None);
    }

    #[test]
    fn unlabelled_samples_are_excluded_not_counted_as_benign() {
        let records = vec![
            record(ScanVerdict::Malicious, "hash:aa", Some(true), 5),
            record(ScanVerdict::Clean, "clean", None, 5),
            record(ScanVerdict::Clean, "clean", None, 5),
        ];
        let summary = EvaluationSummary::from_records(&records);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.labelled, 1);
        assert_eq!(summary.unlabelled, 2);
        // Two unlabelled clean scans must not inflate the true-negative count.
        assert_eq!(summary.strict.true_negatives, 0);
        assert_eq!(summary.strict.true_positives, 1);
        assert_eq!(summary.strict.false_positive_rate(), None);
    }

    #[test]
    fn undecided_scans_are_excluded_from_rates() {
        let records = vec![
            record(ScanVerdict::Malicious, "hash:aa", Some(true), 1),
            record(ScanVerdict::Error, "engine_unavailable", Some(false), 1),
            record(ScanVerdict::Skipped, "scan_skipped_size", Some(false), 1),
            record(ScanVerdict::Clean, "clean", Some(false), 1),
        ];
        let summary = EvaluationSummary::from_records(&records);
        assert_eq!(summary.strict.undecided, 2);
        assert_eq!(summary.strict.true_positives, 1);
        assert_eq!(summary.strict.true_negatives, 1);
        assert_eq!(summary.strict.false_positives, 0);
    }

    #[test]
    fn completed_scan_with_no_signal_counts_as_a_negative_decision() {
        // The scanner maps a completed scan that raised nothing to
        // reason = "unknown" and deliberately refuses to call it Clean
        // ("nothing found" is not "proven clean"). For detection quality the
        // question is different: the engine raised no alarm, so the sample is
        // a negative decision and must reach the true-negative denominator.
        // Without this the FP rate is uncomputable on any real corpus.
        let records = vec![
            record(ScanVerdict::Incomplete, "unknown", Some(false), 1),
            record(ScanVerdict::Incomplete, "unknown", Some(true), 1),
        ];
        let summary = EvaluationSummary::from_records(&records);
        assert_eq!(summary.strict.undecided, 0);
        assert_eq!(summary.strict.true_negatives, 1);
        assert_eq!(summary.strict.false_negatives, 1);
        assert_eq!(summary.strict.false_positive_rate(), Some(0.0));
    }

    #[test]
    fn incomplete_with_an_error_stays_undecided() {
        // engine_unavailable / sandbox_unverified mean nothing was evaluated.
        let mut degraded = record(ScanVerdict::Incomplete, "sandbox_unavailable", Some(false), 1);
        degraded.error = Some("sandbox_unavailable".to_string());
        let summary = EvaluationSummary::from_records(&[degraded]);
        assert_eq!(summary.strict.undecided, 1);
        assert_eq!(summary.strict.true_negatives, 0);
        assert_eq!(summary.strict.false_positive_rate(), None);
    }

    #[test]
    fn suspicious_is_a_false_negative_strict_and_true_positive_tolerant() {
        let records = vec![record(
            ScanVerdict::Suspicious,
            "fusion:static:stage=correlate:heuristic=0.72:ai=0.60:combined=0.65:corroboration=0.60",
            Some(true),
            1,
        )];
        let summary = EvaluationSummary::from_records(&records);
        assert_eq!(summary.strict.false_negatives, 1);
        assert_eq!(summary.strict.true_positives, 0);
        assert_eq!(summary.tolerant.true_positives, 1);
        assert_eq!(summary.tolerant.false_negatives, 0);
    }

    #[test]
    fn false_positive_attribution_names_the_branch_and_rule() {
        let result = ScanResult {
            path: PathBuf::from("installer.exe"),
            malicious: true,
            reason: "fusion:static:stage=intervene:heuristic=0.91:ai=0.55:combined=0.69:corroboration=0.55"
                .to_string(),
            yara_matches: Vec::new(),
            heuristic_score: Some(0.91),
            heuristic_indicators: vec![
                "api_injection_chain".to_string(),
                "many_sections: 12".to_string(),
                "api_injection_chain".to_string(),
            ],
            ai_score: Some(0.55),
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
            duration_ms: 12,
        };

        let attribution = AttributionRecord::from_scan_result(
            &result,
            Some("benign"),
            None,
            Some("green_software"),
        );

        let summary = EvaluationSummary::from_records(&[attribution]);
        assert_eq!(summary.strict.false_positives, 1);
        assert_eq!(summary.fusion_branches.get("static"), Some(&1));
        assert_eq!(
            summary
                .branch_by_category
                .get("green_software")
                .and_then(|branches| branches.get("static")),
            Some(&1)
        );
        assert_eq!(summary.false_positive_sources.get("heuristic"), Some(&1));
        // A rule firing twice inside one sample is still one false positive.
        assert_eq!(
            summary.false_positive_indicators.get("api_injection_chain"),
            Some(&1)
        );
        assert_eq!(summary.false_positive_indicators.get("many_sections"), Some(&1));
    }

    #[test]
    fn gate_reports_each_breached_limit() {
        let records = vec![
            record(ScanVerdict::Malicious, "hash:aa", Some(false), 900),
            record(ScanVerdict::Clean, "clean", Some(true), 10),
        ];
        let summary = EvaluationSummary::from_records(&records);
        let failures = summary.gate_failures(&GateLimits {
            max_fp_rate: Some(0.0),
            max_fn_rate: Some(0.0),
            max_p95_ms: Some(100.0),
            min_labelled: Some(10),
        });
        assert_eq!(failures.len(), 4, "got {failures:?}");
        assert!(failures.iter().any(|item| item.contains("false positive rate")));
        assert!(failures.iter().any(|item| item.contains("false negative rate")));
        assert!(failures.iter().any(|item| item.contains("p95 latency")));
        assert!(failures.iter().any(|item| item.contains("labelled sample")));
    }

    #[test]
    fn gate_passes_when_limits_are_disabled() {
        let records = vec![record(ScanVerdict::Malicious, "hash:aa", Some(false), 900)];
        let summary = EvaluationSummary::from_records(&records);
        assert!(summary.gate_failures(&GateLimits::default()).is_empty());
    }

    #[test]
    fn authority_and_confidence_are_independent_axes() {
        // An exact hash is both authoritative and deterministic...
        assert_eq!(
            source_profile("hash"),
            (DetectionAuthority::Authoritative, ConfidenceBasis::Deterministic)
        );
        // ...while a YARA rule is equally authoritative but only as good as the
        // rule, which is exactly the case a single "trust" score hides.
        assert_eq!(
            source_profile("yara"),
            (DetectionAuthority::Authoritative, ConfidenceBasis::Signature)
        );
        assert_eq!(
            source_profile("heuristic"),
            (DetectionAuthority::Evidence, ConfidenceBasis::RuleSum)
        );
        assert_eq!(
            source_profile("ai"),
            (DetectionAuthority::Evidence, ConfidenceBasis::Model)
        );
    }

    #[test]
    fn serialises_to_the_documented_shape() {
        let records = vec![record(
            ScanVerdict::Malicious,
            "fusion:static:stage=intervene:heuristic=0.91:ai=0.55:combined=0.69:corroboration=0.55",
            Some(true),
            12,
        )];
        let summary = EvaluationSummary::from_records(&records);
        let json = serde_json::to_value(&summary).expect("summary serialises");
        assert_eq!(json["schema"], ATTRIBUTION_SCHEMA_VERSION);
        assert_eq!(json["strict"]["true_positives"], 1);
        assert_eq!(json["fusion_branches"]["static"], 1);
        assert!(json["latency"]["p95_ms"].is_number());
    }
}
