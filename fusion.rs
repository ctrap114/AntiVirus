use crate::layers::behavior::{BehaviorEvent, BehaviorScoreResult, BehavioralScorer};
use crate::layers::sequence::SequenceMatcher;
use crate::sandbox::SandboxReport;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

/// Fusion response level controls how aggressive the multi-stage fusion layer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusionResponseLevel {
    Aggressive,
    Normal,
    Relaxed,
}

impl FusionResponseLevel {
    pub fn threshold(&self) -> f32 {
        match self {
            FusionResponseLevel::Aggressive => 0.55,
            FusionResponseLevel::Normal => 0.70,
            FusionResponseLevel::Relaxed => 0.85,
        }
    }
}

/// The current step of the staged protection decision. The engine still
/// returns the existing `Clean`/`Malicious` API, while the stage is recorded in
/// the reason so callers can distinguish observation from intervention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusionStage {
    Observe,
    Correlate,
    Intervene,
    Recover,
}

impl fmt::Display for FusionStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            FusionStage::Observe => "observe",
            FusionStage::Correlate => "correlate",
            FusionStage::Intervene => "intervene",
            FusionStage::Recover => "recover",
        };
        f.write_str(value)
    }
}

/// Input data for the fusion decision engine.
#[derive(Debug, Clone)]
pub struct FusionInput {
    pub path: String,
    pub sandbox_report: Option<SandboxReport>,
    pub behavior_score: Option<BehaviorScoreResult>,
    pub sequence_matches: Option<Vec<String>>,
    /// Tolerant (in-order, gap-tolerant) multi-step chain matches. Weaker than
    /// strict sequence matches: a tolerant match alone is suspicious and is
    /// escalated only when independent evidence corroborates it.
    pub tolerant_sequence_matches: Option<Vec<String>>,
    pub sandbox_flags: Vec<String>,
    pub heuristic_score: Option<f32>,
    pub ai_score: Option<f32>,
    pub events: Vec<BehaviorEvent>,
    pub hips_alerts: Vec<String>,
}

/// Fusion result from the multi-stage protection layer.
#[derive(Debug, Clone)]
pub enum FusionDecision {
    Clean,
    /// Suspicious evidence was observed, but the configured policy requires
    /// another independent signal before intervention. Callers should retain
    /// the reason for telemetry and continue the remaining scan stages.
    Suspicious {
        reason: String,
    },
    Malicious {
        reason: String,
        rollback: bool,
    },
}

/// Protection fusion engine reserved for ATC-style scoring and Kaspersky-like
/// multi-step behavioral sequence decisioning.
pub struct ProtectionFusion {
    behavioral: Option<Arc<BehavioralScorer>>,
    sequence: Option<Arc<SequenceMatcher>>,
    response_level: FusionResponseLevel,
}

impl ProtectionFusion {
    pub fn new() -> Self {
        Self {
            behavioral: None,
            sequence: None,
            response_level: FusionResponseLevel::Normal,
        }
    }

    pub fn with_behavioral(mut self, scorer: Arc<BehavioralScorer>) -> Self {
        self.behavioral = Some(scorer);
        self
    }

    pub fn with_sequence(mut self, matcher: Arc<SequenceMatcher>) -> Self {
        self.sequence = Some(matcher);
        self
    }

    pub fn with_response_level(mut self, level: FusionResponseLevel) -> Self {
        self.response_level = level;
        self
    }

    pub fn evaluate(&self, input: &FusionInput) -> FusionDecision {
        // A driver block is an enforcement result, not merely an observation.
        // Keep it authoritative even in relaxed mode, but only accept the
        // explicit driver marker; ordinary HIPS alerts remain multi-step
        // evidence below.
        if let Some(driver_alert) = input
            .hips_alerts
            .iter()
            .find(|alert| alert.to_ascii_lowercase().contains("driver blocked"))
        {
            return FusionDecision::Malicious {
                reason: format!(
                    "fusion:driver:stage={}:{}",
                    FusionStage::Intervene,
                    driver_alert
                ),
                rollback: true,
            };
        }

        // A recognized ordered signature is the strongest user-mode
        // correlation signal: it represents multiple behavior steps rather
        // than a single suspicious API.
        if let Some(matches) = &input.sequence_matches {
            if !matches.is_empty() {
                return FusionDecision::Malicious {
                    reason: format!(
                        "fusion:kaspersky_sequence:stage={}:{}",
                        FusionStage::Intervene,
                        matches.join(",")
                    ),
                    rollback: true,
                };
            }
        }

        // Tolerant chains tolerate interleaved noise by design, so they are
        // correlation evidence rather than proof: suspicious by default and
        // escalated to intervention only when an independent signal agrees
        // (an at-threshold behavior score, several simultaneous chains backed
        // by action flags, or multiple chains with meaningful event breadth).
        if let Some(matches) = &input.tolerant_sequence_matches {
            if !matches.is_empty() {
                let score = input
                    .behavior_score
                    .as_ref()
                    .map(|value| value.score)
                    .unwrap_or(0.0);
                let independent_kinds = input
                    .events
                    .iter()
                    .map(|event| event.kind.clone())
                    .collect::<HashSet<_>>()
                    .len();
                let independent_action = input
                    .sandbox_flags
                    .iter()
                    .any(|flag| matches!(flag.as_str(), "files_changed" | "network_activity" | "registry_activity" | "api_activity" | "unpacked"));
                let escalate = score >= self.response_level.threshold()
                    || (matches.len() >= 2 && independent_action)
                    || (matches.len() >= 2 && independent_kinds >= 3)
                    || (matches.len() >= 2 && score >= 0.5);
                let stage = if escalate {
                    FusionStage::Intervene
                } else {
                    FusionStage::Correlate
                };
                let reason = format!(
                    "fusion:kaspersky_sequence_tolerant:stage={}:events={}:score={:.2}:{}",
                    stage,
                    independent_kinds,
                    score,
                    matches.join(",")
                );
                return if escalate {
                    FusionDecision::Malicious {
                        reason,
                        rollback: true,
                    }
                } else {
                    FusionDecision::Suspicious { reason }
                };
            }
        }

        if let Some(score) = &input.behavior_score {
            let score_value = score.score.clamp(0.0, 1.0);
            if score_value >= self.response_level.threshold() {
                let independent_kinds = input
                    .events
                    .iter()
                    .map(|event| event.kind.clone())
                    .collect::<HashSet<_>>()
                    .len();
                let corroborated = independent_kinds >= 2 || score.matched_indicators.len() >= 2;
                let stage = if self.response_level == FusionResponseLevel::Aggressive
                    || score_value >= 0.85
                    || corroborated
                {
                    FusionStage::Intervene
                } else {
                    FusionStage::Correlate
                };
                let reason = format!(
                    "fusion:atc:{:.2}:stage={}:evidence={}:{}",
                    score_value,
                    stage,
                    independent_kinds,
                    score.matched_indicators.join(",")
                );
                return if stage == FusionStage::Intervene {
                    FusionDecision::Malicious {
                        reason,
                        rollback: true,
                    }
                } else {
                    FusionDecision::Suspicious { reason }
                };
            }
        }

        // Do not average a high-confidence independent signal down into a
        // clean verdict. A 0.90 heuristic finding combined with a weak AI
        // score is still a strong malicious indicator; the old weighted mean
        // could turn that into 0.42 and silently discard the evidence.
        if let (Some(heuristic), Some(ai)) = (input.heuristic_score, input.ai_score) {
            let heuristic = heuristic.clamp(0.0, 1.0);
            let ai = ai.clamp(0.0, 1.0);
            let strongest = heuristic.max(ai);
            let weakest = heuristic.min(ai);
            let high_confidence = match self.response_level {
                FusionResponseLevel::Aggressive => 0.82,
                FusionResponseLevel::Normal => 0.90,
                FusionResponseLevel::Relaxed => 0.96,
            };
            if strongest >= high_confidence {
                let stage = if strongest >= 0.96 {
                    FusionStage::Intervene
                } else {
                    FusionStage::Correlate
                };
                let reason = format!(
                    "fusion:static_high:stage={}:heuristic={:.2}:ai={:.2}:strongest={:.2}",
                    stage, heuristic, ai, strongest
                );
                return if stage == FusionStage::Intervene {
                    FusionDecision::Malicious {
                        reason,
                        rollback: true,
                    }
                } else {
                    FusionDecision::Suspicious { reason }
                };
            }

            // Agreement is represented by the lower score as corroboration,
            // not by a linear average. This preserves independent evidence
            // while keeping moderate disagreement in the correlation stage.
            let corroborated = weakest >= self.response_level.threshold() * 0.70;
            let combined = heuristic * 0.4 + ai * 0.6;
            if corroborated && strongest >= self.response_level.threshold() {
                let stage = if strongest >= 0.85 && combined >= 0.75 {
                    FusionStage::Intervene
                } else {
                    FusionStage::Correlate
                };
                let reason = format!(
                    "fusion:static:stage={}:heuristic={:.2}:ai={:.2}:combined={:.2}:corroboration={:.2}",
                    stage, heuristic, ai, combined, weakest
                );
                return if stage == FusionStage::Intervene {
                    FusionDecision::Malicious {
                        reason,
                        rollback: true,
                    }
                } else {
                    FusionDecision::Suspicious { reason }
                };
            }
        }

        if !input.sandbox_flags.is_empty() && self.response_level == FusionResponseLevel::Aggressive
        {
            return FusionDecision::Malicious {
                reason: format!(
                    "fusion:sandbox_flags:stage={}:{}",
                    FusionStage::Intervene,
                    input.sandbox_flags.join(",")
                ),
                rollback: false,
            };
        }

        if !input.hips_alerts.is_empty() {
            let alerts = input.hips_alerts.iter().cloned().collect::<HashSet<_>>();
            let families = alerts
                .iter()
                .map(|alert| hips_alert_family(alert))
                .collect::<HashSet<_>>();
            let stage =
                if families.len() >= 2 && self.response_level != FusionResponseLevel::Relaxed {
                    FusionStage::Intervene
                } else {
                    FusionStage::Correlate
                };
            let reason = format!(
                "fusion:hips:stage={}:evidence={}:{}",
                stage,
                families.len(),
                alerts.into_iter().collect::<Vec<_>>().join("|")
            );
            return if stage == FusionStage::Intervene {
                FusionDecision::Malicious {
                    reason,
                    rollback: true,
                }
            } else {
                FusionDecision::Suspicious { reason }
            };
        }

        FusionDecision::Clean
    }
}

/// Collapse descriptions into evidence families before counting them. A
/// side-load and a generic DLL-origin alert usually describe the same module
/// observation, so they must not be counted as two independent signals. RWX,
/// API patching, thread-stack anomalies, and driver decisions remain separate
/// injection/protection families and can corroborate a side-load.
fn hips_alert_family(alert: &str) -> String {
    let lower = alert.to_ascii_lowercase();
    if lower.contains("module baseline violation") {
        return "module_baseline".to_string();
    }
    if lower.contains("dll") && (lower.contains("load") || lower.contains("side-load")) {
        return "module_origin".to_string();
    }
    if lower.contains("rwx region") || lower.contains("high-entropy private executable memory") {
        return "memory_execution".to_string();
    }
    if lower.contains("apc injection") {
        return "apc_injection".to_string();
    }
    if lower.contains("poolparty") || lower.contains("thread-pool injection") {
        return "threadpool_injection".to_string();
    }
    if lower.contains("reflective pe") {
        return "reflective_pe".to_string();
    }
    if lower.contains("ppl process") {
        return "ppl_abuse".to_string();
    }
    if lower.contains("api patch") {
        return "api_patch".to_string();
    }
    if lower.contains("thread stack") {
        return "thread_stack".to_string();
    }
    if lower.contains("process inject") || lower.contains("process injection") {
        return "process_injection".to_string();
    }
    if lower.contains("cookie") && lower.contains("suspected") {
        return "browser_credential_access".to_string();
    }
    if lower.contains("driver blocked") {
        return "driver_enforcement".to_string();
    }
    alert
        .split(" in pid")
        .next()
        .and_then(|family| family.split(" (pid=").next())
        .unwrap_or(alert)
        .to_string()
}

impl Default for ProtectionFusion {
    fn default() -> Self {
        Self::new()
    }
}
