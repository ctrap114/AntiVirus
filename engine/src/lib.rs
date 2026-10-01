//! Public library surface for the EverbloomSecurity engine.
//!
//! The binary, examples, GUI bridge and integration tests all depend on this
//! crate root. Keep module exports explicit so a clean build does not depend
//! on stale artifacts from a previous `target` directory.

pub mod allowlist;
pub mod amsi;
pub mod attribution;
pub mod driver_bridge;
pub mod driver_integrity;
pub mod hips;
pub mod ipc;
pub mod layers;
pub mod logging;
pub mod metrics;
pub mod model_converter;
pub mod monitoring;
pub mod ndjson;
pub mod onnx_export;
pub mod protection_rules;
pub mod protection_state;
pub mod public_feeds;
pub mod quarantine;
pub mod crypto;
pub mod features;
pub mod watchdog;
pub mod sandbox;
pub mod scanner;
pub mod stealer_guard;
pub mod training;
pub mod report;

pub use allowlist::Allowlist;
pub use attribution::{
    parse_label, source_profile, AttributionRecord, ConfidenceBasis, ConfusionMatrix,
    DetectionAuthority, EvaluationSummary, EvidenceContribution, FusionBreakdown, GateLimits,
    LatencyStats, ATTRIBUTION_SCHEMA_VERSION,
};
pub use ipc::IpcServer;
pub use layers::ai::{
    ai_inference_error_count, AiModel, AiModelInfo, AiModelKind, AiModelValidationReport,
    EnsembleStrategy,
};
pub use layers::behavior::BehavioralScorer;
pub use layers::cache::ScanCache;
pub use layers::hash::HashMatcher;
pub use layers::sequence::SequenceMatcher;
pub use layers::threat_intel::ThreatIntelMatcher;
pub use layers::yara::YaraScanner;
pub use model_converter::{ModelConversionError, ModelConversionOptions, ModelConversionReport};
pub use protection_rules::apply_configured_protection_rules;
pub use scanner::{ScanError, ScanProgress, ScanRequest, ScanResult, ScanVerdict, Scanner};
pub use watchdog::{spawn_watchdog, WatchdogConfig};
pub use crypto::{
    compute_tag_custom, decrypt_payload, derive_key, encrypt_payload,
    generate_nonce, verify_tag_custom, EverbloomCipher, CUSTOM_SBOX,
};
pub use features::{default_feature_dir, feature_metadata_path, FeatureMetadata, FeatureVector, dynamic_dims, static_dims};
pub use report::{ScanReport, ScanReportEntry, ReportSummary, EncryptedReport};
pub use amsi::{AmsiContext, AmsiSession, AmsiVerdict, AmsiStats, amsi_stats, scan_file_with_amsi};
