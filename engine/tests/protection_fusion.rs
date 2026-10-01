use everbloom_engine::layers::behavior::{BehaviorEvent, BehaviorEventKind};
use everbloom_engine::layers::fusion::{
    FusionDecision, FusionInput, FusionResponseLevel, ProtectionFusion,
};

fn build_input(
    score: Option<f32>,
    seq_matches: Option<Vec<String>>,
    sandbox_flags: Vec<String>,
) -> FusionInput {
    FusionInput {
        path: "C:\\sample.exe".to_string(),
        sandbox_report: None,
        behavior_score: score.map(
            |score| everbloom_engine::layers::behavior::BehaviorScoreResult {
                process_id: Some(1000),
                score,
                matched_indicators: vec!["test-indicator".to_string()],
            },
        ),
        sequence_matches: seq_matches,
        tolerant_sequence_matches: None,
        sandbox_flags,
        heuristic_score: None,
        ai_score: None,
        ai_threshold: Some(0.9),
        events: vec![BehaviorEvent {
            kind: BehaviorEventKind::SuspiciousApiCall,
            detail: "test-api".to_string(),
            process_id: Some(1000),
        }],
        hips_alerts: vec![],
    }
}

#[test]
fn aggressive_fusion_triggers_on_behavior_score() {
    let fusion = ProtectionFusion::new().with_response_level(FusionResponseLevel::Aggressive);
    let input = build_input(Some(0.6), None, vec![]);

    match fusion.evaluate(&input) {
        FusionDecision::Malicious { reason, rollback } => {
            assert!(reason.starts_with("fusion:atc:"));
            assert!(rollback);
        }
        FusionDecision::Suspicious { .. } => panic!("aggressive behavior must intervene"),
        FusionDecision::Clean => panic!("expected fusion to detect malicious input"),
    }
}

#[test]
fn sequence_matches_always_raise_malicious() {
    let fusion = ProtectionFusion::new().with_response_level(FusionResponseLevel::Relaxed);
    let input = build_input(None, Some(vec!["persistence-chain".to_string()]), vec![]);

    match fusion.evaluate(&input) {
        FusionDecision::Malicious { reason, rollback } => {
            assert!(reason.starts_with("fusion:kaspersky_sequence:"));
            assert!(rollback);
        }
        FusionDecision::Suspicious { .. } => panic!("ordered sequence must intervene"),
        FusionDecision::Clean => panic!("expected sequence fusion to detect malicious input"),
    }
}

#[test]
fn relaxed_fusion_ignores_sandbox_flags() {
    let fusion = ProtectionFusion::new().with_response_level(FusionResponseLevel::Relaxed);
    let input = build_input(None, None, vec!["network_activity".to_string()]);

    assert!(matches!(fusion.evaluate(&input), FusionDecision::Clean));
}

#[test]
fn static_engine_agreement_enters_correlation_stage() {
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, None, vec![]);
    input.heuristic_score = Some(0.70);
    input.ai_score = Some(0.72);

    match fusion.evaluate(&input) {
        FusionDecision::Suspicious { reason } => {
            assert!(reason.starts_with("fusion:static:stage=correlate:"));
        }
        FusionDecision::Malicious { .. } => {
            panic!("moderate static agreement should correlate first")
        }
        FusionDecision::Clean => panic!("expected independent static engines to correlate"),
    }
}

#[test]
fn high_confidence_single_static_engine_is_not_averaged_into_clean() {
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, None, vec![]);
    input.heuristic_score = Some(0.94);
    input.ai_score = Some(0.08);

    assert!(matches!(
        fusion.evaluate(&input),
        FusionDecision::Suspicious { reason } if reason.starts_with("fusion:static_high:")
    ));
}

#[test]
fn high_confidence_heuristic_override_decides_without_corroboration() {
    // 0.85 clears the published override threshold but not the 0.90
    // static-high gate, and the AI arm is far below the corroboration floor,
    // so only the override can explain a Malicious verdict here.
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, None, vec![]);
    input.heuristic_score = Some(0.85);
    input.ai_score = Some(0.30);

    match fusion.evaluate(&input) {
        FusionDecision::Malicious { reason, rollback } => {
            assert!(reason.starts_with("fusion:high_confidence_override:"));
            assert!(reason.contains("source=heuristic"), "reason={reason}");
            assert!(reason.contains("threshold=0.80"), "reason={reason}");
            assert!(!rollback, "a score is evidence, not an enforcement result");
        }
        FusionDecision::Suspicious { .. } => panic!("0.85 must decide on its own"),
        FusionDecision::Clean => panic!("expected the override to fire"),
    }
}

#[test]
fn high_confidence_override_uses_the_request_ai_threshold() {
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, None, vec![]);
    input.heuristic_score = None;
    input.ai_score = Some(0.93);
    input.ai_threshold = Some(0.9);
    assert!(matches!(
        fusion.evaluate(&input),
        FusionDecision::Malicious { ref reason, .. }
            if reason.starts_with("fusion:high_confidence_override:")
                && reason.contains("source=ai")
    ));

    // The same score must stay undecided when the caller asked for a stricter
    // threshold: the AI arm is request-scoped, not a hard-coded constant.
    input.ai_threshold = Some(0.99);
    assert!(matches!(fusion.evaluate(&input), FusionDecision::Clean));
}

#[test]
fn below_the_override_threshold_fusion_still_returns_undecided() {
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, None, vec![]);
    input.heuristic_score = Some(0.79);
    input.ai_score = Some(0.10);
    assert!(matches!(fusion.evaluate(&input), FusionDecision::Clean));
}

#[test]
fn override_never_preempts_a_corroborated_branch() {
    // A strict sequence match is an enforcement signal; the override must not
    // steal its reason even when the heuristic score is also above 0.80.
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, Some(vec!["persistence-chain".to_string()]), vec![]);
    input.heuristic_score = Some(0.99);

    assert!(matches!(
        fusion.evaluate(&input),
        FusionDecision::Malicious { ref reason, .. }
            if reason.starts_with("fusion:kaspersky_sequence:")
    ));
}

#[test]
fn driver_block_is_authoritative_even_in_relaxed_mode() {
    let fusion = ProtectionFusion::new().with_response_level(FusionResponseLevel::Relaxed);
    let mut input = build_input(None, None, vec![]);
    input.hips_alerts =
        vec!["Driver blocked HIPS event in pid 1000 request=7 action=4".to_string()];

    match fusion.evaluate(&input) {
        FusionDecision::Malicious { reason, rollback } => {
            assert!(reason.starts_with("fusion:driver:stage=intervene:"));
            assert!(rollback);
        }
        FusionDecision::Suspicious { .. } => panic!("driver block must intervene"),
        FusionDecision::Clean => panic!("driver block must remain authoritative"),
    }
}

#[test]
fn one_weak_hips_alert_only_enters_correlation() {
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, None, vec![]);
    input.hips_alerts = vec!["RWX region in pid 1000 at 0x1000 size 4096".to_string()];

    match fusion.evaluate(&input) {
        FusionDecision::Suspicious { reason } => {
            assert!(reason.starts_with("fusion:hips:stage=correlate:"));
        }
        FusionDecision::Clean => panic!("weak HIPS evidence should be retained"),
        FusionDecision::Malicious { .. } => {
            panic!("one weak HIPS alert must not intervene")
        }
    }
}

#[test]
fn side_load_and_generic_dll_origin_are_not_two_independent_signals() {
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, None, vec![]);
    input.hips_alerts = vec![
        "Suspicious DLL load in pid 1000: C:\\Users\\Alice\\AppData\\Local\\Temp\\version.dll"
            .to_string(),
        "White+black DLL side-load in pid 1000: process=C:\\Users\\Alice\\AppData\\Local\\Temp\\trusted.exe dll=C:\\Users\\Alice\\AppData\\Local\\Temp\\version.dll reason=same-directory-user-writable-module".to_string(),
    ];

    assert!(matches!(
        fusion.evaluate(&input),
        FusionDecision::Suspicious { .. }
    ));
}

#[test]
fn side_load_correlated_with_rwx_intervenes_in_normal_mode() {
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, None, vec![]);
    input.hips_alerts = vec![
        "White+black DLL side-load in pid 1000: process=C:\\Users\\Alice\\AppData\\Local\\Temp\\trusted.exe dll=C:\\Users\\Alice\\AppData\\Local\\Temp\\version.dll reason=same-directory-user-writable-module".to_string(),
        "RWX region in pid 1000 at 0x1000 size 4096".to_string(),
    ];

    match fusion.evaluate(&input) {
        FusionDecision::Malicious { reason, rollback } => {
            assert!(reason.starts_with("fusion:hips:stage=intervene:"));
            assert!(rollback);
        }
        FusionDecision::Suspicious { .. } => {
            panic!("independent injection evidence must intervene")
        }
        FusionDecision::Clean => panic!("side-load plus RWX must be retained"),
    }
}

#[test]
fn a_lone_tolerant_chain_only_correlates() {
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, None, vec![]);
    input.tolerant_sequence_matches = Some(vec![
        "credential_exfil_chain".to_string(),
    ]);

    match fusion.evaluate(&input) {
        FusionDecision::Suspicious { reason } => {
            assert!(reason.starts_with("fusion:kaspersky_sequence_tolerant:stage=correlate:"));
        }
        FusionDecision::Clean => panic!("tolerant chain evidence must be retained"),
        FusionDecision::Malicious { .. } => panic!("a lone tolerant chain must not intervene"),
    }
}

#[test]
fn tolerant_chain_corroborated_by_behavior_score_intervenes() {
    let fusion = ProtectionFusion::default();
    let mut input = build_input(Some(0.75), None, vec![]);
    input.tolerant_sequence_matches = Some(vec![
        "inject_browser_exfil_chain".to_string(),
    ]);

    match fusion.evaluate(&input) {
        FusionDecision::Malicious { reason, rollback } => {
            assert!(reason.starts_with("fusion:kaspersky_sequence_tolerant:stage=intervene:"));
            assert!(rollback);
        }
        FusionDecision::Suspicious { .. } => panic!("corroborated chain must intervene"),
        FusionDecision::Clean => panic!("corroborated chain cannot be clean"),
    }
}

#[test]
fn multiple_tolerant_chains_with_action_flags_intervene() {
    let fusion = ProtectionFusion::default();
    let mut input = build_input(None, None, vec!["files_changed".to_string()]);
    input.tolerant_sequence_matches = Some(vec![
        "dropper_c2_persist_chain".to_string(),
        "implant_post_injection_persistence".to_string(),
    ]);

    match fusion.evaluate(&input) {
        FusionDecision::Malicious { reason, .. } => {
            assert!(reason.starts_with("fusion:kaspersky_sequence_tolerant:stage=intervene:"));
        }
        FusionDecision::Suspicious { .. } => panic!("two chains with action flags must intervene"),
        FusionDecision::Clean => panic!("two chains cannot be clean"),
    }
}
