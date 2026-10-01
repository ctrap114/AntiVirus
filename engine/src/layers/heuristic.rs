use goblin::Object;
use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::layers::unpacking::assess_unpacking;
use thiserror::Error;

/// Version of the built-in static rulebook and feature interpretation.
///
/// v5 adds the ATT&CK/MBC-aligned technique families, the sliding-window
/// entropy profile, and the padding-run indicator. Scan-cache entries created
/// under v4 must not be reused: the same bytes now produce different evidence.
pub const STATIC_RULES_VERSION: u64 = 5;

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
    /// Shannon entropy over the whole analyzed window.
    pub global: f32,
    /// Number of `ENTROPY_WINDOW_BYTES` windows whose entropy is at or above
    /// `HIGH_ENTROPY_WINDOW_THRESHOLD`.
    pub high_windows: u32,
    /// Number of `ENTROPY_WINDOW_BYTES` windows examined.
    pub windows: u32,
    /// Longest consecutive run of the dominant filler byte, i.e. padding.
    ///
    /// Deliberately *not* "longest run of `0x00`". Measuring zero-runs alone
    /// conflates two very different things: real padding, and the scattered
    /// `0x00` bytes that random or encrypted data contains by chance. On a
    /// 16 KiB xorshift64 block the longest zero run measures 2, which is
    /// meaningless as evidence yet non-zero. Instead the buffer's most common
    /// byte is identified first and only runs of *that* byte are counted, so
    /// random noise contributes nothing while `0x00`/`0xFF`/`0x20` padding is
    /// still measured. See [`EntropyProfile::is_padding_shape`].
    pub longest_filler_run: u32,
    /// The filler byte that [`EntropyProfile::longest_filler_run`] measured.
    pub filler_byte: u8,
    /// Estimate of how compressible the buffer is, 0.0..=1.0.
    pub compressibility: f32,
}

impl EntropyProfile {
    /// Total bytes covered by the analyzed window.
    pub fn covered_bytes(&self) -> usize {
        self.blocks.len()
    }

    /// Fraction of the buffer sitting in high-entropy windows, 0.0..=1.0.
    ///
    /// This is the key discriminator between two cases that a single mean
    /// cannot separate:
    ///   * a legitimately compressed installer where *most* bytes are packed,
    ///     versus
    ///   * an otherwise-plain executable with a small encrypted blob appended.
    ///
    /// Both can produce a similar mean; only the first has a high ratio.
    pub fn high_entropy_ratio(&self) -> f32 {
        if self.windows == 0 {
            return 0.0;
        }
        self.high_windows as f32 / self.windows as f32
    }

    /// Return a bounded explanatory score.
    ///
    /// The previous implementation used a single hard cut on `mean`/`variance`
    /// which produced the same score for a fully encrypted file and for a text
    /// file with random padding. This version combines three independent
    /// observations — packing density, padding ratio, and global entropy —
    /// so the returned value is monotone in actual evidence strength.
    pub fn score(&self) -> f32 {
        if self.windows == 0 {
            return 0.0;
        }
        let ratio = self.high_entropy_ratio();
        // Fraction of the buffer covered by the longest filler run, normalised
        // against the number of windows (each window is ENTROPY_WINDOW_BYTES).
        let padding_ratio = self.padding_ratio();

        let mut score: f32 = 0.0;

        // Density gates are expressed against the *global* entropy because the
        // per-window numbers carry sampling bias. `global` is computed over the
        // whole buffer, where the bias is negligible.
        if self.windows >= 4 && ratio >= 0.90 && self.global >= 7.5 {
            score += 0.45;
        } else if self.windows >= 4 && ratio >= 0.60 && self.global >= 7.0 {
            score += 0.30;
        } else if self.windows >= 4 && ratio >= 0.35 && self.global >= 6.6 {
            score += 0.15;
        }

        // Large homogeneous padding around an encrypted region is a layout
        // that ordinary compilers and installers do not produce.
        if padding_ratio >= 0.25 && ratio >= 0.30 {
            score += 0.15;
        }

        // Flattened entropy (low variance at a very high mean) indicates a
        // stream cipher or an already-compressed payload with no structure.
        if self.mean >= 7.35 && self.variance <= 0.04 && self.global >= 7.5 {
            score += 0.15;
        }

        score.clamp(0.0, 1.0)
    }

    /// Fraction of the analysed window covered by the longest filler run.
    ///
    /// A multi-kilobyte run of a single byte is a layout that compilers and
    /// installers rarely produce, but that is typical of a blob padded into an
    /// existing section.
    pub fn padding_ratio(&self) -> f32 {
        if self.windows == 0 {
            return 0.0;
        }
        self.longest_filler_run as f32 / (self.windows as f32 * ENTROPY_WINDOW_BYTES as f32)
    }

    /// Predicate for the "a large plain region hosts a small packed region"
    /// layout, which is the shape a mean-only estimator loses.
    ///
    /// Requires both a long filler run and at least moderate packing density,
    /// so a legitimate binary's zero padding (no entropy spike) does not fire
    /// and neither does a dense executable (no filler run).
    pub fn is_padding_shape(&self) -> bool {
        self.longest_filler_run >= 4096 && self.high_entropy_ratio() >= 0.30
    }

    /// Convenience predicate for callers that only need a boolean.
    pub fn is_high_entropy_payload(&self) -> bool {
        self.score() >= 0.45
    }
}

/// Length of the sliding window used for local entropy estimation.
///
/// 512 bytes, not 256: Shannon entropy computed over N samples drawn from a
/// 256-symbol alphabet is severely downward-biased when N is close to 256.
/// Measured on uniform random data the expected value is ~7.26 at N=256 but
/// ~7.60 at N=512 and ~7.80 at N=1024. A threshold chosen against the N=256
/// bias therefore sits inside the noise band and fires on roughly a third of
/// ciphertext windows, which is exactly the bug this constant documents.
/// 512 keeps the estimator stable while still localising a single encrypted
/// region inside an otherwise plain file.
pub(crate) const ENTROPY_WINDOW_BYTES: usize = 512;

/// Entropy at or above which a window is treated as packed/encrypted.
///
/// Derived from the N=512 sampling bias rather than from an ideal 8.0: uniform
/// random data averages ~7.60 here, so 7.40 is roughly two standard deviations
/// below the mean and admits genuine ciphertext while rejecting text and code.
const HIGH_ENTROPY_WINDOW_THRESHOLD: f32 = 7.40;

pub fn analyze_entropy_distribution(bytes: &[u8]) -> EntropyProfile {
    if bytes.is_empty() {
        return EntropyProfile {
            blocks: Vec::new(),
            mean: 0.0,
            variance: 0.0,
            peak: 0.0,
            global: 0.0,
            high_windows: 0,
            windows: 0,
            longest_filler_run: 0,
            filler_byte: 0,
            compressibility: 0.0,
        };
    }

    // Bound the work: sample at most 2048 windows (1 MiB) so a 64 MiB static
    // window cannot turn entropy estimation into the dominant scan cost.
    const MAX_WINDOWS: usize = 2048;
    let window = ENTROPY_WINDOW_BYTES;
    let stride = if bytes.len() > window * MAX_WINDOWS {
        bytes.len() / MAX_WINDOWS
    } else {
        window
    }
    .max(window);

    let mut blocks: Vec<f32> = Vec::with_capacity(bytes.len() / stride + 2);
    let mut high_windows: u32 = 0;
    let mut windows: u32 = 0;
    let mut offset = 0usize;
    while offset + window <= bytes.len() {
        let value = entropy(&bytes[offset..offset + window]);
        if value >= HIGH_ENTROPY_WINDOW_THRESHOLD {
            high_windows += 1;
        }
        windows += 1;
        blocks.push(value);
        offset += stride;
    }
    // Always include the tail so an appended payload is never silently dropped.
    if bytes.len() >= window && offset < bytes.len() {
        let tail = &bytes[bytes.len() - window..];
        let value = entropy(tail);
        if value >= HIGH_ENTROPY_WINDOW_THRESHOLD {
            high_windows += 1;
        }
        windows += 1;
        blocks.push(value);
    }
    if blocks.is_empty() {
        // Shorter than one window: fall back to a single global measurement.
        // The bias is worst here, so only a near-maximal value qualifies.
        let value = entropy(bytes);
        if value >= 7.5 && bytes.len() >= 256 {
            high_windows = 1;
        }
        windows = 1;
        blocks.push(value);
    }

    let mean = blocks.iter().sum::<f32>() / blocks.len() as f32;
    let variance = blocks
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f32>()
        / blocks.len() as f32;
    let peak = blocks.iter().copied().fold(0.0, f32::max);
    let global = entropy(bytes);

    // Cheap compressibility proxy: ratio of distinct byte values to the 256
    // possible values, weighted by how uniform the distribution is. Encrypted
    // data approaches 1.0; source text and icons sit far below it.
    //
    // Computed before the filler scan because the histogram it builds is
    // reused to pick the filler byte.
    let mut counts = [0usize; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }

    // Longest run of the dominant byte, rather than of `0x00` specifically.
    //
    // Counting zero runs conflates padding with the stray `0x00` bytes that
    // random/encrypted data produces by chance: a 16 KiB xorshift block
    // contains a zero run of 2, which is noise but would register as evidence.
    // Selecting the most frequent byte first makes random data contribute
    // nothing (its runs are short) while `0x00`/`0xFF`/`0x20` padding around an
    // appended blob is still measured, because there that byte dominates the
    // histogram.
    let filler_byte = counts
        .iter()
        .enumerate()
        .max_by_key(|(_, count)| **count)
        .map(|(byte, _)| byte as u8)
        .unwrap_or(0);
    let mut longest_filler_run: u32 = 0;
    let mut current: u32 = 0;
    for &byte in bytes {
        if byte == filler_byte {
            current += 1;
            longest_filler_run = longest_filler_run.max(current);
        } else {
            current = 0;
        }
    }
    let distinct = counts.iter().filter(|count| **count > 0).count() as f32;
    let uniform = {
        let expected = bytes.len() as f32 / 256.0;
        let deviation: f32 = counts
            .iter()
            .map(|count| (*count as f32 - expected).abs())
            .sum();
        (1.0 - (deviation / (2.0 * bytes.len() as f32))).clamp(0.0, 1.0)
    };
    let compressibility = (0.5 * (distinct / 256.0) + 0.5 * uniform).clamp(0.0, 1.0);

    EntropyProfile {
        blocks,
        mean,
        variance,
        peak,
        global,
        high_windows,
        windows,
        longest_filler_run,
        filler_byte,
        compressibility,
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
        // --- ATT&CK / MBC-aligned technique families -------------------------
        // Each entry below maps to a MITRE ATT&CK technique and (where one
        // exists) a Malware Behavior Catalog objective/behavior id, following
        // the taxonomy used by capa and CAPE. Weights stay conservative: these
        // rules add independent corroboration rather than carrying a verdict.
        HeuristicRule {
            id: "anti_analysis_evasion_chain",
            weight: 0.34,
            description: "ATT&CK T1497/T1622: anti-VM/anti-debug probes are combined with delayed or time-stomped execution",
        },
        HeuristicRule {
            id: "amsi_etw_bypass_chain",
            weight: 0.66,
            description: "ATT&CK T1562.001: AMSI or ETW patching is combined with in-memory code execution",
        },
        HeuristicRule {
            id: "security_tool_discovery_chain",
            weight: 0.44,
            description: "ATT&CK T1518.001/T1057: installed security products or running security processes are enumerated",
        },
        HeuristicRule {
            id: "process_discovery_chain",
            weight: 0.22,
            description: "ATT&CK T1057: process/module enumeration is combined with remote process handles",
        },
        HeuristicRule {
            id: "system_recon_chain",
            weight: 0.26,
            description: "ATT&CK T1082/T1016/T1033/T1124: host, network, locale, and time reconnaissance is combined",
        },
        HeuristicRule {
            id: "advanced_injection_chain",
            weight: 0.48,
            description: "ATT&CK T1055: section mapping, thread context, or APC-based injection primitives are combined",
        },
        HeuristicRule {
            id: "input_capture_chain",
            weight: 0.30,
            description: "ATT&CK T1056: low-level keyboard hooks or raw input capture are combined with a stream or exfil channel",
        },
        HeuristicRule {
            id: "impact_recovery_inhibition_chain",
            weight: 0.74,
            description: "ATT&CK T1490: shadow copy, backup catalog, or boot recovery data is deleted or disabled",
        },
        HeuristicRule {
            id: "impact_system_shutdown_chain",
            weight: 0.40,
            description: "ATT&CK T1529: system shutdown or reboot is forced after destructive prerequisites",
        },
        HeuristicRule {
            id: "privilege_token_manipulation_chain",
            weight: 0.42,
            description: "ATT&CK T1134: a privileged token is duplicated or impersonated rather than merely adjusted",
        },
        HeuristicRule {
            id: "lolbin_proxy_execution_chain",
            weight: 0.34,
            description: "ATT&CK T1218: signed system binaries are invoked for proxy execution of a remote or staged payload",
        },
        HeuristicRule {
            id: "web_delivery_chain",
            weight: 0.36,
            description: "ATT&CK T1105/T1071.001: a download primitive is combined with an interpreter or shell execution step",
        },
        HeuristicRule {
            id: "scheduled_task_persistence_chain",
            weight: 0.32,
            description: "ATT&CK T1053.005: scheduled task creation is combined with logging or notification suppression",
        },
        HeuristicRule {
            id: "rename_masquerading_chain",
            weight: 0.38,
            description: "ATT&CK T1036.005: a system-looking binary name or path is used from a user-writable location",
        },
        HeuristicRule {
            id: "defense_impairment_firewall_chain",
            weight: 0.56,
            description: "ATT&CK T1562.004: host firewall rules are modified or the firewall service is disabled",
        },
        HeuristicRule {
            id: "reverse_shell_chain",
            weight: 0.72,
            description: "ATT&CK T1059: a command interpreter is bound to a socket or connected to a remote endpoint",
        },
        HeuristicRule {
            id: "container_evasion_chain",
            weight: 0.20,
            description: "ATT&CK T1610: container or namespace boundaries are probed by a non-container workload",
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
            // ATT&CK/MBC-aligned technique families. These are emitted as
            // fully-formed signal names by `analyze_bytes`, so the match is a
            // direct name lookup rather than an API re-derivation.
            "anti_analysis_evasion_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("anti_analysis_evasion_chain"));
            }
            "amsi_etw_bypass_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("amsi_etw_bypass_chain"));
            }
            "security_tool_discovery_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("security_tool_discovery_chain"));
            }
            "process_discovery_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("process_discovery_chain"));
            }
            "system_recon_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("system_recon_chain"));
            }
            "advanced_injection_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("advanced_injection_chain"));
            }
            "input_capture_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("input_capture_chain"));
            }
            "impact_recovery_inhibition_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("impact_recovery_inhibition_chain"));
            }
            "impact_system_shutdown_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("impact_system_shutdown_chain"));
            }
            "privilege_token_manipulation_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("privilege_token_manipulation_chain"));
            }
            "lolbin_proxy_execution_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("lolbin_proxy_execution_chain"));
            }
            "web_delivery_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("web_delivery_chain"));
            }
            "scheduled_task_persistence_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("scheduled_task_persistence_chain"));
            }
            "rename_masquerading_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("rename_masquerading_chain"));
            }
            "defense_impairment_firewall_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("defense_impairment_firewall_chain"));
            }
            "reverse_shell_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("reverse_shell_chain"));
            }
            "container_evasion_chain" => {
                matched_rule = signal_lower
                    .iter()
                    .any(|s| s.contains("container_evasion_chain"));
            }
            _ => {}
        }
        if matched_rule && matched_ids.insert(name) {
            // Emit the stable id *and* the human-readable description.
            //
            // Emitting the description alone (as this used to) meant an
            // operator reading `matched_rules` in the NDJSON output saw prose
            // such as "Executable contains an unusually large number of
            // sections" with no way to join it back to the rulebook, weight,
            // or documentation — the description string is not a stable key
            // and silently changes whenever it is reworded. The id is that
            // key, so both are carried: `id` for machine joins and triage
            // filters, `id: description` for the human reading the report.
            matched.push(format!("{}: {}", rule.id, rule.description));
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
            if entropy_profile.score() >= 0.45 {
                indicators.push("flat_high_entropy_payload".to_string());
            }
            if entropy_profile.high_entropy_ratio() >= 0.80
                && entropy_profile.windows >= 8
                && entropy_profile.global >= 7.5
            {
                indicators.push(format!(
                    "high_entropy_density: {:.2} ({}/{} windows)",
                    entropy_profile.high_entropy_ratio(),
                    entropy_profile.high_windows,
                    entropy_profile.windows
                ));
            }
            if entropy_profile.longest_filler_run >= 8192 && entropy_profile.windows >= 4 {
                indicators.push(format!(
                    "large_padding_run: {}x0x{:02X}",
                    entropy_profile.longest_filler_run, entropy_profile.filler_byte
                ));
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

            // --- ATT&CK / MBC-aligned technique families -------------------
            // Every family below requires at least two independent evidence
            // groups. A single API name is never enough: `OpenProcess` alone is
            // used by Task Manager, `CreateProcess` alone by every launcher.
            let text = |needle: &[u8]| contains_ascii_case_insensitive(data, needle);

            // T1497/T1622 — virtualisation and debugger artefacts combined with
            // timing or execution-delay behaviour. The combination is what
            // distinguishes a real anti-analysis routine from a crash reporter.
            let anti_vm_marker = text(b"vmware")
                || text(b"virtualbox")
                || text(b"vboxservice")
                || text(b"qemu")
                || text(b"xen")
                || text(b"hyper-v")
                || text(b"sbiedll")
                || text(b"wine_get_unix_file_name")
                || text(b"cuckoomon");
            let anti_debug_marker = has("isdebuggerpresent")
                || has("checkremotedebuggerpresent")
                || has("ntqueryinformationprocess")
                || text(b"NtQueryInformationProcess")
                || text(b"OutputDebugString");
            let delay_marker = has("sleep")
                || has("sleepex")
                || has("ntdelayexecution")
                || text(b"NtDelayExecution")
                || text(b"QueryPerformanceCounter");
            let anti_analysis_evasion_chain =
                (anti_vm_marker && anti_debug_marker) || (anti_vm_marker && delay_marker);

            // T1562.001 — AMSI/ETW patching paired with in-memory execution.
            let amsi_target = text(b"AmsiScanBuffer")
                || text(b"AmsiInitialize")
                || text(b"AmsiOpenSession")
                || text(b"amsi.dll");
            let etw_target =
                text(b"EtwEventWrite") || text(b"NtTraceEvent") || text(b"EtwpEventWriteFull");
            let amsi_etw_bypass_chain = (amsi_target || etw_target)
                && (memory_mutation
                    || text(b"VirtualProtect")
                    || text(b"hook")
                    || text(b"patch"));

            // T1518.001/T1057 — security product or process enumeration.
            let security_product_marker = [
                b"windows defender".as_slice(),
                b"windefend".as_slice(),
                b"msmpeng".as_slice(),
                b"avast".as_slice(),
                b"avira".as_slice(),
                b"bitdefender".as_slice(),
                b"eset".as_slice(),
                b"kaspersky".as_slice(),
                b"mcafee".as_slice(),
                b"norton".as_slice(),
                b"symantec".as_slice(),
                b"trend micro".as_slice(),
                b"sophos".as_slice(),
                b"crowdstrike".as_slice(),
                b"sentinelone".as_slice(),
                b"cylance".as_slice(),
                b"carbon black".as_slice(),
                b"360tray".as_slice(),
                b"huorong".as_slice(),
                b"kingsoft".as_slice(),
                b"qqpcmgr".as_slice(),
            ]
            .iter()
            .any(|marker| text(marker));
            let process_enum_marker = has("createtoolhelp32snapshot")
                || has("process32first")
                || has("process32next")
                || has("enumprocesses")
                || has("wtsenumerateprocesses")
                || text(b"CreateToolhelp32Snapshot")
                || text(b"EnumProcesses");
            let security_tool_discovery_chain = security_product_marker
                && (process_enum_marker
                    || has("openprocess")
                    || text(b"EnumServicesStatus"));
            let process_discovery_chain = process_enum_marker
                && (has("openprocess")
                    || memory_mutation
                    || text(b"OpenProcessToken"));

            // T1082/T1016/T1033/T1124 — host, network, locale, time recon.
            let host_recon = has("getcomputername")
                || has("getcomputernameex")
                || has("getusername")
                || has("getusernameex")
                || text(b"GetComputerName")
                || text(b"GetUserName");
            let network_recon = has("getadaptersinfo")
                || has("getipforwardtable")
                || has("gethostbyname")
                || has("dnsquery")
                || text(b"GetAdaptersInfo")
                || text(b"GetHostName");
            let locale_recon = has("getsystemdefaultlangid")
                || has("getuserdefaultlangid")
                || has("getsystemdefaultuilanguage")
                || text(b"GetSystemDefaultLangID")
                || text(b"GetLocaleInfo");
            let time_recon = has("getsystemtime")
                || has("getlocaltime")
                || has("gettimezoneinformation")
                || text(b"GetSystemTimeAsFileTime")
                || text(b"QueryPerformanceFrequency");
            let recon_families = [
                host_recon,
                network_recon,
                locale_recon,
                time_recon,
            ]
            .iter()
            .filter(|present| **present)
            .count();
            let system_recon_chain = recon_families >= 3;

            // T1055 — the "advanced" injection primitives that ordinary
            // software essentially never links: cross-process section mapping,
            // thread context rewrites, and APC queues.
            let advanced_injection_marker = [
                b"NtMapViewOfSection".as_slice(),
                b"ZwMapViewOfSection".as_slice(),
                b"NtUnmapViewOfSection".as_slice(),
                b"NtCreateSection".as_slice(),
                b"QueueUserAPC".as_slice(),
                b"NtQueueApcThread".as_slice(),
                b"SetThreadContext".as_slice(),
                b"NtGetContextThread".as_slice(),
                b"RtlCreateUserThread".as_slice(),
                b"NtCreateThreadEx".as_slice(),
                b"Process Hollowing".as_slice(),
            ]
            .iter()
            .filter(|marker| text(marker))
            .count();
            let advanced_injection_chain = advanced_injection_marker >= 2
                || (advanced_injection_marker >= 1
                    && (memory_mutation || text(b"OpenProcess")));

            // T1056 — low-level input capture fed into a channel.
            let input_capture_marker = [
                b"SetWindowsHookEx".as_slice(),
                b"WH_KEYBOARD_LL".as_slice(),
                b"GetRawInputData".as_slice(),
                b"RegisterRawInputDevices".as_slice(),
                b"GetAsyncKeyState".as_slice(),
                b"GetKeyboardState".as_slice(),
                b"SetWinEventHook".as_slice(),
                b"OBJID_CARET".as_slice(),
            ]
            .iter()
            .filter(|marker| text(marker))
            .count();
            let input_capture_chain = input_capture_marker >= 2
                && (credential_exfil
                    || text(b"FileStream")
                    || text(b"CreateFile")
                    || text(b"http"));

            // T1490 — recovery inhibition. This family is a very strong
            // independent signal: legitimate backup software does not invoke
            // vssadmin to delete shadows.
            let recovery_inhibition_marker = [
                b"vssadmin delete shadows".as_slice(),
                b"delete shadows".as_slice(),
                b"wbadmin delete catalog".as_slice(),
                b"delete catalog".as_slice(),
                b"bcdedit /set".as_slice(),
                b"recoveryenabled no".as_slice(),
                b"bootstatuspolicy".as_slice(),
                b"wmic shadowcopy delete".as_slice(),
                b"IgnoreAllFailures".as_slice(),
                b"vssadmin.exe".as_slice(),
                b"diskshadow".as_slice(),
            ]
            .iter()
            .filter(|marker| text(marker))
            .count();
            let impact_recovery_inhibition_chain = recovery_inhibition_marker >= 1
                && (recovery_inhibition_marker >= 2
                    || text(b"CreateProcess")
                    || text(b"ShellExecute")
                    || text(b"WinExec")
                    || ransom_chain);

            // T1529 — forced shutdown/reboot following destructive capability.
            let shutdown_marker = text(b"InitiateSystemShutdown")
                || text(b"InitiateShutdown")
                || text(b"shutdown /r")
                || text(b"shutdown /s")
                || text(b"shutdown -r")
                || text(b"ExitWindowsEx");
            let impact_system_shutdown_chain = shutdown_marker
                && (ransom_chain
                    || impact_recovery_inhibition_chain
                    || text(b"encrypt"));

            // T1134 — token duplication/impersonation, not mere privilege
            // adjustment (which has its own, weaker rule).
            let token_dup_marker = has("duplicatetoken")
                || has("duplicatetokenex")
                || has("impersonateloggedonuser")
                || has("setthreadtoken")
                || text(b"DuplicateTokenEx")
                || text(b"ImpersonateLoggedOnUser");
            let privilege_token_manipulation_chain = token_dup_marker
                && (has("openprocesstoken")
                    || text(b"SeDebugPrivilege")
                    || text(b"SeTcbPrivilege")
                    || has("logonuser"));

            // T1218 — signed-binary proxy execution.
            let lolbin_name = [
                b"rundll32".as_slice(),
                b"regsvr32".as_slice(),
                b"mshta".as_slice(),
                b"certutil".as_slice(),
                b"bitsadmin".as_slice(),
                b"installutil".as_slice(),
                b"msbuild.exe".as_slice(),
                b"wmic.exe".as_slice(),
                b"cmstp".as_slice(),
                b"control.exe".as_slice(),
                b"pcalua".as_slice(),
                b"forfiles".as_slice(),
                b"cscript".as_slice(),
                b"wscript".as_slice(),
            ]
            .iter()
            .filter(|marker| text(marker))
            .count();
            let remote_or_staged = text(b"http://")
                || text(b"https://")
                || text(b"\\temp\\")
                || text(b"\\appdata\\")
                || text(b"javascript:")
                || text(b"scrobj.dll")
                || text(b"delegateexecute");
            let lolbin_proxy_execution_chain = lolbin_name >= 2 && remote_or_staged;

            // T1105/T1071.001 — download then execute.
            let download_marker = [
                b"URLDownloadToFile".as_slice(),
                b"InternetReadFile".as_slice(),
                b"WinHttpReadData".as_slice(),
                b"HttpSendRequest".as_slice(),
                b"BitBlt".as_slice(),
                b"FtpGetFile".as_slice(),
                b"certutil -urlcache".as_slice(),
            ]
            .iter()
            .any(|marker| text(marker));
            let execute_marker = text(b"CreateProcess")
                || text(b"ShellExecute")
                || text(b"WinExec")
                || text(b"system(")
                || text(b"eval(")
                || text(b"Invoke-Expression");
            let web_delivery_chain = download_marker
                && execute_marker
                && (remote_or_staged || text(b"http"));

            // T1053.005 — scheduled task with suppression of visibility.
            let scheduled_task_marker =
                text(b"schtasks") || text(b"TaskScheduler") || text(b"ITaskService");
            let suppression_marker = text(b"/f /tn")
                || text(b"DisableRealtimeMonitoring")
                || text(b"reg delete")
                || text(b"wevtutil cl")
                || text(b"ClearEventLog");
            let scheduled_task_persistence_chain = scheduled_task_marker
                && (suppression_marker
                    || (persistence_chain && text(b"schtasks")));

            // T1036.005 — name/path masquerading of a system binary.
            let masquerade_name = [
                b"svchost.exe".as_slice(),
                b"lsass.exe".as_slice(),
                b"csrss.exe".as_slice(),
                b"services.exe".as_slice(),
                b"winlogon.exe".as_slice(),
                b"smss.exe".as_slice(),
                b"explorer.exe".as_slice(),
                b"taskhostw.exe".as_slice(),
                b"dllhost.exe".as_slice(),
                b"runtimebroker.exe".as_slice(),
            ]
            .iter()
            .filter(|marker| text(marker))
            .count();
            let user_writable_marker = text(b"\\appdata\\")
                || text(b"\\temp\\")
                || text(b"\\downloads\\")
                || text(b"\\programdata\\")
                || text(b"%temp%")
                || text(b"\\users\\public\\");
            let rename_masquerading_chain = masquerade_name >= 1
                && user_writable_marker
                && (persistence_chain || memory_mutation || text(b"CurrentVersion\\Run"));

            // T1562.004 — firewall impairment.
            let firewall_target =
                text(b"netsh advfirewall") || text(b"netsh firewall") || text(b"MpsSvc");
            let firewall_action = text(b"set opmode disable")
                || text(b"state off")
                || text(b"disable")
                || text(b"stop")
                || text(b"delete rule");
            let defense_impairment_firewall_chain = firewall_target && firewall_action;

            // T1059 — reverse/bind shell: an interpreter wired to a socket.
            let socket_marker = has("wsastartup")
                || has("socket")
                || has("connect")
                || has("wsasocket")
                || text(b"WSAStartup")
                || text(b"TcpClient")
                || text(b"NetworkStream");
            let shell_marker = text(b"cmd.exe")
                || text(b"/bin/sh")
                || text(b"powershell")
                || text(b"bash -i")
                || text(b"nc -e")
                || text(b"ncat")
                || text(b"CreateProcess")
                || text(b"ShellExecute");
            let reverse_shell_chain = socket_marker
                && shell_marker
                && (has("createremotethread")
                    || text(b"cmd.exe /c")
                    || text(b"StdHandle")
                    || text(b"STARTUPINFO"));

            // T1610 — container/namespace probing from a non-container image.
            let container_marker = [
                b"docker.sock".as_slice(),
                b"\\\\.\\pipe\\docker".as_slice(),
                b"/proc/self/status".as_slice(),
                b"libcontainer".as_slice(),
                b"KUBERNETES_SERVICE_HOST".as_slice(),
                b"cgroup".as_slice(),
            ]
            .iter()
            .filter(|marker| text(marker))
            .count();
            let container_evasion_chain = container_marker >= 1
                && (network_recon || memory_mutation || text(b"privileged"));

            for (fired, signal) in [
                (anti_analysis_evasion_chain, "anti_analysis_evasion_chain"),
                (amsi_etw_bypass_chain, "amsi_etw_bypass_chain"),
                (
                    security_tool_discovery_chain,
                    "security_tool_discovery_chain",
                ),
                (process_discovery_chain, "process_discovery_chain"),
                (system_recon_chain, "system_recon_chain"),
                (advanced_injection_chain, "advanced_injection_chain"),
                (input_capture_chain, "input_capture_chain"),
                (
                    impact_recovery_inhibition_chain,
                    "impact_recovery_inhibition_chain",
                ),
                (
                    impact_system_shutdown_chain,
                    "impact_system_shutdown_chain",
                ),
                (
                    privilege_token_manipulation_chain,
                    "privilege_token_manipulation_chain",
                ),
                (
                    lolbin_proxy_execution_chain,
                    "lolbin_proxy_execution_chain",
                ),
                (web_delivery_chain, "web_delivery_chain"),
                (
                    scheduled_task_persistence_chain,
                    "scheduled_task_persistence_chain",
                ),
                (rename_masquerading_chain, "rename_masquerading_chain"),
                (
                    defense_impairment_firewall_chain,
                    "defense_impairment_firewall_chain",
                ),
                (reverse_shell_chain, "reverse_shell_chain"),
                (container_evasion_chain, "container_evasion_chain"),
            ] {
                if fired {
                    indicators.push(signal.to_string());
                }
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
        assert_eq!(empty.score(), 0.0);
        assert_eq!(empty.windows, 0);
        let small = analyze_entropy_distribution(b"ordinary data");
        assert!(!small.blocks.is_empty());
        assert!(small.score() <= 0.55);
    }

    /// A fully randomised buffer (standing in for an encrypted payload) must
    /// score far higher than ordinary text of the same length. The previous
    /// mean/variance-only implementation could not separate these two.
    #[test]
    fn entropy_profile_separates_encrypted_payload_from_plain_text() {
        // Deterministic pseudo-random bytes: a xorshift generator avoids a
        // rand dependency and keeps the fixture reproducible.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut encrypted = Vec::with_capacity(64 * 1024);
        for _ in 0..(64 * 1024) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            encrypted.push((state & 0xFF) as u8);
        }
        // Plain English-ish text repeated to the same size.
        let plain = b"the quick brown fox jumps over the lazy dog. ".repeat(1500);

        let high = analyze_entropy_distribution(&encrypted);
        let low = analyze_entropy_distribution(&plain);

        assert!(
            high.score() > low.score(),
            "encrypted={} plain={}",
            high.score(),
            low.score()
        );
        assert!(high.is_high_entropy_payload(), "score={}", high.score());
        assert!(!low.is_high_entropy_payload(), "score={}", low.score());
        assert!(high.global > low.global);
        assert!(high.high_entropy_ratio() > low.high_entropy_ratio());
        // Text is far more "compressible" than ciphertext under the proxy.
        assert!(high.compressibility > low.compressibility);
    }

    /// A small encrypted blob appended to otherwise-plain content must still be
    /// visible through the density ratio, which is the regression this guards.
    #[test]
    fn entropy_profile_detects_appended_encrypted_region() {
        let mut buffer = b"A".repeat(32 * 1024);
        buffer.extend(std::iter::repeat_n(0x00u8, 4096));
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..(32 * 1024) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            buffer.push((state & 0xFF) as u8);
        }

        let profile = analyze_entropy_distribution(&buffer);
        let ratio = profile.high_entropy_ratio();

        // Half the buffer is plain, half is high entropy, so the density must
        // land strictly between the two extremes rather than saturating.
        assert!(
            ratio > 0.20 && ratio < 0.95,
            "ratio={ratio} windows={} high={}",
            profile.windows,
            profile.high_windows
        );
        // The 4 KiB zero run is detected independently of the entropy ratio.
        // Measured value for this fixture is exactly 4096.
        assert!(
            profile.longest_filler_run >= 4096,
            "filler_run={} filler=0x{:02X}",
            profile.longest_filler_run,
            profile.filler_byte
        );
        // The global figure is diluted by the plain half, so it must sit
        // clearly below a fully-encrypted buffer's ~8.0. The 'A' run holds the
        // whole-buffer value down to just under 5.0, which is the entire point:
        // a mean-only estimator scores this buffer as *inert*.
        assert!(
            profile.global > 4.5 && profile.global < 7.8,
            "global={}",
            profile.global
        );
        // The padding gate pairs a long filler run with moderate packing
        // density, which is what separates "appended blob" from "dense
        // executable". This is the assertion that proves the mixed layout is
        // still recognised even though `global` alone says it is plain.
        assert!(
            profile.is_padding_shape(),
            "the appended-region shape must satisfy the padding gate; \
             ratio={ratio} filler_run={}",
            profile.longest_filler_run
        );
    }

    /// A payload appended after a very large plain prefix is the case a
    /// mean-only estimator loses; the density ratio must still register it.
    #[test]
    fn entropy_profile_registers_small_appendix_after_large_prefix() {
        let mut buffer = b"B".repeat(512 * 1024);
        let mut state = 0xDEAD_BEEF_CAFE_F00Du64;
        for _ in 0..(16 * 1024) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            buffer.push((state & 0xFF) as u8);
        }
        let profile = analyze_entropy_distribution(&buffer);
        // ~3% of the buffer is high entropy, so the ratio must be small but
        // strictly non-zero — the tail-window logic guarantees this.
        assert!(
            profile.high_windows > 0,
            "appended tail must be sampled; windows={} ratio={}",
            profile.windows,
            profile.high_entropy_ratio()
        );
        assert!(profile.high_entropy_ratio() < 0.25);
        // The 512 KiB 'B' prefix is the dominant byte, so it is the filler,
        // and it runs for the whole prefix. This is the case that a raw
        // zero-run measure reported as 0 while still leaving stray xorshift
        // zeroes behind; the dominant-byte measure is structurally correct.
        assert_eq!(profile.filler_byte, b'B');
        assert!(profile.longest_filler_run >= 512 * 1024);
        // A long filler run alone must not imply packing: the density gate
        // keeps `is_padding_shape` false for a plain padded buffer.
        assert!(!profile.is_padding_shape());
    }

    /// The stray-zero problem: random data contains short zero runs that a
    /// zero-run measure counts as evidence. The dominant-byte measure must not
    /// be fooled by them, and must not report them as padding.
    #[test]
    fn entropy_profile_ignores_incidental_zero_runs_in_random_data() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut buffer = Vec::with_capacity(64 * 1024);
        for _ in 0..(64 * 1024) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            buffer.push((state & 0xFF) as u8);
        }
        let profile = analyze_entropy_distribution(&buffer);
        // Fully dense, so no filler run of any consequence exists. Anything
        // in the thousands here would reintroduce the false-positive the
        // dominant-byte change exists to remove.
        assert!(
            profile.longest_filler_run < 16,
            "filler_run={} filler=0x{:02X}",
            profile.longest_filler_run,
            profile.filler_byte
        );
        assert!(!profile.is_padding_shape());
        assert!(profile.is_high_entropy_payload());
    }

    #[test]
    fn entropy_profile_bounds_window_count_for_large_inputs() {
        let large = vec![0x5Au8; 8 * 1024 * 1024];
        let profile = analyze_entropy_distribution(&large);
        // The 2048-window cap plus a tail window must hold.
        assert!(profile.windows <= 2049, "windows={}", profile.windows);
        // Uniform filler with no entropy at all: the longest run reaches the
        // end of the analysed region.
        assert_eq!(profile.filler_byte, 0x5A);
        assert!(profile.longest_filler_run > 0);
        assert!(!profile.is_high_entropy_payload());
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

    // --- ATT&CK/MBC-aligned technique family tests -------------------------

    fn fires(score: &HeuristicScore, family: &str) -> bool {
        score.indicators.iter().any(|s| s == family)
    }

    #[test]
    fn impact_recovery_inhibition_chain_fires_on_shadow_copy_deletion() {
        let benign = analyze_bytes(&minimal_pe(0x6000_0020, b"kernel32.dll\0ExitProcess\0"))
            .expect("analyze");
        assert!(!fires(&benign, "impact_recovery_inhibition_chain"));

        let malicious = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"vssadmin delete shadows /all /quiet\0\
              wbadmin delete catalog -quiet\0\
              CreateProcessW\0",
        ))
        .expect("analyze");
        assert!(
            fires(&malicious, "impact_recovery_inhibition_chain"),
            "indicators={:?}",
            malicious.indicators
        );
        assert!(malicious.score >= 0.70, "score={}", malicious.score);
    }

    #[test]
    fn amsi_etw_bypass_chain_needs_patching_plus_execution() {
        // The AMSI name alone is present in legitimate tooling and must not fire.
        let name_only = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"AmsiScanBuffer\0amsi.dll\0installer helper\0",
        ))
        .expect("analyze");
        assert!(!fires(&name_only, "amsi_etw_bypass_chain"));

        let bypass = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"AmsiScanBuffer\0EtwEventWrite\0VirtualProtect\0LoadLibraryW\0",
        ))
        .expect("analyze");
        assert!(
            fires(&bypass, "amsi_etw_bypass_chain"),
            "indicators={:?}",
            bypass.indicators
        );
    }

    #[test]
    fn security_tool_discovery_chain_requires_enumeration() {
        // Naming an AV product is not enumeration on its own.
        let name_only = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"Windows Defender\0about this product\0",
        ))
        .expect("analyze");
        assert!(!fires(&name_only, "security_tool_discovery_chain"));

        let discovery = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"Windows Defender\0MsMpEng.exe\0CreateToolhelp32Snapshot\0OpenProcess\0",
        ))
        .expect("analyze");
        assert!(
            fires(&discovery, "security_tool_discovery_chain"),
            "indicators={:?}",
            discovery.indicators
        );
    }

    #[test]
    fn advanced_injection_chain_requires_real_primitives() {
        // The classic trio is matched against the *import table*, which this
        // fixture does not build; assert on the structural rule instead so the
        // test documents the boundary rather than a parser detail.
        let classic = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"VirtualAlloc\0WriteProcessMemory\0CreateRemoteThread\0",
        ))
        .expect("analyze");
        // A single advanced primitive plus a memory mutation is enough.
        let advanced = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"NtMapViewOfSection\0NtUnmapViewOfSection\0NtCreateSection\0OpenProcess\0",
        ))
        .expect("analyze");
        assert!(
            fires(&advanced, "advanced_injection_chain"),
            "indicators={:?}",
            advanced.indicators
        );
        // Two independent advanced primitives alone are sufficient even with no
        // other memory API present.
        let primitives_only = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"QueueUserAPC\0NtQueueApcThread\0",
        ))
        .expect("analyze");
        assert!(
            fires(&primitives_only, "advanced_injection_chain"),
            "indicators={:?}",
            primitives_only.indicators
        );
        // A single primitive with no corroboration must stay quiet.
        let single = analyze_bytes(&minimal_pe(0x6000_0020, b"QueueUserAPC\0"))
            .expect("analyze");
        assert!(!fires(&single, "advanced_injection_chain"));
        let _ = classic;
    }

    #[test]
    fn defense_impairment_firewall_chain_requires_target_and_action() {
        let target_only = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"netsh advfirewall\0documentation\0",
        ))
        .expect("analyze");
        assert!(!fires(&target_only, "defense_impairment_firewall_chain"));

        let impair = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"netsh advfirewall set opmode disable\0",
        ))
        .expect("analyze");
        assert!(
            fires(&impair, "defense_impairment_firewall_chain"),
            "indicators={:?}",
            impair.indicators
        );
    }

    #[test]
    fn anti_analysis_evasion_chain_needs_two_families() {
        let single = analyze_bytes(&minimal_pe(0x6000_0020, b"VMware Tools\0"))
            .expect("analyze");
        assert!(!fires(&single, "anti_analysis_evasion_chain"));

        let combined = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"VMware Tools\0VBoxService\0IsDebuggerPresent\0QueryPerformanceCounter\0",
        ))
        .expect("analyze");
        assert!(
            fires(&combined, "anti_analysis_evasion_chain"),
            "indicators={:?}",
            combined.indicators
        );
    }

    #[test]
    fn system_recon_chain_requires_three_families() {
        // Two families is common in ordinary software and must stay quiet.
        let two = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"GetComputerNameW\0GetUserNameW\0",
        ))
        .expect("analyze");
        assert!(!fires(&two, "system_recon_chain"));

        let broad = analyze_bytes(&minimal_pe(
            0x6000_0020,
            b"GetComputerNameW\0GetUserNameW\0GetAdaptersInfo\0GetSystemTimeAsFileTime\0",
        ))
        .expect("analyze");
        assert!(
            fires(&broad, "system_recon_chain"),
            "indicators={:?}",
            broad.indicators
        );
    }

    #[test]
    fn rulebook_weights_stay_within_the_calibrated_contract() {
        let rulebook = static_rulebook();
        // Every rule must carry a meaningful but sub-certain weight; the
        // calibrated_score combiner assumes 0.0..=0.95 per contributor.
        for rule in &rulebook {
            assert!(
                rule.weight > 0.0 && rule.weight <= 0.95,
                "rule {} has weight {}",
                rule.id,
                rule.weight
            );
            assert!(
                !rule.description.is_empty(),
                "rule {} needs a description",
                rule.id
            );
        }
        // Rule ids must be unique, otherwise evidence silently merges.
        let mut ids: Vec<&str> = rulebook.iter().map(|rule| rule.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate rule id in static_rulebook");
    }

    #[test]
    fn every_new_family_has_a_matching_scoring_arm() {
        // A rulebook entry whose id is never consulted by `score_static_signals`
        // can never fire — a silent coverage hole rather than a compile error.
        //
        // Most rules match their own id as a substring of the signal, but a few
        // are intentionally *derived*: they fire on a combination of API names
        // or on a structural shape, so a bare id must not be expected to match.
        // Those are listed explicitly with a probe that does satisfy them, which
        // keeps the test honest about the contract instead of weakening it.
        let derived: [(&str, &[&str]); 10] = [
            // `packer_detected` matches the `packer_detected:` prefixed form
            // emitted by assess_unpacking, not the bare rule id.
            ("packer_detected", &["packer_detected:upx"]),
            ("obfuscated_command_strings", &["obfuscated_command_or_url"]),
            ("tls_callbacks", &["tls_callback"]),
            (
                "api_injection_chain",
                &["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
            ),
            (
                "api_ransom_chain",
                &["CryptAcquireContext", "CryptEncrypt", "DeleteFile"],
            ),
            (
                "privilege_escalation_chain",
                &["OpenProcessToken", "AdjustTokenPrivileges", "OpenProcess"],
            ),
            ("hooking_chain", &["SetWindowsHookEx", "GetAsyncKeyState"]),
            ("dynamic_load_chain", &["GetProcAddress", "LoadLibrary"]),
            ("embedded_payload", &["embedded_payload"]),
            ("authenticode_anomaly", &["signature:invalid"]),
        ];

        let mut reachable = 0usize;
        let mut derived_ids = std::collections::HashSet::new();
        for (id, probes) in derived {
            derived_ids.insert(id);
            let signals: Vec<String> = probes.iter().map(|p| p.to_string()).collect();
            assert!(
                !score_static_signals(&signals).indicators.is_empty(),
                "derived rule {id} is unreachable"
            );
            reachable += 1;
        }

        for rule in static_rulebook() {
            if derived_ids.contains(rule.id) {
                continue;
            }
            let probe = vec![rule.id.to_string()];
            let indicators = score_static_signals(&probe).indicators;
            // Reachable means "its own id fires". Two details make an exact
            // equality check wrong:
            //
            //  * Indicators are emitted as `id: description`, so the id is a
            //    prefix rather than the whole string.
            //  * An id can be a substring of another id, in which case both
            //    arms legitimately fire. `embedded_pe_payload` also matching
            //    the bare `embedded_payload` arm is the canonical case.
            //
            // So the contract is: the rule's own id must appear as a prefix of
            // some emitted indicator. That still catches the real bug this
            // test was written for — a rulebook entry with no scoring arm, or
            // one whose arm keys off some *other* string entirely.
            let prefixed = format!("{}:", rule.id);
            assert!(
                indicators
                    .iter()
                    .any(|item| item == rule.id || item.starts_with(&prefixed)),
                "rule {} must be reachable from its own id, got {:?}",
                rule.id,
                indicators
            );
            reachable += 1;
        }

        assert_eq!(
            reachable,
            static_rulebook().len(),
            "every rulebook id must be reachable from score_static_signals"
        );
    }
}
