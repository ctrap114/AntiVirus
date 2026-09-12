//! Static sandbox prediction layer.
//!
//! Predicts the runtime capabilities a sample would demonstrate in a dynamic
//! sandbox — network C2, persistence, process injection, credential access,
//! evasion and system reconnaissance — purely from static bytes (PE imports,
//! ASCII/UTF-16LE strings, embedded URLs). Nothing is ever executed.
//!
//! The prediction is advisory telemetry: it never produces a malicious
//! verdict on its own. See `docs/static_sandbox.md` for the threat model.

use serde::Serialize;

/// Weight of each capability family in the calibrated score.
const W_INJECTION: f32 = 0.30;
const W_PERSISTENCE: f32 = 0.25;
const W_CREDENTIAL: f32 = 0.25;
const W_NETWORK: f32 = 0.20;
const W_EVASION: f32 = 0.15;
const W_RECON: f32 = 0.10;

/// Analysis is bounded to keep worst-case cost predictable even when callers
/// pass oversized blobs.
pub const MAX_ANALYSIS_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPORTED_URLS: usize = 8;
const MIN_URL_LENGTH: usize = 11; // "http://a.bb" is shorter than any real C2.

/// Static prediction of sandbox-observable capabilities.
#[derive(Debug, Clone, Serialize)]
pub struct StaticSandboxPrediction {
    /// Calibrated risk 0..=1 across all triggered capability families.
    pub score: f32,
    /// Triggered capabilities, e.g. `injection:write_process_memory`.
    pub capabilities: Vec<String>,
    /// Extracted URLs (capped) that look like C2 endpoints.
    pub network_indicators: Vec<String>,
}

impl StaticSandboxPrediction {
    /// Strongest static chain: injection + persistence plus an exfil or C2
    /// channel. This combination almost never occurs in legitimate software
    /// and is the only shape allowed to escalate a scan to Suspicious.
    pub fn is_high_confidence_chain(&self) -> bool {
        let has = |prefix: &str| self.capabilities.iter().any(|cap| cap.starts_with(prefix));
        let injection = has("injection:");
        let persistence = has("persistence:");
        let channel =
            has("network:") || has("credential_access:");
        injection && persistence && channel && self.score >= 0.55
    }
}

fn contains_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn contains_wide(haystack: &[u8], needle: &str) -> bool {
    let mut encoded = Vec::with_capacity(needle.len() * 2);
    for unit in needle.encode_utf16() {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    contains_case_insensitive(haystack, &encoded)
}

/// Extracts http/https URLs from raw bytes; tolerates trailing binary noise
/// by cutting at the first byte outside a URL character set.
fn extract_urls(bytes: &[u8]) -> Vec<String> {
    fn is_url_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b':' | b'/' | b'.' | b'?' | b'=' | b'&' | b'-' | b'_' | b'%' | b'~' | b'#'
                    | b'@' | b'+'
            )
    }
    let mut urls = Vec::new();
    let mut position = 0usize;
    while position + MIN_URL_LENGTH <= bytes.len() && urls.len() < MAX_REPORTED_URLS {
        let rest = &bytes[position..];
        let scheme_offset = if rest.starts_with(b"https://") {
            8
        } else if rest.starts_with(b"http://") {
            7
        } else {
            // Advance to the next candidate position.
            match find_scheme_start(rest) {
                Some(next) => {
                    position += next;
                    continue;
                }
                None => break,
            }
        };
        let mut end = scheme_offset;
        while end < rest.len() && is_url_byte(rest[end]) {
            end += 1;
        }
        // Require at least one dot in the host part to skip bare "http://" hits.
        let candidate = &rest[..end];
        let host = &candidate[scheme_offset..];
        if host.iter().filter(|&&b| b == b'.').count() >= 1 && host.len() >= 4 {
            urls.push(String::from_utf8_lossy(candidate).trim_end_matches('.').to_string());
        }
        position += end.max(1);
    }
    urls.sort();
    urls.dedup();
    urls
}

fn find_scheme_start(bytes: &[u8]) -> Option<usize> {
    const NEEDLES: [&[u8]; 2] = [b"http://", b"https://"];
    let mut best: Option<usize> = None;
    for needle in NEEDLES {
        if let Some(found) =
            haystack_find(bytes, needle)
        {
            best = Some(match best {
                Some(existing) => existing.min(found),
                None => found,
            });
        }
    }
    best
}

fn haystack_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Collects lowercased imported symbol names from a PE image, mirroring the
/// heuristic layer's approach but tolerating any parse failure silently.
fn pe_import_names(bytes: &[u8]) -> Vec<String> {
    let Ok(object) = goblin::Object::parse(bytes) else {
        return Vec::new();
    };
    match object {
        goblin::Object::PE(pe) => pe
            .imports
            .iter()
            .map(|import| import.name.to_ascii_lowercase())
            .collect(),
        _ => Vec::new(),
    }
}

const INJECTION_IMPORTS: [&str; 8] = [
    "writeprocessmemory",
    "virtualallocex",
    "createremotethread",
    "ntmapviewofsection",
    "queueuserapc",
    "setwindowshookex",
    "rtlcreateuserthread",
    "zwwritevirtualmemory",
];

const CREDENTIAL_MARKERS: [&str; 6] = [
    "cryptunprotectdata",
    "vaultcli",
    "login data",
    "web data",
    "cookies.sqlite",
    "lsass",
];

const EVASION_STRINGS: [&str; 7] = [
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "vmwaresvga",
    "virtualbox guest additions",
    "sandboxie",
    "qemu guest",
    "xenservice",
];

const PERSISTENCE_WIDE: [&str; 5] = [
    "currentversion\\run",
    "currentversion\\runonce",
    "schtasks /create",
    "\\startup\\",
    "currentversion\\explorer\\shell folders",
];

fn calibrated(weights: &[f32]) -> f32 {
    // Only triggered families participate, so the corroboration bonus never
    // inflates a single-detector finding.
    let active: Vec<f32> = weights.iter().copied().filter(|w| *w > 0.0).collect();
    if active.is_empty() {
        return 0.0;
    }
    let complement: f32 = active.iter().map(|w| 1.0 - w).product();
    let combined =
        (1.0 - complement + (active.len() - 1) as f32 * 0.025).min(0.95);
    combined.clamp(0.0, 1.0)
}

/// Runs every static capability detector over `bytes`.
pub fn analyze_static_sandbox(bytes: &[u8]) -> StaticSandboxPrediction {
    let scope = &bytes[..bytes.len().min(MAX_ANALYSIS_BYTES)];
    let imports = pe_import_names(scope);
    let lowered_blob = scope.to_ascii_lowercase();

    let mut capabilities = Vec::new();

    // --- injection ---------------------------------------------------------
    let injection_hits: Vec<&str> = INJECTION_IMPORTS
        .iter()
        .filter(|name| imports.iter().any(|imp| imp.contains(*name)))
        .copied()
        .collect();
    let injection_weight = match injection_hits.len() {
        0 => 0.0,
        1 => W_INJECTION * 0.6,
        _ => W_INJECTION,
    };
    for hit in injection_hits.iter() {
        capabilities.push(format!("injection:{hit}"));
    }

    // --- persistence -------------------------------------------------------
    let mut persistence_weight = 0.0f32;
    for needle in PERSISTENCE_WIDE {
        if contains_case_insensitive(&lowered_blob, needle.as_bytes())
            || contains_wide(scope, needle)
        {
            persistence_weight = persistence_weight.max(W_PERSISTENCE * 0.7);
            capabilities.push(format!(
                "persistence:{}",
                needle.trim_start_matches('\\')
            ));
        }
    }
    if imports
        .iter()
        .any(|imp| imp.contains("regsetvalueex") || imp.contains("schtask"))
    {
        persistence_weight = persistence_weight.max(W_PERSISTENCE);
        capabilities.push("persistence:registry_api".to_string());
    }

    // --- credential access -------------------------------------------------
    let mut credential_weight = 0.0f32;
    for marker in CREDENTIAL_MARKERS {
        let marker_lower = marker.to_ascii_lowercase();
        if imports.iter().any(|imp| imp.contains(&marker_lower))
            || contains_case_insensitive(&lowered_blob, marker.as_bytes())
            || contains_wide(scope, marker)
        {
            credential_weight = W_CREDENTIAL;
            capabilities.push(format!("credential_access:{marker}"));
        }
    }

    // --- network -----------------------------------------------------------
    let urls = extract_urls(scope);
    let network_imports = imports
        .iter()
        .any(|imp| imp.contains("internetopen") || imp.contains("winhttpopen"));
    let network_weight = if !urls.is_empty() {
        W_NETWORK
    } else if network_imports {
        W_NETWORK * 0.5
    } else {
        0.0
    };
    if network_weight > 0.0 {
        capabilities.push("network:c2_endpoints".to_string());
    }

    // --- evasion -----------------------------------------------------------
    let mut evasion_weight = 0.0f32;
    for marker in EVASION_STRINGS {
        let marker_lower = marker.to_ascii_lowercase();
        if imports.iter().any(|imp| imp.contains(&marker_lower))
            || contains_case_insensitive(&lowered_blob, marker.as_bytes())
            || contains_wide(scope, marker)
        {
            evasion_weight = evasion_weight.max(W_EVASION);
            capabilities.push(format!("evasion:{marker}"));
        }
    }

    // --- reconnaissance ----------------------------------------------------
    let recon_hits = ["getcomputername", "getusername", "getadaptersinfo"]
        .iter()
        .filter(|name| imports.iter().any(|imp| imp.contains(**name)))
        .count();
    let recon_weight = match recon_hits {
        0 => 0.0,
        1 => W_RECON * 0.7,
        _ => W_RECON,
    };
    if recon_hits > 0 {
        capabilities.push("recon:system_discovery".to_string());
    }

    capabilities.sort();
    capabilities.dedup();

    StaticSandboxPrediction {
        score: calibrated(&[
            injection_weight,
            persistence_weight,
            credential_weight,
            network_weight,
            evasion_weight,
            recon_weight,
        ]),
        capabilities,
        network_indicators: urls,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE64 image with an import directory, mirroring the helper in
    /// the heuristic layer's tests.
    fn minimal_pe(import_dll: &str, functions: &[&str]) -> Vec<u8> {
        let mut dos = vec![0u8; 0x40];
        dos[..2].copy_from_slice(b"MZ");
        dos[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        let mut pe = Vec::new();
        pe.extend_from_slice(b"PE\0\0");
        pe.extend_from_slice(&0x8664u16.to_le_bytes()); // machine
        pe.extend_from_slice(&1u16.to_le_bytes()); // one section
        pe.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        pe.extend_from_slice(&0u32.to_le_bytes()); // no symbol table
        pe.extend_from_slice(&0u32.to_le_bytes());
        pe.extend_from_slice(&240u16.to_le_bytes());
        pe.extend_from_slice(&0x0022u16.to_le_bytes());

        // Import blob: one descriptor + dll name + hint/name entries + IAT.
        let dir_rva = 0x2000usize;
        let dll_name_rva = 0x2100usize;
        let first_thunk_rva = 0x2200usize;
        let original_first_thunk_rva = 0x2300usize;
        let hint_name_base = 0x2400usize;

        let mut import_blob = [0u8; 0x600];
        // OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk
        import_blob[0..4].copy_from_slice(&(original_first_thunk_rva as u32).to_le_bytes());
        import_blob[12..16].copy_from_slice(&(dll_name_rva as u32).to_le_bytes());
        import_blob[16..20].copy_from_slice(&(first_thunk_rva as u32).to_le_bytes());

        for (offset, byte) in import_dll.bytes().enumerate() {
            import_blob[dll_name_rva - dir_rva + offset] = byte.to_ascii_uppercase();
        }

        let mut hint_offset = 0usize; // blob-relative
        let hint_blob_base = hint_name_base - dir_rva;
        let mut thunk_values = Vec::new();
        for function in functions {
            let name = format!("{function}\0");
            let needed = hint_blob_base + hint_offset + 2 + name.len() + 8;
            if needed >= import_blob.len() || thunk_values.len() >= 12 {
                break;
            }
            thunk_values.push((hint_name_base as u32) + (hint_offset as u32));
            // Hint (2 bytes) then name.
            let write_at = hint_blob_base + hint_offset;
            import_blob[write_at] = 0;
            import_blob[write_at + 1] = 0;
            let bytes = name.as_bytes();
            import_blob[write_at + 2..write_at + 2 + bytes.len()].copy_from_slice(bytes);
            hint_offset += 2 + bytes.len();
        }
        for (index, value) in thunk_values.iter().enumerate() {
            let at = original_first_thunk_rva - dir_rva + index * 8;
            import_blob[at..at + 4].copy_from_slice(&value.to_le_bytes());
            let at2 = first_thunk_rva - dir_rva + index * 8;
            import_blob[at2..at2 + 4].copy_from_slice(&value.to_le_bytes());
        }

        let mut optional = vec![0u8; 240];
        optional[0..2].copy_from_slice(&0x20Bu16.to_le_bytes());
        optional[32..36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        optional[36..40].copy_from_slice(&0x0200u32.to_le_bytes()); // FileAlignment
        optional[56..60].copy_from_slice(&0x5000u32.to_le_bytes()); // SizeOfImage
        optional[60..64].copy_from_slice(&0x0200u32.to_le_bytes()); // SizeOfHeaders
        optional[108..112].copy_from_slice(&16u32.to_le_bytes());
        // Second data directory (imports): dirs begin right after
        // NumberOfRvaAndSizes at 112; entry = {RVA, Size}.
        let import_dir_at = 112 + 8;
        optional[import_dir_at..import_dir_at + 4]
            .copy_from_slice(&(dir_rva as u32).to_le_bytes());
        optional[import_dir_at + 4..import_dir_at + 8]
            .copy_from_slice(&(import_blob.len() as u32).to_le_bytes());

        let mut headers = Vec::new();
        headers.extend_from_slice(&dos);
        headers.extend_from_slice(&pe);
        headers.extend_from_slice(&optional);

        // Section maps RVA = file offset in this fixture: VA 0x1000 at raw
        // 0x1000, so the import blob placed at file offset 0x2000 carries
        // RVAs starting at 0x2000 as declared above.
        let mut section_header = [0u8; 40];
        section_header[..6].copy_from_slice(b".rdata");
        section_header[8..12].copy_from_slice(&0x3000u32.to_le_bytes()); // VirtualSize
        section_header[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        section_header[16..20].copy_from_slice(&0x3000u32.to_le_bytes()); // RawSize
        section_header[20..24].copy_from_slice(&0x1000u32.to_le_bytes()); // PointerToRawData
        section_header[36..40].copy_from_slice(&0x40000040u32.to_le_bytes());

        let mut image = headers;
        image.extend_from_slice(&section_header);
        image.resize(0x2000, 0);
        image.extend_from_slice(&import_blob);
        // Pad to the next SectionAlignment boundary so goblin's aligned
        // import-table slice never runs off the end of the file.
        image.resize(0x3000, 0);
        image
    }

    #[test]
    fn benign_content_yields_no_capabilities() {
        let prediction = analyze_static_sandbox(b"just a plain text readme file\nnothing to see");
        assert!(prediction.capabilities.is_empty());
        assert_eq!(prediction.score, 0.0);
        assert!(prediction.network_indicators.is_empty());
        assert!(!prediction.is_high_confidence_chain());
    }

    #[test]
    fn injection_and_persistence_and_network_form_high_confidence_chain() {
        let mut blob = minimal_pe("kernel32.dll", &["WriteProcessMemory", "CreateRemoteThread"]);
        blob.extend_from_slice(b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0");
        blob.extend_from_slice(b"http://c2.example-store.ru/gate.php\0");
        let prediction = analyze_static_sandbox(&blob);
        assert!(
            prediction.capabilities.iter().any(|cap| cap.starts_with("injection:")),
            "capabilities: {:?}",
            prediction.capabilities
        );
        assert!(prediction
            .capabilities
            .iter()
            .any(|cap| cap.starts_with("persistence:")));
        assert!(prediction
            .capabilities
            .iter()
            .any(|cap| cap.starts_with("network:")));
        assert!(
            !prediction.network_indicators.is_empty(),
            "urls should be harvested"
        );
        assert!(
            prediction.is_high_confidence_chain(),
            "chain must qualify; score={}",
            prediction.score
        );
    }

    #[test]
    fn single_capability_stays_below_chain_threshold() {
        let prediction =
            analyze_static_sandbox(b"visit https://update.example.com/notes for details");
        assert!(!prediction.is_high_confidence_chain());
        assert!(prediction.score < 0.5);
    }

    #[test]
    fn utf16_persistence_markers_are_detected() {
        let mut wide_marker = Vec::new();
        for unit in "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\u{0}".encode_utf16() {
            wide_element(&mut wide_marker, unit);
        }
        let mut blob = minimal_pe("advapi32.dll", &["RegSetValueExW"]);
        blob.extend_from_slice(&wide_marker);
        let prediction = analyze_static_sandbox(&blob);
        assert!(prediction
            .capabilities
            .iter()
            .any(|cap| cap.contains("runonce") || cap.starts_with("persistence:")));
        assert!(prediction.score > 0.1);
    }

    fn wide_element(target: &mut Vec<u8>, unit: u16) {
        target.extend_from_slice(&unit.to_le_bytes());
    }

    #[test]
    fn url_extraction_trims_binary_noise() {
        let urls = extract_urls(b"xxhttp://a.example.net/p?q=1\x01\x02tailhttps://second.example.org/x");
        assert_eq!(urls.first().map(String::as_str), Some("http://a.example.net/p?q=1"));
        assert!(urls.iter().any(|url| url.starts_with("https://second.example.org")));
    }

    #[test]
    fn analysis_is_bounded_for_large_inputs() {
        let huge = vec![0x41u8; MAX_ANALYSIS_BYTES * 2];
        let prediction = analyze_static_sandbox(&huge);
        assert!(prediction.capabilities.is_empty());
    }
}
