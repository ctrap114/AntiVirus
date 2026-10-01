//! Privacy-preserving browser cookie theft detection.
//!
//! This layer deliberately never opens a browser cookie database to inspect
//! rows or values.  It only classifies well-known store paths and looks for
//! combinations of extraction, decryption, database and exfiltration
//! indicators in a scanned executable/script.  The same small classifier is
//! reused by the user-mode HIPS monitor.

use std::fs;
use std::path::Path;

const MAX_PROCESS_IMAGE_BYTES: u64 = 8 * 1024 * 1024;

/// Stable, content-only SilverFox credential-theft indicators. These labels
/// are used for scoring and telemetry; matched strings and browser data are
/// never returned to callers.
pub const SILVERFOX_INDICATORS: &[&str] = &[
    "Login Data",
    "Web Data",
    "Local State",
    "cryptunprotectdata",
    "telegram",
];

#[derive(Debug, Clone, PartialEq)]
pub struct CookieGuardScore {
    pub score: f32,
    /// Stable indicator labels only; never include matched strings or data
    /// read from a browser profile.
    pub indicators: Vec<String>,
    pub browser_cookie_store: bool,
}

impl CookieGuardScore {
    pub fn high_confidence(&self) -> bool {
        self.score >= 0.82 && !self.browser_cookie_store
    }

    pub fn medium_confidence(&self) -> bool {
        self.score >= 0.55 && !self.browser_cookie_store
    }
}

/// Return true for the database files used by Chromium-family browsers and
/// Firefox.  A path match is metadata only and must not be treated as a
/// malware verdict by itself.
pub fn is_browser_cookie_store(path: &Path) -> bool {
    let normalized = normalize_path(path);
    normalized.contains("\\network\\cookies")
        || normalized.contains("\\cookies.sqlite")
        || normalized.contains("\\cookies.sqlite-wal")
        || normalized.contains("\\cookies.sqlite-shm")
}

/// Only files likely to contain an executable or script are eligible for the
/// content classifier when the caller disabled the regular static engines.
/// This keeps hash-only scans cheap while still covering common stealer forms.
pub fn is_cookie_guard_candidate_file(path: &Path) -> bool {
    if is_browser_cookie_store(path) {
        return false;
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());
    matches!(
        extension.as_deref(),
        Some(
            "bat"
                | "bin"
                | "cmd"
                | "com"
                | "dat"
                | "dll"
                | "exe"
                | "hta"
                | "js"
                | "jse"
                | "ps1"
                | "py"
                | "pyw"
                | "scr"
                | "sys"
                | "vbe"
                | "vbs"
                | "wsc"
                | "wsf"
        )
    )
}

/// Browser processes are expected to access their own stores.  This is an
/// allowlist for correlation, not a trust decision for arbitrary files.
pub fn is_browser_process_name(path_or_name: &str) -> bool {
    let name = path_or_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path_or_name)
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
            | "brave.exe"
            | "opera.exe"
            | "vivaldi.exe"
            | "chromium.exe"
            | "iexplore.exe"
            | "msedgewebview2.exe"
    )
}

/// Recognize a small set of explicit browser-data utility names.  The name is
/// only a HIPS hint; the blocking decision still requires the driver path
/// guard or additional behavior evidence.
pub fn is_known_cookie_tool_name(path_or_name: &str) -> bool {
    let name = path_or_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path_or_name)
        .trim_end_matches(".exe")
        .to_ascii_lowercase();
    [
        "hackbrowserdata",
        "browsergost",
        "chromeloginview",
        "webbrowserpassview",
        "cookieextractor",
        "cookiegrabber",
        "cookiesstealer",
        "browserstealer",
        "browserdata",
        "silverfox",
    ]
    .iter()
    .any(|marker| name == *marker || name.contains(marker))
}

/// Scan an executable/script snapshot without parsing browser databases.
pub fn analyze_bytes(path: &Path, bytes: &[u8]) -> CookieGuardScore {
    let browser_cookie_store = is_browser_cookie_store(path);
    if browser_cookie_store {
        return CookieGuardScore {
            score: 0.0,
            indicators: vec!["browser_cookie_store_path".to_string()],
            browser_cookie_store: true,
        };
    }

    let browser_process = is_browser_process_name(&path.to_string_lossy());
    let known_tool = is_known_cookie_tool_name(&path.to_string_lossy());
    let store_reference = contains_any(
        bytes,
        &[
            "network\\cookies",
            "/network/cookies",
            "cookies.sqlite",
            "document.cookie",
            "navigator.cookie",
            "encrypted_value",
            "select host_key",
        ],
    );
    let database_or_credential_api = contains_any(
        bytes,
        &[
            "cookies.sqlite",
            "sqlite3",
            "select host_key",
            "host_key",
            "encrypted_value",
            "cryptunprotectdata",
            "cryptprotectdata",
            "dpapi",
            "login data",
        ],
    );
    let silverfox_browser_store = contains_any(bytes, &["login data", "web data", "local state"]);
    let silverfox_dpapi = contains_any(bytes, &["cryptunprotectdata"]);
    let silverfox_telegram = contains_any(bytes, &["telegram"]);
    let collection = contains_any(
        bytes,
        &[
            "copyfile",
            "shutil.copy",
            "file.copy",
            "readfile",
            "sqlite3",
            "select host_key",
            "document.cookie",
        ],
    );
    let exfiltration = contains_any(
        bytes,
        &[
            "invoke-webrequest",
            "invoke-restmethod",
            "webclient",
            "httpclient",
            "requests.post",
            "requests.put",
            "curl",
            "wget",
            "winhttp",
            "urlmon",
            "base64",
        ],
    );
    let archive = contains_any(bytes, &["7z", "zipfile", "archive", "compress"]);

    let mut indicators = Vec::new();
    if known_tool {
        indicators.push("known_browser_data_tool_name".to_string());
    }
    if store_reference {
        indicators.push("browser_cookie_reference".to_string());
    }
    if database_or_credential_api {
        indicators.push("browser_credential_api".to_string());
    }
    if collection {
        indicators.push("local_cookie_collection".to_string());
    }
    if exfiltration {
        indicators.push("possible_data_exfiltration".to_string());
    }
    if archive {
        indicators.push("archive_or_compression".to_string());
    }
    if silverfox_browser_store {
        indicators.push("silverfox_browser_credential_store".to_string());
    }
    if silverfox_dpapi {
        indicators.push("silverfox_dpapi_decryption".to_string());
    }
    if silverfox_telegram {
        indicators.push("silverfox_telegram_data_reference".to_string());
    }

    // A browser binary is not condemned just because its implementation
    // contains database/API strings.  The explicit tool-name hint remains
    // useful for renamed utilities and is handled by HIPS as a separate
    // signal.
    if browser_process && !known_tool {
        return CookieGuardScore {
            score: 0.0,
            indicators,
            browser_cookie_store: false,
        };
    }

    let mut score: f32 = 0.0;
    if store_reference {
        score += 0.28;
    }
    if database_or_credential_api {
        score += 0.25;
    }
    if collection {
        score += 0.15;
    }
    if exfiltration {
        score += 0.25;
    }
    if archive && store_reference {
        score += 0.12;
    }
    if known_tool {
        score += 0.45;
    }
    if silverfox_browser_store {
        score += 0.24;
    }
    if silverfox_dpapi {
        score += 0.25;
    }
    if silverfox_telegram {
        score += 0.15;
    }
    if (store_reference && database_or_credential_api && (exfiltration || archive))
        || (known_tool && (store_reference || database_or_credential_api))
    {
        score = score.max(0.90);
    }
    if silverfox_browser_store && silverfox_dpapi && (collection || exfiltration) {
        score = score.max(0.93);
    }
    if silverfox_telegram && (collection || exfiltration) {
        score = score.max(0.86);
    }

    CookieGuardScore {
        score: score.min(1.0),
        indicators,
        browser_cookie_store: false,
    }
}

/// Best-effort process-image inspection for HIPS.  It is intentionally
/// bounded and returns an empty score on access/size errors so the monitor
/// cannot become a source of CPU or memory spikes.
pub fn analyze_process_image(path: &Path) -> CookieGuardScore {
    let empty = || CookieGuardScore {
        score: 0.0,
        indicators: Vec::new(),
        browser_cookie_store: false,
    };
    let Ok(metadata) = fs::metadata(path) else {
        return empty();
    };
    if !metadata.is_file() || metadata.len() > MAX_PROCESS_IMAGE_BYTES {
        return empty();
    }
    let Ok(bytes) = fs::read(path) else {
        return empty();
    };
    analyze_bytes(path, &bytes)
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn contains_any(bytes: &[u8], needles: &[&str]) -> bool {
    needles.iter().any(|needle| {
        contains_ascii_case_insensitive(bytes, needle)
            || contains_utf16le_case_insensitive(bytes, needle)
    })
}

fn contains_ascii_case_insensitive(bytes: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    !needle.is_empty()
        && bytes.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle.iter())
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
}

fn contains_utf16le_case_insensitive(bytes: &[u8], needle: &str) -> bool {
    let encoded: Vec<u8> = needle
        .encode_utf16()
        .flat_map(|unit| [unit as u8, (unit >> 8) as u8])
        .collect();
    !encoded.is_empty()
        && bytes.windows(encoded.len()).any(|window| {
            window
                .chunks_exact(2)
                .zip(needle.encode_utf16())
                .all(|(pair, expected)| {
                    pair[0].eq_ignore_ascii_case(&(expected as u8))
                        && pair[1] == (expected >> 8) as u8
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn recognizes_chromium_and_firefox_store_paths() {
        assert!(is_browser_cookie_store(Path::new(
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
        )));
        assert!(is_browser_cookie_store(Path::new(
            r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\cookies.sqlite"
        )));
        assert!(!is_browser_cookie_store(Path::new(
            r"C:\Users\alice\Desktop\Cookies.txt"
        )));
    }

    #[test]
    fn requires_multiple_signals_for_high_confidence() {
        let score = analyze_bytes(
            Path::new(r"C:\Users\alice\Downloads\update.exe"),
            b"Network\\Cookies sqlite3 CryptUnProtectData Invoke-WebRequest base64",
        );
        assert!(score.high_confidence());
        assert!(score
            .indicators
            .iter()
            .all(|value| !value.contains("secret")));
    }

    #[test]
    fn a_cookie_store_path_is_metadata_only() {
        let score = analyze_bytes(
            Path::new(r"C:\Users\alice\AppData\Local\Chrome\User Data\Default\Network\Cookies"),
            b"encrypted_value=secret_cookie_value",
        );
        assert!(score.browser_cookie_store);
        assert_eq!(score.score, 0.0);
        assert!(!score
            .indicators
            .iter()
            .any(|value| value.contains("secret")));
    }

    #[test]
    fn utf16_indicators_are_detected_without_returning_contents() {
        let bytes: Vec<u8> = "cookies.sqlite\0Invoke-WebRequest"
            .encode_utf16()
            .flat_map(|unit| [unit as u8, (unit >> 8) as u8])
            .collect();
        let score = analyze_bytes(Path::new(r"C:\Temp\loader.ps1"), &bytes);
        assert!(score.medium_confidence());
        assert!(score
            .indicators
            .iter()
            .all(|value| !value.contains("cookies.sqlite")));
    }

    #[test]
    fn silverfox_credential_chain_is_high_confidence() {
        let score = analyze_bytes(
            Path::new(r"C:\Users\alice\AppData\Local\Temp\loader.exe"),
            b"Login Data Web Data Local State CryptUnProtectData telegram requests.post",
        );
        assert!(score.high_confidence());
        assert!(score
            .indicators
            .iter()
            .any(|value| value == "silverfox_browser_credential_store"));
        assert!(score
            .indicators
            .iter()
            .all(|value| !value.contains("Login Data")));
    }
}
