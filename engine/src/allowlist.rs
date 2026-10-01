//! Conservative allowlist support for files that are known to be legitimate.
//!
//! The allowlist deliberately does not short-circuit the whole scan. Exact
//! hashes, YARA matches and high-confidence runtime behavior remain
//! authoritative. An allowlist match only suppresses the noisy static/AI
//! layers for a trusted file, which prevents a path or process-name match from
//! becoming a malware bypass.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

const BUILTIN_PROCESS_NAMES: &[&str] = &[
    "audiodg.exe",
    "csrss.exe",
    "conhost.exe",
    "dllhost.exe",
    "dwm.exe",
    "explorer.exe",
    "lsass.exe",
    "services.exe",
    "securityhealthservice.exe",
    "smss.exe",
    "spoolsv.exe",
    "svchost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "wininit.exe",
    "winlogon.exe",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowlistMatch {
    TrustedSystemProcess(String),
    ConfiguredPath(String),
    TrustedSha256(String),
}

impl AllowlistMatch {
    pub fn reason(&self) -> String {
        match self {
            Self::TrustedSystemProcess(name) => format!("trusted_system_process:{name}"),
            Self::ConfiguredPath(path) => format!("configured_path:{path}"),
            Self::TrustedSha256(hash) => format!("trusted_sha256:{hash}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Allowlist {
    enabled: bool,
    allow_builtin_system_processes: bool,
    configured_paths: Arc<RwLock<Vec<String>>>,
    trusted_sha256: Arc<RwLock<HashSet<String>>>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct AllowlistFile {
    enabled: Option<bool>,
    allow_builtin_system_processes: Option<bool>,
    paths: Option<Vec<String>>,
    sha256: Option<Vec<String>>,
}

/// Resolves the allowlist file the engine reads -- EVERBLOOM_ALLOWLIST_FILE, or
/// the packaged data/allowlist.json. Used for both loading and persistence.
pub fn allowlist_file_path() -> PathBuf {
    std::env::var_os("EVERBLOOM_ALLOWLIST_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data/allowlist.json"))
}

/// Persists a file's SHA-256 and canonical path into the allowlist file so
/// `matches()` suppresses the noisy layers on future scans. Fails closed: an
/// unreadable or unparseable config file is never overwritten blindly.
pub fn add_trusted_sha256(path: &Path) -> Result<String, String> {
    let hash = sha256_file(path)
        .map_err(|error| format!("unable to hash {}: {error}", path.display()))?;
    let canonical = canonical_or_normalized(path);

    let file_path = allowlist_file_path();
    let mut config = if file_path.is_file() {
        let content = std::fs::read_to_string(&file_path)
            .map_err(|error| format!("unable to read {}: {error}", file_path.display()))?;
        serde_json::from_str::<AllowlistFile>(&content)
            .map_err(|error| format!("invalid allowlist {}: {error}", file_path.display()))?
    } else {
        AllowlistFile {
            enabled: Some(true),
            allow_builtin_system_processes: Some(true),
            paths: Some(Vec::new()),
            sha256: Some(Vec::new()),
        }
    };

    let mut paths = config.paths.unwrap_or_default();
    if !paths.iter().any(|entry| entry == &canonical) {
        paths.push(canonical);
    }
    let mut hashes = config.sha256.unwrap_or_default();
    if !hashes.iter().any(|entry| entry.eq_ignore_ascii_case(&hash)) {
        hashes.push(hash.clone());
    }
    config.paths = Some(paths);
    config.sha256 = Some(hashes);

    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("unable to create {}: {error}", parent.display()))?;
    }
    let encoded = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("unable to serialize allowlist: {error}"))?;
    std::fs::write(&file_path, encoded)
        .map_err(|error| format!("unable to write {}: {error}", file_path.display()))?;
    Ok(hash)
}

impl Allowlist {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            allow_builtin_system_processes: false,
            configured_paths: Arc::new(RwLock::new(Vec::new())),
            trusted_sha256: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn builtin() -> Self {
        Self {
            enabled: true,
            allow_builtin_system_processes: true,
            configured_paths: Arc::new(RwLock::new(Vec::new())),
            trusted_sha256: Arc::new(RwLock::new(HashSet::new())),
        }
    }

/// Load an optional JSON allowlist. Missing files leave the conservative
    /// built-in Windows process list enabled; malformed files fail closed for
    /// the user-supplied entries and are reported to the caller.
    pub fn load_optional(path: Option<&Path>) -> Result<Self, String> {
        let mut result = Self::builtin();
        let Some(path) = path else {
            return Ok(result);
        };
        if !path.is_file() {
            return Ok(result);
        }

        let content = std::fs::read_to_string(path)
            .map_err(|error| format!("unable to read allowlist {}: {error}", path.display()))?;
        let config: AllowlistFile = serde_json::from_str(&content)
            .map_err(|error| format!("invalid allowlist {}: {error}", path.display()))?;

        result.enabled = config.enabled.unwrap_or(true);
        result.allow_builtin_system_processes =
            config.allow_builtin_system_processes.unwrap_or(true);
        *result
            .configured_paths
            .write()
            .map_err(|_| "allowlist path set poisoned".to_string())? = config
            .paths
            .unwrap_or_default()
            .into_iter()
            .map(|value| normalize_path_string(&value))
            .filter(|value| !value.is_empty())
            .collect();
        *result
            .trusted_sha256
            .write()
            .map_err(|_| "allowlist hash set poisoned".to_string())? = config
            .sha256
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| is_sha256(value))
            .collect();
        Ok(result)
    }

    /// Uses EVERBLOOM_ALLOWLIST_FILE when supplied, otherwise the packaged
    /// data/allowlist.json file when it exists.
    pub fn load_from_environment() -> Result<Self, String> {
        let configured = std::env::var_os("EVERBLOOM_ALLOWLIST_FILE")
            .map(PathBuf::from)
            .or_else(|| {
                let path = PathBuf::from("data/allowlist.json");
                path.is_file().then_some(path)
            });
        Self::load_optional(configured.as_deref())
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn builtin_system_processes_enabled(&self) -> bool {
        self.allow_builtin_system_processes
    }

    /// Returns a match only for a canonical configured path, a known Windows
    /// system process in System32/SysWOW64, or a trusted SHA-256. A process
    /// name alone is never sufficient.
    pub fn matches(&self, path: &Path) -> Option<AllowlistMatch> {
        if !self.enabled || !path.is_file() {
            return None;
        }

        let normalized = canonical_or_normalized(path);
        let configured_paths = self.configured_paths.read().map_err(|_| ()).ok();
        if let Some(paths) = &configured_paths {
            if let Some(configured) = paths
                .iter()
                .find(|configured| path_matches(configured, &normalized))
            {
                return Some(AllowlistMatch::ConfiguredPath(configured.clone()));
            }
        }

        if self.allow_builtin_system_processes && is_builtin_system_process(&normalized) {
            let name = Path::new(&normalized)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            return Some(AllowlistMatch::TrustedSystemProcess(name));
        }

        let trusted_sha256 = self.trusted_sha256.read().map_err(|_| ()).ok();
        if let Some(hashes) = &trusted_sha256 {
            if !hashes.is_empty() {
                if let Ok(hash) = sha256_file(path) {
                    if hashes.contains(&hash) {
                        return Some(AllowlistMatch::TrustedSha256(hash));
                    }
                }
            }
        }

        None
    }

    /// Adds a file to the allowlist at runtime: the canonical path and SHA-256
    /// are inserted into this live instance (so pending scans honour them
    /// immediately) and persisted to the allowlist JSON for the next session.
    pub fn add_trusted(&self, path: &Path) -> Result<String, String> {
        let hash = sha256_file(path)
            .map_err(|error| format!("unable to hash {}: {error}", path.display()))?;
        let canonical = canonical_or_normalized(path);

        {
            let mut paths = self
                .configured_paths
                .write()
                .map_err(|_| "allowlist path set poisoned".to_string())?;
            if !paths.iter().any(|entry| entry == &canonical) {
                paths.push(canonical);
            }
        }
        {
            let mut hashes = self
                .trusted_sha256
                .write()
                .map_err(|_| "allowlist hash set poisoned".to_string())?;
            hashes.insert(hash.clone());
        }

        // Keep the on-disk copy and the live instance consistent so a restart
        // does not forget the update.
        add_trusted_sha256(path)?;
        Ok(hash)
    }
}

impl std::default::Default for Allowlist {
    fn default() -> Self {
        Self::builtin()
    }
}

fn normalize_path_string(value: &str) -> String {
    let normalized = value
        .trim()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    normalized
        .strip_prefix("\\\\?\\")
        .unwrap_or(&normalized)
        .to_string()
}

fn canonical_or_normalized(path: &Path) -> String {
    let value = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned();
    normalize_path_string(&value)
}

fn path_matches(pattern: &str, normalized: &str) -> bool {
    if pattern.ends_with("\\*") {
        let prefix = pattern.trim_end_matches('*');
        normalized.starts_with(prefix)
    } else {
        pattern == normalized
    }
}

#[cfg(windows)]
fn is_builtin_system_process(path: &str) -> bool {
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
    let root = normalize_path_string(&windir);
    let system32 = format!("{root}\\system32\\");
    let syswow64 = format!("{root}\\syswow64\\");
    let in_trusted_directory = path.starts_with(&system32) || path.starts_with(&syswow64);
    let name = Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    in_trusted_directory && BUILTIN_PROCESS_NAMES.contains(&name.as_str())
}

#[cfg(not(windows))]
fn is_builtin_system_process(_path: &str) -> bool {
    false
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::tempdir;

    // Tests that switch EVERBLOOM_ALLOWLIST_FILE touch a process-global env var;
    // serialize them so parallel runs cannot point each other at the wrong file.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn configured_path_is_only_match_when_file_exists() {
        let dir = tempdir().expect("tempdir");
        let sample = dir.path().join("trusted.exe");
        std::fs::File::create(&sample)
            .expect("sample")
            .write_all(b"clean fixture")
            .expect("write");
        let json = serde_json::json!({
            "paths": [sample.to_string_lossy().to_string()]
        })
        .to_string();
        let config_path = dir.path().join("allowlist.json");
        std::fs::write(&config_path, json).expect("config");
        let allowlist = Allowlist::load_optional(Some(&config_path)).expect("load");
        assert!(matches!(
            allowlist.matches(&sample),
            Some(AllowlistMatch::ConfiguredPath(_))
        ));
    }

    #[test]
    fn add_trusted_sha256_round_trips_and_matches() {
        let _guard = ENV_GUARD.lock().unwrap();
        let dir = tempdir().expect("tempdir");
        let sample = dir.path().join("trusted.bin");
        std::fs::write(&sample, b"trusted fixture").expect("write");
        let config_path = dir.path().join("allowlist.json");
        std::env::set_var("EVERBLOOM_ALLOWLIST_FILE", &config_path);
        let persisted = add_trusted_sha256(&sample);
        std::env::remove_var("EVERBLOOM_ALLOWLIST_FILE");
        let hash = persisted.expect("persisted hash");
        assert_eq!(hash.len(), 64);
        let allowlist = Allowlist::load_optional(Some(&config_path)).expect("load");
        // The canonical path takes precedence in `matches()`, but the SHA-256
        // must have been persisted too: a path move must still be recognised.
        assert!(allowlist.matches(&sample).is_some());
        let persisted_content = std::fs::read_to_string(&config_path).expect("read");
        assert!(persisted_content.contains(&hash));
        assert!(persisted_content.contains("\"sha256\""));
    }

    #[test]
    fn add_trusted_updates_live_instance() {
        let _guard = ENV_GUARD.lock().unwrap();
        let allowlist = Allowlist::builtin();
        assert!(allowlist.matches(Path::new(r"C:\missing.exe")).is_none());
        let dir = tempdir().expect("tempdir");
        let sample = dir.path().join("live.bin");
        std::fs::write(&sample, b"live fixture").expect("write");
        let config_path = dir.path().join("allowlist.json");
        std::env::set_var("EVERBLOOM_ALLOWLIST_FILE", &config_path);
        let added = allowlist.add_trusted(&sample);
        std::env::remove_var("EVERBLOOM_ALLOWLIST_FILE");
        assert!(added.is_ok());
        assert!(allowlist.matches(&sample).is_some());
    }
}
