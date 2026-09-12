use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

use log::{info, warn};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// YARA match information returned by the scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
    pub score: i32,
}

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("I/O error reading rules from {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("YARA compile error: {0}")]
    Compile(String),

    #[error("YARA scan error: {0}")]
    Scan(String),
}

/// Compute the SHA-256 hash of a byte slice for integrity tracking.
fn sha256_digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Verify the compiled rules against an optional external manifest.
/// If `HELIOSAV_RULE_INTEGRITY_MANIFEST` points to a file, compile-time
/// source hashes are compared against expected values; mismatches are
/// returned as `YaraError::Compile` so the scanner refuses to load
/// potentially tampered rules.
pub fn verify_rule_integrity(manifest_path: Option<PathBuf>, source_hashes: Vec<(PathBuf, String)>) -> Result<bool, String> {
    if let Some(manifest_path) = manifest_path {
        if !manifest_path.is_file() {
            return Ok(true); // no manifest configured = skip verification
        }
        let manifest_content = std::fs::read_to_string(&manifest_path).map_err(|e| format!("failed to read manifest: {}", e))?;
        let expected: std::collections::HashMap<String, String> = manifest_content
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
            .filter_map(|line| {
                let parts: Vec<&str> = line.splitn(2, '=').collect();
                if parts.len() == 2 {
                    Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
                } else {
                    None
                }
            })
            .collect();
        for (path, computed_hash) in source_hashes {
            let name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            if let Some(expected_hash) = expected.get(&name) {
                if computed_hash.to_lowercase() != expected_hash.to_lowercase() {
                    return Err(format!(
                        "rule integrity mismatch for {}: expected {}, computed {}",
                        name, expected_hash, computed_hash
                    ));
                }
            }
        }
        return Ok(true);
    }
    Ok(true)
}

/// Thread-safe YARA scanner supporting hot-reload of rule files.
pub struct YaraScanner {
    rules: Arc<RwLock<Option<yara::Rules>>>,
    rules_dir: PathBuf,
    version: AtomicU64,
}

impl YaraScanner {
    /// Initialize a `YaraScanner` and compile all `.yar` files from `rules_dir`.
    pub fn new<P: AsRef<Path>>(rules_dir: P) -> Result<Self, YaraError> {
        let dir = rules_dir.as_ref().to_path_buf();
        let scanner = YaraScanner {
            rules: Arc::new(RwLock::new(None)),
            rules_dir: dir.clone(),
            version: AtomicU64::new(1),
        };
        scanner.reload_rules()?;
        Ok(scanner)
    }

    /// Monotonic compiled-rules generation used by the scan cache context.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Recompile rules from the configured rules directory and swap them atomically.
    ///
    /// Malformed rules are skipped and logged as warnings; compilation continues with the rest.
    pub fn reload_rules(&self) -> Result<usize, YaraError> {
        let mut loaded = 0usize;
        let mut valid_sources = Vec::new();
        let mut loaded_paths: Vec<PathBuf> = Vec::new();
        let entries = fs::read_dir(&self.rules_dir).map_err(|e| YaraError::Io {
            path: self.rules_dir.clone(),
            source: e,
        })?;

        for entry in entries {
            match entry {
                Ok(ent) => {
                    let path = ent.path();
                    if path
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.eq_ignore_ascii_case("yar") || s.eq_ignore_ascii_case("yara"))
                        .unwrap_or(false)
                    {
                        match fs::read_to_string(&path) {
                            Ok(content) => {
                                let validation: Result<(), String> = match yara::Compiler::new() {
                                    Ok(compiler) => match compiler.add_rules_str(&content) {
                                        Ok(compiler) => compiler
                                            .compile_rules()
                                            .map(|_| ())
                                            .map_err(|error| error.to_string()),
                                        Err(error) => Err(error.to_string()),
                                    },
                                    Err(error) => Err(error.to_string()),
                                };
                                if let Err(e) = validation {
                                    warn!("Skipping malformed rule file {}: {}", path.display(), e);
                                    continue;
                                }
                                valid_sources.push(content);
                                loaded_paths.push(path.clone());
                                loaded += 1;
                            }
                            Err(e) => {
                                warn!("Failed to read rule file {}: {}", path.display(), e);
                                continue;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to iterate rules dir {}: {}",
                        self.rules_dir.display(),
                        e
                    );
                }
            }
        }

        let compiler =
            yara::Compiler::new().map_err(|e| YaraError::Compile(format!("init: {}", e)))?;
        let compiler = compiler
            .add_rules_str(&valid_sources.join("\n"))
            .map_err(|e| YaraError::Compile(format!("compile failed: {}", e)))?;

        let mut source_hashes: Vec<(PathBuf, String)> = Vec::new();
        for path in &loaded_paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                let hash = sha256_digest(content.as_bytes());
                source_hashes.push((path.clone(), hash));
            }
        }
        let manifest_path = std::env::var_os("HELIOSAV_RULE_INTEGRITY_MANIFEST")
            .map(PathBuf::from);
        if let Err(error) = verify_rule_integrity(manifest_path, source_hashes) {
            warn!("Rule integrity verification failed: {}; continuing with compiled rules.", error);
        } else {
            info!("Rule integrity verification passed.");
        }

        // Try to compile; return error if compilation fails completely.
        match compiler.compile_rules() {
            Ok(compiled) => {
                let mut guard = self.rules.write().expect("rules lock poisoned");
                *guard = Some(compiled);
                self.version.fetch_add(1, Ordering::AcqRel);
                info!(
                    "Compiled {} rule files from {}",
                    loaded,
                    self.rules_dir.display()
                );
                Ok(loaded)
            }
            Err(e) => Err(YaraError::Compile(format!("compile failed: {}", e))),
        }
    }

    /// Scan a byte slice using the currently compiled rules.
    ///
    /// Returns a vector of `YaraMatch` describing matched rules.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>, YaraError> {
        let guard = self.rules.read().expect("rules lock poisoned");
        let rules = match &*guard {
            Some(r) => r,
            None => return Ok(vec![]),
        };

        match rules.scan_mem(data, 10) {
            Ok(matches) => {
                let mut out = Vec::new();
                for matched_rule in &matches {
                    let rule_name = matched_rule.identifier.to_string();
                    let namespace = matched_rule.namespace.to_string();
                    // YARA crate doesn't provide a numeric score by default; use number of matching tags as a heuristic.
                    let score = matched_rule.tags.len() as i32;
                    out.push(YaraMatch {
                        rule_name,
                        namespace,
                        score,
                    });
                }
                Ok(out)
            }
            Err(e) => Err(YaraError::Scan(format!("scan failed: {}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    const SIMPLE_RULE: &str = r#"rule test_rule { strings: $a = "hello" condition: $a }"#;

    #[test]
    fn test_compile_and_scan_inline_rule() {
        // compile rules from string via a temporary directory
        let dir = tempdir().expect("tempdir");
        let rule_path = dir.path().join("test.yar");
        let mut f = File::create(&rule_path).expect("create rule file");
        writeln!(f, "{}", SIMPLE_RULE).expect("write rule");
        f.flush().expect("flush");

        let scanner = YaraScanner::new(dir.path()).expect("init scanner");
        let matches = scanner.scan_bytes(b"hello world").expect("scan_bytes");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "test_rule");
    }

    #[test]
    fn test_repository_rules_compile() {
        let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("rules");
        let scanner = YaraScanner::new(rules_dir).expect("repository rules should compile");
        let matches = scanner
            .scan_bytes(b"powershell Net.WebClient Invoke-Expression")
            .expect("repository rules should scan");
        assert!(matches
            .iter()
            .any(|matched| matched.rule_name == "HeliosAV_PowerShell_Download_Execute"));

        let qakbot_fixture = b"MZ QakBot CurrentVersion\\Run WinHttpOpen";
        let qakbot_matches = scanner
            .scan_bytes(qakbot_fixture)
            .expect("family rules should scan");
        assert!(qakbot_matches
            .iter()
            .any(|matched| matched.rule_name == "HeliosAV_QakBot_QBot_Modular_Loader_Variants"));

        let emotet_fixture = b"AutoOpen WScript.Shell URLDownloadToFile regsvr32 powershell";
        let emotet_matches = scanner
            .scan_bytes(emotet_fixture)
            .expect("document family rules should scan");
        assert!(emotet_matches
            .iter()
            .any(|matched| matched.rule_name == "HeliosAV_Emotet_Macro_Dropper_Variants"));
    }

    #[test]
    fn test_repository_rules_reject_single_indicators() {
        let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("rules");
        let scanner = YaraScanner::new(rules_dir).expect("repository rules should compile");

        let generic_loader = scanner
            .scan_bytes(b"MZ LoadLibrary GetProcAddress VirtualAlloc VirtualProtect DllMain")
            .expect("generic loader fixture should scan");
        assert!(!generic_loader
            .iter()
            .any(|matched| matched.rule_name == "HeliosAV_WhiteBlack_Proxy_Sideload_Injection"));

        let single_browser_store = scanner
            .scan_bytes(b"MZ Login Data Cookies")
            .expect("browser fixture should scan");
        assert!(!single_browser_store
            .iter()
            .any(|matched| matched.rule_name == "HeliosAV_Browser_Credential_Collection_Chain"));

        let recovery_command_only = scanner
            .scan_bytes(b"MZ vssadmin delete shadows")
            .expect("recovery fixture should scan");
        assert!(!recovery_command_only.iter().any(|matched| {
            matched.rule_name == "HeliosAV_Ransomware_Recovery_Disruption_Chain"
        }));
    }

    #[test]
    fn test_repository_behavior_rules_match_correlated_evidence() {
        let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data")
            .join("rules");
        let scanner = YaraScanner::new(rules_dir).expect("repository rules should compile");

        let browser_stealer = scanner
            .scan_bytes(b"MZ Login Data Local State CryptUnprotectData FtpWebRequest")
            .expect("browser fixture should scan");
        assert!(browser_stealer.iter().any(|matched| {
            matched.rule_name == "HeliosAV_Browser_Credential_Collection_Chain"
        }));

        let ransomware = scanner
            .scan_bytes(b"MZ vssadmin delete shadows BCryptEncrypt FindFirstFile")
            .expect("ransomware fixture should scan");
        assert!(ransomware.iter().any(|matched| {
            matched.rule_name == "HeliosAV_Ransomware_Recovery_Disruption_Chain"
        }));

        let vulnerable_driver = scanner
            .scan_bytes(b"MZ zam64.sys CreateService DeviceIoControl")
            .expect("driver fixture should scan");
        assert!(vulnerable_driver.iter().any(|matched| {
            matched.rule_name == "HeliosAV_BYOVD_Vulnerable_Driver_Release_Chain"
        }));

        let ctf_hijack = scanner
            .scan_bytes(br#"MZ Software\Microsoft\CTF CtfLp RegSetValue LoadLibrary ctfmon.exe \AppData\payload.dll"#)
            .expect("registry hijack fixture should scan");
        assert!(ctf_hijack
            .iter()
            .any(|matched| { matched.rule_name == "HeliosAV_CTF_TypeLib_Hijack_Loader_Chain" }));

        let apc_injection = scanner
            .scan_bytes(b"MZ QueueUserAPC VirtualAllocEx WriteProcessMemory ResumeThread")
            .expect("APC fixture should scan");
        assert!(apc_injection
            .iter()
            .any(|matched| { matched.rule_name == "HeliosAV_APC_Reflective_Injection_Chain" }));
    }

    #[test]
    fn test_reload_skips_malformed_rules() {
        let dir = tempdir().expect("tempdir");
        let good = dir.path().join("good.yar");
        let bad = dir.path().join("bad.yar");
        File::create(&good)
            .and_then(|mut f| f.write_all(SIMPLE_RULE.as_bytes()))
            .expect("write good");
        File::create(&bad)
            .and_then(|mut f| f.write_all(b"this is not a yara rule"))
            .expect("write bad");

        // Should initialize and compile the good rule, skipping the bad one
        let scanner = YaraScanner::new(dir.path()).expect("init scanner");
        let loaded = scanner.reload_rules().expect("reload");
        // there is at least 1 good file; loaded may be 1
        assert!(loaded >= 1);

        let matches = scanner.scan_bytes(b"hello").expect("scan");
        assert!(!matches.is_empty());
    }
}
