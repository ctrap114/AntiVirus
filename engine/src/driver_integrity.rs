//! Optional integrity verification for the kernel driver image.
//!
//! The driver is a trust boundary, but the engine cannot safely infer a
//! vendor's expected digest.  Verification is therefore opt-in through
//! `EVERBLOOM_DRIVER_PATH` plus either `EVERBLOOM_DRIVER_SHA256` or a detached
//! `<driver>.sha256`/`<driver>.sys.sha256` file.  Without an expected digest,
//! the result is explicitly reported as unconfigured rather than silently
//! claiming that the image is trusted.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverIntegrityState {
    NotConfigured {
        path: Option<PathBuf>,
    },
    Verified {
        path: PathBuf,
        sha256: String,
    },
    Mismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    Unavailable {
        path: Option<PathBuf>,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverIntegrityReport {
    pub state: DriverIntegrityState,
}

impl DriverIntegrityReport {
    /// Returns false only when an explicitly configured integrity check
    /// failed or could not be performed.  Unconfigured verification is kept
    /// backward-compatible with installations that do not ship a digest.
    pub fn allows_driver_use(&self) -> bool {
        matches!(
            self.state,
            DriverIntegrityState::NotConfigured { .. } | DriverIntegrityState::Verified { .. }
        )
    }

    pub fn summary(&self) -> String {
        match &self.state {
            DriverIntegrityState::NotConfigured { path: Some(path) } => {
                format!(
                    "driver integrity digest is not configured for {}",
                    path.display()
                )
            }
            DriverIntegrityState::NotConfigured { path: None } => {
                "driver integrity verification is not configured".to_string()
            }
            DriverIntegrityState::Verified { path, sha256 } => {
                format!(
                    "driver integrity verified: {} sha256={sha256}",
                    path.display()
                )
            }
            DriverIntegrityState::Mismatch {
                path,
                expected,
                actual,
            } => format!(
                "driver integrity mismatch: {} expected={} actual={}",
                path.display(),
                expected,
                actual
            ),
            DriverIntegrityState::Unavailable { path, reason } => match path {
                Some(path) => format!(
                    "driver integrity unavailable for {}: {reason}",
                    path.display()
                ),
                None => format!("driver integrity unavailable: {reason}"),
            },
        }
    }
}

/// Verify the configured driver image, if a driver path is configured.
pub fn verify_configured_driver() -> DriverIntegrityReport {
    let path = std::env::var_os("EVERBLOOM_DRIVER_PATH").map(PathBuf::from);
    let Some(path) = path else {
        return DriverIntegrityReport {
            state: DriverIntegrityState::NotConfigured { path: None },
        };
    };

    let expected = match std::env::var("EVERBLOOM_DRIVER_SHA256") {
        Ok(value) => match normalize_digest(&value) {
            Some(value) => Some(value),
            None => {
                return DriverIntegrityReport {
                    state: DriverIntegrityState::Unavailable {
                        path: Some(path),
                        reason: "EVERBLOOM_DRIVER_SHA256 is not a 64-character hexadecimal digest"
                            .to_string(),
                    },
                }
            }
        },
        Err(_) => match detached_digest(&path) {
            Ok(value) => value,
            Err(reason) => {
                return DriverIntegrityReport {
                    state: DriverIntegrityState::Unavailable {
                        path: Some(path),
                        reason,
                    },
                }
            }
        },
    };

    let Some(expected) = expected else {
        return DriverIntegrityReport {
            state: DriverIntegrityState::NotConfigured { path: Some(path) },
        };
    };
    verify_driver_file(&path, &expected)
}

pub fn verify_driver_file<P: AsRef<Path>>(path: P, expected: &str) -> DriverIntegrityReport {
    let path = path.as_ref().to_path_buf();
    let Some(expected) = normalize_digest(expected) else {
        return DriverIntegrityReport {
            state: DriverIntegrityState::Unavailable {
                path: Some(path),
                reason: "expected digest is not a 64-character hexadecimal value".to_string(),
            },
        };
    };

    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) => {
            return DriverIntegrityReport {
                state: DriverIntegrityState::Unavailable {
                    path: Some(path),
                    reason: format!("unable to open driver image: {error}"),
                },
            }
        }
    };
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hasher.update(&buffer[..count]),
            Err(error) => {
                return DriverIntegrityReport {
                    state: DriverIntegrityState::Unavailable {
                        path: Some(path),
                        reason: format!("unable to hash driver image: {error}"),
                    },
                }
            }
        }
    }

    let actual = hex::encode(hasher.finalize());
    let state = if actual == expected {
        DriverIntegrityState::Verified {
            path,
            sha256: actual,
        }
    } else {
        DriverIntegrityState::Mismatch {
            path,
            expected,
            actual,
        }
    };
    DriverIntegrityReport { state }
}

fn detached_digest(path: &Path) -> Result<Option<String>, String> {
    let mut candidates = Vec::new();
    candidates.push(path.with_extension("sha256"));
    candidates.push(PathBuf::from(format!("{}.sha256", path.display())));
    for candidate in candidates {
        match std::fs::read_to_string(&candidate) {
            Ok(value) => {
                let digest = value
                    .split_whitespace()
                    .next()
                    .and_then(normalize_digest)
                    .ok_or_else(|| {
                        format!(
                            "detached digest {} is not a 64-character hexadecimal digest",
                            candidate.display()
                        )
                    })?;
                return Ok(Some(digest));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "unable to read detached digest {}: {error}",
                    candidate.display()
                ))
            }
        }
    }
    Ok(None)
}

fn normalize_digest(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use tempfile::tempdir;

    #[test]
    fn verifies_driver_image_and_detects_tampering() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("everbloom_driver.sys");
        std::fs::write(&path, b"signed-driver-placeholder").unwrap();
        let digest = hex::encode(Sha256::digest(b"signed-driver-placeholder"));

        let verified = verify_driver_file(&path, &digest);
        assert!(matches!(
            verified.state,
            DriverIntegrityState::Verified { .. }
        ));

        std::fs::write(&path, b"modified-driver").unwrap();
        let mismatch = verify_driver_file(&path, &digest);
        assert!(matches!(
            mismatch.state,
            DriverIntegrityState::Mismatch { .. }
        ));
    }

    #[test]
    fn invalid_digest_is_not_accepted() {
        let report = verify_driver_file("missing.sys", "not-a-digest");
        assert!(matches!(
            report.state,
            DriverIntegrityState::Unavailable { .. }
        ));
        assert!(!report.allows_driver_use());
    }
}
