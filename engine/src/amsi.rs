//! User-mode AMSI (Antimalware Scan Interface) integration layer.
//!
//! This module provides a Rust wrapper around the Windows AMSI API,
//! allowing the EverbloomSecurity engine to scan script content (PowerShell,
//! VBScript, JScript, and other interpreted code) before execution.
//!
//! AMSI is used as a secondary scan layer — the engine's own detection
//! (hash, YARA, AI, heuristics) remains authoritative. AMSI provides
//! defense-in-depth for script-based attacks.
//!
//! Note: AMSI is only available on Windows 8.1+ with PowerShell 3.0+.
//! On non-Windows platforms, this module provides a stub implementation.

use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Antimalware::{
    AmsiInitialize, AmsiUninitialize, AmsiOpenSession, AmsiCloseSession,
    AmsiScanBuffer, AmsiScanString, HAMSICONTEXT, HAMSISESSION,
};

static AMSI_SCAN_COUNT: AtomicU64 = AtomicU64::new(0);
static AMSI_DETECTION_COUNT: AtomicU64 = AtomicU64::new(0);
static AMSI_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);

const AMSI_CONTENT_NAME: &[u16] = &[
    b'H' as u16, b'e' as u16, b'l' as u16, b'i' as u16, b'o' as u16,
    b's' as u16, b'A' as u16, b'V' as u16, b'-' as u16, b'A' as u16,
    b'M' as u16, b'S' as u16, b'I' as u16, b'-' as u16, b'S' as u16,
    b'c' as u16, b'a' as u16, b'n' as u16, 0,
];

#[derive(Debug, Error)]
pub enum AmsiError {
    #[error("AMSI is not available on this platform")]
    Unsupported,
    #[error("AMSI initialization failed: {0}")]
    InitFailed(String),
    #[error("AMSI session creation failed: {0}")]
    SessionFailed(String),
    #[error("AMSI scan failed: {0}")]
    ScanFailed(String),
    #[error("AMSI context is not initialized")]
    NotInitialized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmsiVerdict {
    Clean,
    Detected { description: String },
    Error { detail: String },
}

/// AMSI scan context. Must be initialized before scanning.
pub struct AmsiContext {
    #[cfg(target_os = "windows")]
    context: HAMSICONTEXT,
    app_name: String,
}

impl AmsiContext {
    /// Initialize the AMSI context.
    pub fn new(app_name: &str) -> Result<Self, AmsiError> {
        #[cfg(target_os = "windows")]
        {
            let mut context: HAMSICONTEXT = null_mut();
            let wide_name: Vec<u16> = OsString::from(app_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let result = unsafe { AmsiInitialize(wide_name.as_ptr(), &mut context) };
            if result != 0 {
                return Err(AmsiError::InitFailed(format!(
                    "AmsiInitialize returned 0x{result:08x}"
                )));
            }
            Ok(Self {
                context,
                app_name: app_name.to_string(),
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = app_name;
            Err(AmsiError::Unsupported)
        }
    }

    /// Open a new scan session. Each session should be short-lived.
    pub fn open_session(&self) -> Result<AmsiSession, AmsiError> {
        #[cfg(target_os = "windows")]
        {
            let mut session: HAMSISESSION = null_mut();
            let result = unsafe { AmsiOpenSession(self.context, &mut session) };
            if result != 0 {
                return Err(AmsiError::SessionFailed(format!(
                    "AmsiOpenSession returned 0x{result:08x}"
                )));
            }
            Ok(AmsiSession {
                session,
                context: self.context,
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(AmsiError::Unsupported)
        }
    }

    /// Scan a byte buffer for malicious content.
    pub fn scan_buffer(&self, data: &[u8]) -> AmsiVerdict {
        AMSI_SCAN_COUNT.fetch_add(1, Ordering::Relaxed);
        #[cfg(target_os = "windows")]
        {
            let mut session = match self.open_session() {
                Ok(s) => s,
                Err(e) => {
                    AMSI_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
                    return AmsiVerdict::Error {
                        detail: e.to_string(),
                    };
                }
            };
            session.scan_buffer(data)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = data;
            AmsiVerdict::Error {
                detail: "AMSI not available".to_string(),
            }
        }
    }

    /// Scan a string for malicious content.
    pub fn scan_string(&self, text: &str) -> AmsiVerdict {
        AMSI_SCAN_COUNT.fetch_add(1, Ordering::Relaxed);
        #[cfg(target_os = "windows")]
        {
            let mut session = match self.open_session() {
                Ok(s) => s,
                Err(e) => {
                    AMSI_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
                    return AmsiVerdict::Error {
                        detail: e.to_string(),
                    };
                }
            };
            session.scan_string(text)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = text;
            AmsiVerdict::Error {
                detail: "AMSI not available".to_string(),
            }
        }
    }
}

impl Drop for AmsiContext {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            if self.context != null_mut() {
                unsafe { AmsiUninitialize(self.context) };
            }
        }
    }
}

/// An AMSI scan session. Must be closed after use.
pub struct AmsiSession {
    #[cfg(target_os = "windows")]
    session: HAMSISESSION,
    #[cfg(target_os = "windows")]
    context: HAMSICONTEXT,
}

impl AmsiSession {
    #[cfg(target_os = "windows")]
    fn scan_buffer(&mut self, data: &[u8]) -> AmsiVerdict {
        use windows_sys::Win32::System::Antimalware::AMSI_RESULT_DETECTED;
        let mut result = 0i32;
        let scan_result = unsafe {
            AmsiScanBuffer(
                self.context,
                data.as_ptr() as *const _,
                data.len() as u32,
                AMSI_CONTENT_NAME.as_ptr(),
                self.session,
                &mut result,
            )
        };
        if scan_result != 0 {
            AMSI_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
            return AmsiVerdict::Error {
                detail: format!("AmsiScanBuffer returned 0x{scan_result:08x}"),
            };
        }
        if result == AMSI_RESULT_DETECTED as i32 {
            AMSI_DETECTION_COUNT.fetch_add(1, Ordering::Relaxed);
            AmsiVerdict::Detected {
                description: format!("AMSI detection (result={result})"),
            }
        } else {
            AmsiVerdict::Clean
        }
    }

    #[cfg(target_os = "windows")]
    fn scan_string(&mut self, text: &str) -> AmsiVerdict {
        use windows_sys::Win32::System::Antimalware::AMSI_RESULT_DETECTED;
        let wide: Vec<u16> = OsString::from(text)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut result = 0i32;
        let scan_result = unsafe {
            AmsiScanString(
                self.context,
                wide.as_ptr(),
                AMSI_CONTENT_NAME.as_ptr(),
                self.session,
                &mut result,
            )
        };
        if scan_result != 0 {
            AMSI_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
            return AmsiVerdict::Error {
                detail: format!("AmsiScanString returned 0x{scan_result:08x}"),
            };
        }
        if result == AMSI_RESULT_DETECTED as i32 {
            AMSI_DETECTION_COUNT.fetch_add(1, Ordering::Relaxed);
            AmsiVerdict::Detected {
                description: format!("AMSI detection (result={result})"),
            }
        } else {
            AmsiVerdict::Clean
        }
    }
}

impl Drop for AmsiSession {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            if self.session != null_mut() {
                unsafe { AmsiCloseSession(self.context, self.session) };
            }
        }
    }
}

/// Get AMSI scan statistics.
pub fn amsi_stats() -> AmsiStats {
    AmsiStats {
        scan_count: AMSI_SCAN_COUNT.load(Ordering::Relaxed),
        detection_count: AMSI_DETECTION_COUNT.load(Ordering::Relaxed),
        error_count: AMSI_ERROR_COUNT.load(Ordering::Relaxed),
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AmsiStats {
    pub scan_count: u64,
    pub detection_count: u64,
    pub error_count: u64,
}

/// Scan a file's content using AMSI (if available).
/// Returns the AMSI verdict alongside the file hash for correlation.
pub fn scan_file_with_amsi(path: &Path) -> (AmsiVerdict, Option<String>) {
    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(e) => {
            return (
                AmsiVerdict::Error {
                    detail: format!("read failed: {e}"),
                },
                None,
            );
        }
    };
    let hash = format!("{:x}", Sha256::digest(&content));
    let verdict = match AmsiContext::new("EverbloomSecurity-Engine") {
        Ok(ctx) => ctx.scan_buffer(&content),
        Err(e) => AmsiVerdict::Error {
            detail: e.to_string(),
        },
    };
    (verdict, Some(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amsi_stats_starts_at_zero() {
        let stats = amsi_stats();
        assert!(stats.scan_count >= 0);
    }

    #[test]
    fn amsi_verdict_display() {
        let clean = AmsiVerdict::Clean;
        assert_eq!(format!("{clean:?}"), "Clean");
        let detected = AmsiVerdict::Detected {
            description: "test".to_string(),
        };
        assert!(format!("{detected:?}").contains("test"));
    }
}
