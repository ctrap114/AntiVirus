//! Encrypted scan report generation.
//!
//! This module generates JSON scan reports that can be optionally
//! encrypted using the EverbloomSecurity custom stream cipher. Reports include
//! scan results, engine metadata, and integrity verification.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{encrypt_payload, decrypt_payload, compute_tag_custom, verify_tag_custom};

const REPORT_FORMAT_VERSION: u32 = 1;
const REPORT_MAGIC: &[u8] = b"EVERBLOOM-REPORT-v1\n";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub format_version: u32,
    pub report_id: String,
    pub generated_at: u64,
    pub engine_name: String,
    pub engine_version: String,
    pub scan_results: Vec<ScanReportEntry>,
    pub summary: ReportSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReportEntry {
    pub file_path: String,
    pub sha256: String,
    pub verdict: String,
    pub confidence: Option<f32>,
    pub threat_name: Option<String>,
    pub threat_category: Option<String>,
    pub matched_rules: Vec<String>,
    pub scan_time_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_files: usize,
    pub malicious_count: usize,
    pub suspicious_count: usize,
    pub clean_count: usize,
    pub error_count: usize,
    pub total_scan_time_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedReport {
    pub report_id: String,
    pub encrypted_payload: Vec<u8>,
    pub integrity_tag: [u8; 32],
}

impl ScanReport {
    /// Create a new scan report.
    pub fn new(
        engine_name: &str,
        engine_version: &str,
        scan_results: Vec<ScanReportEntry>,
    ) -> Self {
        let summary = ReportSummary::from_results(&scan_results);
        let report_id = format!(
            "RPT-{}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::process::id()
        );
        Self {
            format_version: REPORT_FORMAT_VERSION,
            report_id,
            generated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            engine_name: engine_name.to_string(),
            engine_version: engine_version.to_string(),
            scan_results,
            summary,
        }
    }

    /// Serialize the report to JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| format!("serialize failed: {e}"))
    }

    /// Serialize and encrypt the report.
    pub fn to_encrypted_report(&self, key: &[u8]) -> Result<EncryptedReport, String> {
        let json_bytes = self.to_json_bytes()?;
        let encrypted = encrypt_payload(&json_bytes, key);
        let tag = compute_tag_custom(key, &encrypted);
        Ok(EncryptedReport {
            report_id: self.report_id.clone(),
            encrypted_payload: encrypted,
            integrity_tag: tag,
        })
    }

    /// Save the report as plaintext JSON.
    pub fn save_plaintext(&self, path: &PathBuf) -> Result<(), String> {
        let bytes = self.to_json_bytes()?;
        std::fs::write(path, bytes).map_err(|e| format!("write failed: {e}"))?;
        Ok(())
    }

    /// Save the report as encrypted binary.
    pub fn save_encrypted(&self, path: &PathBuf, key: &[u8]) -> Result<(), String> {
        let encrypted = self.to_encrypted_report(key)?;
        let mut output = Vec::new();
        output.extend_from_slice(REPORT_MAGIC);
        output.extend_from_slice(&encrypted.report_id.len().to_le_bytes());
        output.extend_from_slice(encrypted.report_id.as_bytes());
        output.extend_from_slice(&encrypted.integrity_tag);
        output.extend_from_slice(&(encrypted.encrypted_payload.len() as u64).to_le_bytes());
        output.extend_from_slice(&encrypted.encrypted_payload);
        std::fs::write(path, output).map_err(|e| format!("write failed: {e}"))?;
        Ok(())
    }
}

impl EncryptedReport {
    /// Decrypt and deserialize a report.
    pub fn decrypt(&self, key: &[u8]) -> Result<ScanReport, String> {
        if !verify_tag_custom(key, &self.encrypted_payload, &self.integrity_tag) {
            return Err("integrity verification failed: report may be tampered".to_string());
        }
        let plaintext = decrypt_payload(&self.encrypted_payload, key)
            .ok_or("decryption failed: wrong key or corrupted data")?;
        serde_json::from_slice(&plaintext).map_err(|e| format!("deserialize failed: {e}"))
    }

    /// Load an encrypted report from a file.
    pub fn load_from_file(path: &PathBuf) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read failed: {e}"))?;
        if !bytes.starts_with(REPORT_MAGIC) {
            return Err("invalid report file: wrong magic".to_string());
        }
        let mut offset = REPORT_MAGIC.len();
        if bytes.len() < offset + 8 {
            return Err("truncated report file".to_string());
        }
        let id_len = u64::from_le_bytes(
            bytes[offset..offset + 8].try_into().unwrap(),
        ) as usize;
        offset += 8;
        if bytes.len() < offset + id_len + 32 {
            return Err("truncated report file".to_string());
        }
        let report_id = String::from_utf8(bytes[offset..offset + id_len].to_vec())
            .map_err(|_| "invalid report id encoding")?;
        offset += id_len;
        let mut integrity_tag = [0u8; 32];
        integrity_tag.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        if bytes.len() < offset + 8 {
            return Err("truncated report file".to_string());
        }
        let payload_len = u64::from_le_bytes(
            bytes[offset..offset + 8].try_into().unwrap(),
        ) as usize;
        offset += 8;
        if bytes.len() < offset + payload_len {
            return Err("truncated report file".to_string());
        }
        let encrypted_payload = bytes[offset..offset + payload_len].to_vec();
        Ok(Self {
            report_id,
            encrypted_payload,
            integrity_tag,
        })
    }
}

impl ReportSummary {
    fn from_results(results: &[ScanReportEntry]) -> Self {
        let mut malicious = 0;
        let mut suspicious = 0;
        let mut clean = 0;
        let mut errors = 0;
        let mut total_time = 0u128;
        for entry in results {
            total_time += entry.scan_time_ms;
            match entry.verdict.as_str() {
                "malicious" => malicious += 1,
                "suspicious" => suspicious += 1,
                "clean" | "benign" => clean += 1,
                _ => errors += 1,
            }
        }
        Self {
            total_files: results.len(),
            malicious_count: malicious,
            suspicious_count: suspicious,
            clean_count: clean,
            error_count: errors,
            total_scan_time_ms: total_time,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(verdict: &str) -> ScanReportEntry {
        ScanReportEntry {
            file_path: "test.exe".to_string(),
            sha256: "abc123".to_string(),
            verdict: verdict.to_string(),
            confidence: Some(0.95),
            threat_name: None,
            threat_category: None,
            matched_rules: vec!["rule1".to_string()],
            scan_time_ms: 100,
        }
    }

    #[test]
    fn report_summary_counts_correctly() {
        let entries = vec![
            sample_entry("malicious"),
            sample_entry("malicious"),
            sample_entry("suspicious"),
            sample_entry("clean"),
            sample_entry("error"),
        ];
        let report = ScanReport::new("EverbloomSecurity", "1.0.0", entries);
        assert_eq!(report.summary.total_files, 5);
        assert_eq!(report.summary.malicious_count, 2);
        assert_eq!(report.summary.suspicious_count, 1);
        assert_eq!(report.summary.clean_count, 1);
        assert_eq!(report.summary.error_count, 1);
    }

    #[test]
    fn encrypted_report_roundtrip() {
        let key = b"test-report-key";
        let entries = vec![sample_entry("malicious")];
        let report = ScanReport::new("EverbloomSecurity", "1.0.0", entries);
        let encrypted = report.to_encrypted_report(key).unwrap();
        let decrypted = encrypted.decrypt(key).unwrap();
        assert_eq!(decrypted.report_id, report.report_id);
        assert_eq!(decrypted.summary.total_files, 1);
    }

    #[test]
    fn encrypted_report_wrong_key_fails() {
        let key = b"correct-key";
        let wrong_key = b"wrong-key";
        let entries = vec![sample_entry("clean")];
        let report = ScanReport::new("EverbloomSecurity", "1.0.0", entries);
        let encrypted = report.to_encrypted_report(key).unwrap();
        assert!(encrypted.decrypt(wrong_key).is_err());
    }

    #[test]
    fn encrypted_report_tampered_fails() {
        let key = b"test-key";
        let entries = vec![sample_entry("clean")];
        let report = ScanReport::new("EverbloomSecurity", "1.0.0", entries);
        let mut encrypted = report.to_encrypted_report(key).unwrap();
        if !encrypted.encrypted_payload.is_empty() {
            encrypted.encrypted_payload[0] ^= 0xFF;
        }
        assert!(encrypted.decrypt(key).is_err());
    }

    #[test]
    fn save_and_load_encrypted_report() {
        let key = b"file-test-key";
        let entries = vec![sample_entry("malicious"), sample_entry("clean")];
        let report = ScanReport::new("EverbloomSecurity", "1.0.0", entries);
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test_report.everbloom");
        report.save_encrypted(&path, key).unwrap();
        let loaded = EncryptedReport::load_from_file(&path).unwrap();
        let decrypted = loaded.decrypt(key).unwrap();
        assert_eq!(decrypted.report_id, report.report_id);
        assert_eq!(decrypted.summary.total_files, 2);
        let _ = std::fs::remove_file(&path);
    }
}
