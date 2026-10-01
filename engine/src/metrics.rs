//! Low-overhead process-local metrics for engine health and performance.
//!
//! The counters are intentionally independent of logging and tracing. They
//! can be exported through NDJSON now and mapped to Prometheus/OpenTelemetry
//! later without changing scanner behavior.

use crate::layers::memory_snapshot::SandboxUnpackingReport;
use crate::sandbox::SandboxReport;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

static SCAN_REQUESTS: AtomicU64 = AtomicU64::new(0);
static SCAN_FILES: AtomicU64 = AtomicU64::new(0);
static SCAN_BYTES: AtomicU64 = AtomicU64::new(0);
static SCAN_DURATION_MS: AtomicU64 = AtomicU64::new(0);
static SCAN_ERRORS: AtomicU64 = AtomicU64::new(0);
static SCAN_MALWARE: AtomicU64 = AtomicU64::new(0);
static SANDBOX_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static SANDBOX_CANDIDATE: AtomicU64 = AtomicU64::new(0);
static SANDBOX_RECOVERED_CANDIDATE: AtomicU64 = AtomicU64::new(0);
static SANDBOX_NOT_AVAILABLE: AtomicU64 = AtomicU64::new(0);
static KERNEL_EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct EngineMetricsSnapshot {
    pub scan_requests: u64,
    pub scan_files: u64,
    pub scan_bytes: u64,
    pub scan_duration_ms: u64,
    pub scan_errors: u64,
    pub scan_malware: u64,
    pub sandbox_fallbacks: u64,
    pub sandbox_candidate: u64,
    pub sandbox_recovered_candidate: u64,
    pub sandbox_not_available: u64,
    pub kernel_events_dropped: u64,
    pub ai_inference_errors: u64,
    pub ai_queue_wait_us: u64,
    pub ai_inference_time_us: u64,
    pub ai_inference_requests: u64,
    pub ai_queue_rejections: u64,
}

pub fn record_scan_request() {
    SCAN_REQUESTS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_scan_result(duration_ms: u128, bytes: u64, error: bool, malware: bool) {
    SCAN_FILES.fetch_add(1, Ordering::Relaxed);
    SCAN_BYTES.fetch_add(bytes, Ordering::Relaxed);
    SCAN_DURATION_MS.fetch_add(duration_ms.min(u64::MAX as u128) as u64, Ordering::Relaxed);
    if error {
        SCAN_ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    if malware {
        SCAN_MALWARE.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn record_sandbox(report: &SandboxReport) {
    if report
        .api_calls
        .iter()
        .any(|call| call.starts_with("fallback:local_backend_unavailable:"))
    {
        SANDBOX_FALLBACKS.fetch_add(1, Ordering::Relaxed);
    }
    record_unpacking(&report.unpacking);
}

fn record_unpacking(report: &SandboxUnpackingReport) {
    match report.status.as_str() {
        "candidate" => SANDBOX_CANDIDATE.fetch_add(1, Ordering::Relaxed),
        "recovered_candidate" => SANDBOX_RECOVERED_CANDIDATE.fetch_add(1, Ordering::Relaxed),
        "not_available" => SANDBOX_NOT_AVAILABLE.fetch_add(1, Ordering::Relaxed),
        _ => 0,
    };
}

pub fn record_kernel_events_dropped(count: u64) {
    KERNEL_EVENTS_DROPPED.fetch_add(count, Ordering::Relaxed);
}

pub fn snapshot() -> EngineMetricsSnapshot {
    let ai = crate::layers::ai::ai_runtime_metrics();
    EngineMetricsSnapshot {
        scan_requests: SCAN_REQUESTS.load(Ordering::Relaxed),
        scan_files: SCAN_FILES.load(Ordering::Relaxed),
        scan_bytes: SCAN_BYTES.load(Ordering::Relaxed),
        scan_duration_ms: SCAN_DURATION_MS.load(Ordering::Relaxed),
        scan_errors: SCAN_ERRORS.load(Ordering::Relaxed),
        scan_malware: SCAN_MALWARE.load(Ordering::Relaxed),
        sandbox_fallbacks: SANDBOX_FALLBACKS.load(Ordering::Relaxed),
        sandbox_candidate: SANDBOX_CANDIDATE.load(Ordering::Relaxed),
        sandbox_recovered_candidate: SANDBOX_RECOVERED_CANDIDATE.load(Ordering::Relaxed),
        sandbox_not_available: SANDBOX_NOT_AVAILABLE.load(Ordering::Relaxed),
        kernel_events_dropped: KERNEL_EVENTS_DROPPED.load(Ordering::Relaxed),
        ai_inference_errors: ai.inference_errors,
        ai_queue_wait_us: ai.queue_wait_us,
        ai_inference_time_us: ai.inference_time_us,
        ai_inference_requests: ai.inference_requests,
        ai_queue_rejections: ai.queue_rejections,
    }
}

#[cfg(test)]
mod tests {
    use super::{record_kernel_events_dropped, record_scan_request, snapshot};
    use serde_json::Value;

    #[test]
    fn snapshot_contains_stable_health_fields() {
        let before = snapshot();
        record_scan_request();
        record_kernel_events_dropped(2);
        let after = snapshot();

        assert!(after.scan_requests >= before.scan_requests + 1);
        assert!(after.kernel_events_dropped >= before.kernel_events_dropped + 2);

        let encoded = serde_json::to_value(after).expect("metrics serialize");
        for field in [
            "scan_requests",
            "scan_files",
            "scan_bytes",
            "scan_duration_ms",
            "sandbox_fallbacks",
            "sandbox_candidate",
            "sandbox_recovered_candidate",
            "sandbox_not_available",
            "kernel_events_dropped",
            "ai_queue_wait_us",
            "ai_inference_time_us",
            "ai_queue_rejections",
        ] {
            assert!(
                matches!(encoded.get(field), Some(Value::Number(_))),
                "missing {field}"
            );
        }
    }
}
