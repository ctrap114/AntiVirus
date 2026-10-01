use crate::driver_bridge::{DriverBridge, DriverEvent};
use crate::layers::behavior::{BehaviorEvent, BehaviorEventKind};
use crate::protection_state;
use lazy_static::lazy_static;
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

lazy_static! {
    static ref ETW_EVENT_QUEUE: Mutex<VecDeque<BehaviorEvent>> = Mutex::new(VecDeque::new());
    static ref CRITICAL_EVENT_QUEUE: Mutex<VecDeque<CriticalMonitorEvent>> =
        Mutex::new(VecDeque::new());
    static ref KERNEL_EVENT_QUEUE: Mutex<VecDeque<DriverEvent>> = Mutex::new(VecDeque::new());
    static ref GHOST_FILE_CACHE: Mutex<HashMap<String, GhostFileEvidenceRecord>> =
        Mutex::new(HashMap::new());
    static ref ETW_EVENT_DROPPED: Mutex<u64> = Mutex::new(0);
    static ref KERNEL_QUEUE_DROPPED: Mutex<u64> = Mutex::new(0);
}

const ETW_EVENT_QUEUE_LIMIT: usize = 4096;
const CRITICAL_EVENT_QUEUE_LIMIT: usize = 256;
const KERNEL_EVENT_QUEUE_LIMIT: usize = 512;
const GHOST_FILE_CACHE_LIMIT: usize = 512;
const GHOST_FILE_TTL: Duration = Duration::from_secs(10 * 60);
const KERNEL_STATUS_SUCCESS: u32 = 0;
const KERNEL_EVENT_KIND_PROCESS: u32 = 1;
const KERNEL_EVENT_KIND_FILE: u32 = 2;
const KERNEL_EVENT_KIND_REGISTRY: u32 = 3;
const KERNEL_EVENT_KIND_RAW_DISK: u32 = 4;
const KERNEL_EVENT_KIND_NETWORK: u32 = 5;
/// Advisory score from the driver's kernel inference core. For this kind only,
/// the event's `status` field carries the score rather than an NTSTATUS; see
/// `EVERBLOOM_EVENT_KIND_MODEL_SCORE` in `everbloom_driver_protocol.h`.
const KERNEL_EVENT_KIND_MODEL_SCORE: u32 = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostFileEvidence {
    pub target: String,
    pub reason: String,
    pub caller_pid: u32,
    pub sequence: u64,
}

/// A high-priority telemetry item that requests an immediate user-mode
/// inspection. It is deliberately a request for inspection, not a direct
/// suspend/terminate command: ETW records are asynchronous and their payload
/// may be incomplete, so the final action remains with HIPS/fusion/driver
/// policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalMonitorEvent {
    pub event_id: u16,
    pub process_id: u32,
    pub detail: String,
}

#[derive(Debug, Clone)]
struct GhostFileEvidenceRecord {
    evidence: GhostFileEvidence,
    observed_at: Instant,
}

/// Start a user-mode event collector as a best-effort ETW subscription.
///
/// On Windows this attaches to a live Sysmon ETW session if available and
/// converts incoming event records into behavior events for ProtectionFusion.
pub fn start_user_event_collector() {
    start_priority_event_worker();
    thread::spawn(|| {
        #[cfg(target_os = "windows")]
        {
            if let Err(err) = windows_etw::run_real_time_collector() {
                log::warn!("ETW user-mode collector could not start: {}", err);
                fallback_event_loop();
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            fallback_event_loop();
        }
    });
}

/// Start a bounded high-priority worker once. The worker performs a targeted
/// HIPS process scan instead of waiting for the normal three-second sweep.
pub fn start_priority_event_worker() {
    static START: Once = Once::new();
    START.call_once(|| {
        thread::spawn(|| {
            let mut last_scan: HashMap<u32, Instant> = HashMap::new();
            loop {
                let events = {
                    let mut queue = match CRITICAL_EVENT_QUEUE.lock() {
                        Ok(queue) => queue,
                        Err(_) => {
                            thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                    };
                    queue.drain(..).collect::<Vec<_>>()
                };

                let now = Instant::now();
                last_scan.retain(|_, observed| now.duration_since(*observed) < Duration::from_secs(5));
                for event in events {
                    if event.process_id == 0
                        || last_scan
                            .get(&event.process_id)
                            .is_some_and(|observed| now.duration_since(*observed) < Duration::from_secs(5))
                    {
                        continue;
                    }
                    last_scan.insert(event.process_id, now);
                    log::warn!(
                        "critical R3 telemetry event_id={} pid={} detail={}; starting targeted HIPS inspection",
                        event.event_id,
                        event.process_id,
                        event.detail
                    );
                    crate::hips::scan_process_on_demand(event.process_id);
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
    });
}

/// Poll the kernel audit ring and persist every enforcement decision in the
/// same user-mode log stream as the Rust engines. The ring is bounded and the
/// poll is intentionally low frequency so it cannot compete with scans.
pub fn start_driver_event_collector() {
    thread::spawn(|| {
        let bridge = DriverBridge::new();
        loop {
            if protection_state::driver_enabled() {
                match bridge.read_events() {
                    Ok(batch) => {
                        if batch.dropped > 0 {
                            record_kernel_event_overflow(batch.dropped);
                        }
                        for event in batch.events {
                            if event.kind == KERNEL_EVENT_KIND_MODEL_SCORE {
                                // The kernel model never vetoes; it only reports
                                // a launch whose score crossed the model's own
                                // advisory threshold. Logging it at info rather
                                // than warn keeps "warn" meaning "the kernel
                                // enforced something", which is what every other
                                // kind in this loop represents.
                                log::info!(
                                    "kernel model score={} pid={} sequence={} target={} reason={}",
                                    event.status,
                                    event.caller_pid,
                                    event.sequence,
                                    event.target,
                                    event.reason
                                );
                            } else {
                                log::warn!(
                                "kernel enforcement event sequence={} kind={} pid={} status=0x{:08x} target={} reason={}",
                                event.sequence,
                                event.kind,
                                event.caller_pid,
                                event.status,
                                event.target,
                                event.reason
                                );
                            }
                            record_ghost_file_evidence(&event);
                            record_kernel_behavior_event(&event);
                            if let Ok(mut queue) = KERNEL_EVENT_QUEUE.lock() {
                                if queue.len() >= KERNEL_EVENT_QUEUE_LIMIT {
                                    queue.pop_front();
                                    if let Ok(mut dropped) = KERNEL_QUEUE_DROPPED.lock() {
                                        *dropped = dropped.saturating_add(1);
                                    }
                                }
                                queue.push_back(event);
                            }
                        }
                    }
                    Err(error) if error.is_unavailable() => {
                        protection_state::set_driver_enabled(false);
                        log::debug!("kernel event collection disabled because the driver is unavailable: {}", error.unavailable_message());
                    }
                    Err(error) => log::debug!("kernel event poll unavailable: {}", error),
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
    });
}

/// Drain kernel enforcement events for the active platform channel. Events are
/// persisted by the collector first, then forwarded to GUI clients as
/// asynchronous `engine_event` NDJSON frames so a driver decision is not lost
/// when the engine returns `STATUS_ACCESS_DENIED` directly.
pub fn drain_kernel_events() -> Vec<DriverEvent> {
    let mut queue = KERNEL_EVENT_QUEUE.lock().unwrap();
    queue.drain(..).collect()
}

lazy_static! {
    static ref KERNEL_EVENT_DROPPED: Mutex<u64> = Mutex::new(0);
}

fn record_kernel_event_overflow(dropped: u64) {
    crate::metrics::record_kernel_events_dropped(dropped);
    if let Ok(mut total) = KERNEL_EVENT_DROPPED.lock() {
        *total = total.saturating_add(dropped);
    }
    log::error!("kernel event ring overflow: {} event(s) dropped", dropped);
}

/// Drain the accumulated kernel ring loss counter. It is emitted as a
/// separate engine event so consumers never mistake a partial event stream for
/// a complete one.
pub fn drain_kernel_event_dropped() -> u64 {
    let mut total = KERNEL_EVENT_DROPPED.lock().unwrap();
    let dropped = *total;
    *total = 0;
    dropped
}

/// Drain collected behavior events from the ETW queue.
pub fn drain_behavior_events() -> Vec<BehaviorEvent> {
    let mut queue = ETW_EVENT_QUEUE.lock().unwrap();
    queue.drain(..).collect()
}

pub fn drain_queue_dropped() -> (u64, u64) {
    let etw = ETW_EVENT_DROPPED
        .lock()
        .map(|mut value| std::mem::take(&mut *value))
        .unwrap_or(0);
    let kernel = KERNEL_QUEUE_DROPPED
        .lock()
        .map(|mut value| std::mem::take(&mut *value))
        .unwrap_or(0);
    (etw, kernel)
}

fn enqueue_critical_event(event: CriticalMonitorEvent) {
    if let Ok(mut queue) = CRITICAL_EVENT_QUEUE.lock() {
        if queue.len() >= CRITICAL_EVENT_QUEUE_LIMIT {
            queue.pop_front();
            log::warn!("critical R3 telemetry queue is full; oldest event was dropped");
        }
        queue.push_back(event);
    }
}

/// Look up short-lived kernel evidence for a high-risk file that may have
/// been deleted before a user-mode static scan could open it.
pub fn lookup_ghost_file_evidence(path: &std::path::Path) -> Option<GhostFileEvidence> {
    let key = ghost_driver_file_key(&path.to_string_lossy())?;
    let mut cache = GHOST_FILE_CACHE.lock().ok()?;
    let now = Instant::now();
    cache.retain(|_, record| now.duration_since(record.observed_at) <= GHOST_FILE_TTL);
    cache.get(&key).map(|record| record.evidence.clone())
}

fn record_ghost_file_evidence(event: &DriverEvent) {
    if event.kind != KERNEL_EVENT_KIND_FILE || event.status != KERNEL_STATUS_SUCCESS {
        return;
    }
    let reason = event.reason.to_ascii_lowercase();
    if !reason.contains("drivers directory module")
        || !(reason.contains("write")
            || reason.contains("self-delete")
            || reason.contains("rename"))
    {
        return;
    }
    let Some(key) = ghost_driver_file_key(&event.target) else {
        return;
    };
    let mut cache = match GHOST_FILE_CACHE.lock() {
        Ok(cache) => cache,
        Err(_) => return,
    };
    let now = Instant::now();
    cache.retain(|_, record| now.duration_since(record.observed_at) <= GHOST_FILE_TTL);
    if cache.len() >= GHOST_FILE_CACHE_LIMIT {
        if let Some(oldest_key) = cache
            .iter()
            .min_by_key(|(_, record)| record.observed_at)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest_key);
        }
    }
    cache.insert(
        key,
        GhostFileEvidenceRecord {
            evidence: GhostFileEvidence {
                target: event.target.clone(),
                reason: event.reason.clone(),
                caller_pid: event.caller_pid,
                sequence: event.sequence,
            },
            observed_at: now,
        },
    );
}

fn record_kernel_behavior_event(event: &DriverEvent) {
    if !protection_state::r3_enabled() {
        return;
    }
    // Advisory scores are not observed behaviours, so they are not mapped here.
    // The model reads only the image path and the command line, which the
    // user-mode correlation already has; feeding a score back in as a
    // ProcessCreate behaviour event would present this pipeline's own input as
    // if it were independent evidence. Returning before the lowercase
    // allocation below also keeps the score path allocation-free.
    if event.kind == KERNEL_EVENT_KIND_MODEL_SCORE {
        return;
    }
    let reason = event.reason.to_ascii_lowercase();
    let kind = match event.kind {
        KERNEL_EVENT_KIND_PROCESS if reason.contains("apc") || reason.contains("thread-pool") => {
            BehaviorEventKind::ProcessInject
        }
        KERNEL_EVENT_KIND_PROCESS => BehaviorEventKind::ProcessCreate,
        KERNEL_EVENT_KIND_FILE => BehaviorEventKind::FileWrite,
        KERNEL_EVENT_KIND_REGISTRY => BehaviorEventKind::RegistryWrite,
        KERNEL_EVENT_KIND_NETWORK => BehaviorEventKind::NetworkConnect,
        KERNEL_EVENT_KIND_RAW_DISK => BehaviorEventKind::RansomwareEncryption,
        _ => return,
    };
    let detail = format!(
        "kernel:{}:status=0x{:08x}:target={}:reason={}",
        event.sequence, event.status, event.target, event.reason
    );
    if let Ok(mut queue) = ETW_EVENT_QUEUE.lock() {
        if queue.len() >= ETW_EVENT_QUEUE_LIMIT {
            queue.pop_front();
            if let Ok(mut dropped) = ETW_EVENT_DROPPED.lock() {
                *dropped = dropped.saturating_add(1);
            }
            log::warn!("behavior event queue is full; oldest event was dropped");
        }
        let behavior_event = BehaviorEvent {
            kind,
            detail,
            process_id: Some(event.caller_pid),
        };
        crate::stealer_guard::observe_behavior_event(&behavior_event);
        queue.push_back(behavior_event);
    }
}

fn ghost_driver_file_key(path: &str) -> Option<String> {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    if !(normalized.ends_with(".dll") || normalized.ends_with(".sys")) {
        return None;
    }
    for marker in ["\\system32\\drivers\\", "\\syswow64\\drivers\\"] {
        if let Some(index) = normalized.rfind(marker) {
            return Some(normalized[index + 1..].to_string());
        }
    }
    None
}

fn fallback_event_loop() {
    loop {
        thread::sleep(Duration::from_secs(10));
    }
}

#[cfg(target_os = "windows")]
mod windows_etw {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Diagnostics::Etw::PROCESSTRACE_HANDLE;
    use windows_sys::Win32::System::Diagnostics::Etw::{
        CloseTrace, OpenTraceW, ProcessTrace, EVENT_RECORD, EVENT_TRACE_LOGFILEW,
        PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    };

    const SYSMON_SESSION_NAMES: [&str; 2] = ["Microsoft-Windows-Sysmon", "Sysmon"];
    const INVALID_TRACE_HANDLE: u64 = u64::MAX;

    fn to_wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    unsafe extern "system" fn etw_event_callback(record: *mut EVENT_RECORD) {
        if record.is_null() {
            return;
        }
        if !protection_state::r3_enabled() {
            return;
        }

        let header = &(*record).EventHeader;
        let event_id = header.EventDescriptor.Id;
        let process_id = if header.ProcessId == 0 {
            None
        } else {
            Some(header.ProcessId)
        };

        let Some(kind) = map_sysmon_event_kind(event_id) else {
            // Do not turn every provider-specific or future event into a
            // suspicious API call. Unknown events are deliberately ignored
            // until their payload schema has been decoded and classified.
            return;
        };

        if is_high_priority_sysmon_event(event_id) {
            enqueue_critical_event(CriticalMonitorEvent {
                event_id,
                process_id: process_id.unwrap_or(0),
                detail: format!("Sysmon injection/tampering event {event_id}"),
            });
        }

        let detail = format!(
            "sysmon:event_id:{}:pid:{}",
            event_id,
            process_id.unwrap_or(0)
        );
        if let Ok(mut queue) = ETW_EVENT_QUEUE.lock() {
            if queue.len() >= ETW_EVENT_QUEUE_LIMIT {
                queue.pop_front();
                log::warn!("ETW behavior queue is full; oldest event was dropped");
            }
            let behavior_event = BehaviorEvent {
                kind,
                detail,
                process_id,
            };
            crate::stealer_guard::observe_behavior_event(&behavior_event);
            queue.push_back(behavior_event);
        }
    }

    fn map_sysmon_event_kind(event_id: u16) -> Option<BehaviorEventKind> {
        // Sysmon event ids are provider-specific. Keep this mapping explicit:
        // registry events (12-14) must not be reported as file writes, and
        // unknown ids must not manufacture a suspicious verdict.
        match event_id {
            1 => Some(BehaviorEventKind::ProcessCreate),
            3 => Some(BehaviorEventKind::NetworkConnect),
            6 | 16 => Some(BehaviorEventKind::ServiceTampering),
            8 | 10 => Some(BehaviorEventKind::ProcessInject),
            9 | 25 => Some(BehaviorEventKind::SuspiciousApiCall),
            11 | 15 | 23 | 26 => Some(BehaviorEventKind::FileWrite),
            12..=14 => Some(BehaviorEventKind::RegistryWrite),
            22 => Some(BehaviorEventKind::DnsQuery),
            _ => None,
        }
    }

    fn is_high_priority_sysmon_event(event_id: u16) -> bool {
        // 8 = CreateRemoteThread, 10 = ProcessAccess, 25 = ProcessTampering.
        // Sysmon does not expose a stable QueueUserAPC event contract here;
        // these are the supported precursor events that justify an immediate
        // targeted memory inspection.
        matches!(event_id, 8 | 10 | 25)
    }

    fn open_sysmon_session() -> Option<PROCESSTRACE_HANDLE> {
        for session in SYSMON_SESSION_NAMES.iter() {
            let mut logger_name = to_wide(session);
            let mut logfile = EVENT_TRACE_LOGFILEW {
                LoggerName: logger_name.as_mut_ptr(),
                ..Default::default()
            };
            logfile.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
            logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);

            let handle = unsafe { OpenTraceW(&mut logfile) };
            if handle.Value != INVALID_TRACE_HANDLE {
                return Some(handle);
            }
        }

        None
    }

    pub fn run_real_time_collector() -> Result<(), String> {
        let trace_handle = open_sysmon_session()
            .ok_or_else(|| "no active Sysmon ETW session was found".to_string())?;

        let handles = [trace_handle];
        let status =
            unsafe { ProcessTrace(handles.as_ptr(), handles.len() as u32, null(), null()) };
        let _ = unsafe { CloseTrace(trace_handle) };

        if status != ERROR_SUCCESS {
            return Err(format!("ProcessTrace failed: {status}"));
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::map_sysmon_event_kind;
        use crate::layers::behavior::BehaviorEventKind;

        #[test]
        fn maps_sysmon_event_families_without_cross_classification() {
            assert_eq!(
                map_sysmon_event_kind(1),
                Some(BehaviorEventKind::ProcessCreate)
            );
            assert_eq!(
                map_sysmon_event_kind(12),
                Some(BehaviorEventKind::RegistryWrite)
            );
            assert_eq!(
                map_sysmon_event_kind(15),
                Some(BehaviorEventKind::FileWrite)
            );
            assert_eq!(map_sysmon_event_kind(999), None);
            assert!(super::is_high_priority_sysmon_event(8));
            assert!(super::is_high_priority_sysmon_event(10));
            assert!(!super::is_high_priority_sysmon_event(11));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drain_behavior_events_empty() {
        let drained = drain_behavior_events();
        assert!(drained.is_empty());
    }

    #[test]
    fn test_drain_behavior_events_receives_new_events() {
        let event = BehaviorEvent {
            kind: BehaviorEventKind::ProcessCreate,
            detail: "test-process".to_string(),
            process_id: Some(1234),
        };

        {
            let mut queue = ETW_EVENT_QUEUE.lock().unwrap();
            queue.push_back(event);
        }

        let drained = drain_behavior_events();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].process_id, Some(1234));
    }

    #[test]
    fn test_drain_kernel_events_receives_new_events() {
        let event = DriverEvent {
            kind: 1,
            status: 5,
            caller_pid: 1234,
            sequence: 1,
            timestamp: 0,
            target: "C:/blocked.exe".to_string(),
            reason: "test".to_string(),
        };
        {
            let mut queue = KERNEL_EVENT_QUEUE.lock().unwrap();
            queue.push_back(event);
        }
        let drained = drain_kernel_events();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].caller_pid, 1234);
    }

    #[test]
    fn ghost_file_cache_matches_device_and_dos_driver_paths() {
        let event = DriverEvent {
            kind: KERNEL_EVENT_KIND_FILE,
            status: KERNEL_STATUS_SUCCESS,
            caller_pid: 4321,
            sequence: 7,
            timestamp: 0,
            target: r"\Device\HarddiskVolume3\Windows\System32\drivers\winmm.dll".to_string(),
            reason: "suspicious drivers directory module self-delete or rename observed"
                .to_string(),
        };
        record_ghost_file_evidence(&event);

        let evidence = lookup_ghost_file_evidence(std::path::Path::new(
            r"C:\Windows\System32\drivers\winmm.dll",
        ))
        .expect("ghost evidence");
        assert_eq!(evidence.caller_pid, 4321);
        assert_eq!(evidence.sequence, 7);
    }
}
