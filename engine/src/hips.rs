// Host Intrusion Prevention System (HIPS) - user-mode skeletal implementation
// Provides lightweight monitoring for process creation chains, simple injection
// heuristics (RWX memory), and DLL load origin checks. Intended as a safe,
// user-mode guardian that feeds events into ProtectionFusion and alerts the GUI.

use crate::driver_bridge::DriverBridge;
use crate::layers::behavior::{BehaviorEvent, BehaviorEventKind};
use crate::layers::cookie_guard::{
    analyze_process_image as analyze_cookie_process_image, is_browser_process_name,
    is_known_cookie_tool_name,
};
use crate::protection_state;
use goblin::pe::PE;
use lazy_static::lazy_static;
use log::{info, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::os::windows::prelude::OsStringExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

lazy_static! {
    static ref HIPS_RUNNING: Mutex<bool> = Mutex::new(false);
    static ref HIPS_EVENT_QUEUE: Mutex<VecDeque<HipsEvent>> = Mutex::new(VecDeque::new());
    static ref DRIVER_REVIEW_TX: Mutex<Option<SyncSender<DriverReviewEvent>>> = Mutex::new(None);
    static ref HIPS_EVENT_LAST_SEEN: Mutex<HashMap<String, Instant>> = Mutex::new(HashMap::new());
    static ref HIPS_EVENT_DROPPED: AtomicU64 = AtomicU64::new(0);
    static ref DRIVER_REVIEW_DROPPED: AtomicU64 = AtomicU64::new(0);
}

const HIPS_EVENT_QUEUE_LIMIT: usize = 2048;
const DRIVER_REVIEW_QUEUE_LIMIT: usize = 512;
const DRIVER_REVIEW_WINDOW: Duration = Duration::from_millis(100);
const DRIVER_RETRY_COOLDOWN: Duration = Duration::from_secs(5);
const HIPS_EVENT_DEDUP_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct DriverReviewEvent {
    pid: u32,
    description: String,
    urgent: bool,
}

#[derive(Debug, Clone)]
pub enum HipsEvent {
    SuspiciousProcessChain {
        parent: String,
        child: String,
        pid: u32,
    },
    SuspiciousRwxRegion {
        pid: u32,
        addr: usize,
        size: usize,
    },
    SuspiciousMemoryLoad {
        pid: u32,
        addr: usize,
        size: usize,
        entropy: f32,
    },
    /// A private executable region contains an APC-queueing indicator. This
    /// is a correlation signal, not a claim that every occurrence of
    /// QueueUserAPC is malicious.
    SuspiciousApcInjection {
        pid: u32,
        tid: u32,
        indicator: String,
    },
    /// Thread-pool work/timer APIs observed alongside private executable
    /// memory, which is the useful user-mode approximation of PoolParty.
    SuspiciousThreadPoolInjection {
        pid: u32,
        addr: usize,
        size: usize,
        indicator: String,
    },
    /// A private executable region starts with an in-memory PE header. This
    /// is a high-value sRDI/reflective-loader signal when combined with RWX.
    SuspiciousReflectivePe {
        pid: u32,
        addr: usize,
        size: usize,
        mz_offset: usize,
    },
    /// A protected system process loaded a module outside the Windows system
    /// module roots. This is a baseline signal; it is not by itself proof of
    /// malware and is correlated with signer/path/injection evidence.
    SuspiciousModuleBaseline {
        pid: u32,
        process_path: String,
        dll_path: String,
        reason: String,
    },
    SuspiciousDllLoad {
        pid: u32,
        dll_path: String,
    },
    CtfHijackDllLoad {
        pid: u32,
        process_path: String,
        dll_path: String,
        reason: String,
    },
    /// A DLL was found beside a process image in a user-writable directory.
    /// Fusion treats this as a distinct side-loading family and requires
    /// independent injection evidence before intervention.
    WhiteBlackSideLoad {
        pid: u32,
        process_path: String,
        dll_path: String,
        reason: String,
    },
    SuspiciousApiPatch {
        pid: u32,
        module: String,
        function: String,
        addr: usize,
    },
    SuspiciousThreadStack {
        pid: u32,
        tid: u32,
        ip: usize,
        stack: Vec<usize>,
    },
    /// High-confidence browser-data extraction indicators in a process image
    /// or an explicit browser-data utility name. The event contains labels,
    /// never cookie values or database contents.
    CookieTheftSuspected {
        pid: u32,
        process_path: String,
        indicators: Vec<String>,
    },
    SuspiciousPplProcess {
        pid: u32,
        process_path: String,
        protection_level: u8,
    },
    DriverBlocked {
        pid: u32,
        request_id: u64,
        action: u32,
    },
}

impl HipsEvent {
    /// Return the process associated with this alert so callers can correlate
    /// events without parsing the human-readable description.
    pub fn process_id(&self) -> u32 {
        match self {
            HipsEvent::SuspiciousProcessChain { pid, .. }
            | HipsEvent::SuspiciousRwxRegion { pid, .. }
            | HipsEvent::SuspiciousMemoryLoad { pid, .. }
            | HipsEvent::SuspiciousApcInjection { pid, .. }
            | HipsEvent::SuspiciousThreadPoolInjection { pid, .. }
            | HipsEvent::SuspiciousReflectivePe { pid, .. }
            | HipsEvent::SuspiciousModuleBaseline { pid, .. }
            | HipsEvent::SuspiciousDllLoad { pid, .. }
            | HipsEvent::CtfHijackDllLoad { pid, .. }
            | HipsEvent::WhiteBlackSideLoad { pid, .. }
            | HipsEvent::SuspiciousApiPatch { pid, .. }
            | HipsEvent::SuspiciousThreadStack { pid, .. }
            | HipsEvent::CookieTheftSuspected { pid, .. }
            | HipsEvent::SuspiciousPplProcess { pid, .. }
            | HipsEvent::DriverBlocked { pid, .. } => *pid,
        }
    }

    pub fn description(&self) -> String {
        match self {
            HipsEvent::SuspiciousProcessChain { parent, child, pid } => {
                format!("Suspicious chain: {} -> {} (pid={})", parent, child, pid)
            }
            HipsEvent::SuspiciousRwxRegion { pid, addr, size } => {
                format!("RWX region in pid {} at {:#x} size {}", pid, addr, size)
            }
            HipsEvent::SuspiciousMemoryLoad {
                pid,
                addr,
                size,
                entropy,
            } => format!(
                "Suspicious high-entropy private executable memory in pid {} at {:#x} size {} entropy={:.2}",
                pid, addr, size, entropy
            ),
            HipsEvent::SuspiciousApcInjection {
                pid,
                tid,
                indicator,
            } => format!(
                "APC injection indicator in pid {} tid {}: {}",
                pid, tid, indicator
            ),
            HipsEvent::SuspiciousThreadPoolInjection {
                pid,
                addr,
                size,
                indicator,
            } => format!(
                "PoolParty thread-pool injection indicator in pid {} at {:#x} size {}: {}",
                pid, addr, size, indicator
            ),
            HipsEvent::SuspiciousReflectivePe {
                pid,
                addr,
                size,
                mz_offset,
            } => format!(
                "Reflective PE image in private executable memory in pid {} at {:#x} size {} mz_offset={:#x}",
                pid, addr, size, mz_offset
            ),
            HipsEvent::SuspiciousModuleBaseline {
                pid,
                process_path,
                dll_path,
                reason,
            } => format!(
                "Protected process module baseline violation in pid {}: process={} dll={} reason={}",
                pid, process_path, dll_path, reason
            ),
            HipsEvent::SuspiciousDllLoad { pid, dll_path } => {
                format!("Suspicious DLL load in pid {}: {}", pid, dll_path)
            }
            HipsEvent::CtfHijackDllLoad {
                pid,
                process_path,
                dll_path,
                reason,
            } => format!(
                "Possible SilverFox CTF hijack in pid {}: process={} dll={} reason={}",
                pid, process_path, dll_path, reason
            ),
            HipsEvent::WhiteBlackSideLoad {
                pid,
                process_path,
                dll_path,
                reason,
            } => format!(
                "White+black DLL side-load in pid {}: process={} dll={} reason={}",
                pid, process_path, dll_path, reason
            ),
            HipsEvent::SuspiciousApiPatch {
                pid,
                module,
                function,
                addr,
            } => format!(
                "API patch detected in pid {}: {}!{} at {:#x}",
                pid, module, function, addr
            ),
            HipsEvent::SuspiciousThreadStack {
                pid,
                tid,
                ip,
                stack,
            } => format!(
                "Suspicious thread stack in pid {} tid {} ip {:#x} stack {:?}",
                pid, tid, ip, stack
            ),
            HipsEvent::CookieTheftSuspected {
                pid,
                process_path,
                indicators,
            } => format!(
                "Browser cookie theft suspected in pid {} process={} indicators={}",
                pid,
                process_path,
                indicators.join(",")
            ),
            HipsEvent::SuspiciousPplProcess {
                pid,
                process_path,
                protection_level,
            } => format!(
                "Suspicious PPL process in pid {} level={} path={}",
                pid, protection_level, process_path
            ),
            HipsEvent::DriverBlocked {
                pid,
                request_id,
                action,
            } => format!(
                "Driver blocked HIPS event in pid {} request={} action={}",
                pid, request_id, action
            ),
        }
    }

/// Translate a HIPS alert into a behavioral event so the sequence
    /// matcher and ATC-style scorer can correlate it with sandbox telemetry.
    /// Driver enforcement is deliberately excluded: it is already an
    /// authoritative fusion input and would otherwise double-count.
    pub fn behavior_event(&self) -> Option<BehaviorEvent> {
        let kind = match self {
            HipsEvent::SuspiciousProcessChain { .. } => BehaviorEventKind::ProcessCreate,
            HipsEvent::SuspiciousRwxRegion { .. }
            | HipsEvent::SuspiciousMemoryLoad { .. }
            | HipsEvent::SuspiciousApcInjection { .. }
            | HipsEvent::SuspiciousThreadPoolInjection { .. }
            | HipsEvent::SuspiciousReflectivePe { .. }
            | HipsEvent::SuspiciousThreadStack { .. } => BehaviorEventKind::ProcessInject,
            HipsEvent::SuspiciousApiPatch { .. } | HipsEvent::SuspiciousPplProcess { .. } => {
                BehaviorEventKind::SuspiciousApiCall
            }
            HipsEvent::SuspiciousModuleBaseline { .. }
            | HipsEvent::SuspiciousDllLoad { .. }
            | HipsEvent::CtfHijackDllLoad { .. }
            | HipsEvent::WhiteBlackSideLoad { .. } => BehaviorEventKind::SuspiciousModuleLoad,
            HipsEvent::CookieTheftSuspected { .. } => BehaviorEventKind::CredentialAccess,
            HipsEvent::DriverBlocked { .. } => return None,
        };
        Some(BehaviorEvent {
            kind,
            detail: self.description(),
            process_id: Some(self.process_id()),
        })
    }

    fn requires_immediate_driver_review(&self) -> bool {
        matches!(
            self,
            HipsEvent::SuspiciousRwxRegion { .. }
                | HipsEvent::SuspiciousMemoryLoad { .. }
                | HipsEvent::SuspiciousApcInjection { .. }
                | HipsEvent::SuspiciousThreadPoolInjection { .. }
                | HipsEvent::SuspiciousReflectivePe { .. }
                | HipsEvent::SuspiciousModuleBaseline { .. }
                | HipsEvent::SuspiciousApiPatch { .. }
                | HipsEvent::SuspiciousThreadStack { .. }
                | HipsEvent::CookieTheftSuspected { .. }
                | HipsEvent::CtfHijackDllLoad { .. }
                | HipsEvent::SuspiciousPplProcess { .. }
        )
    }
}

fn record_event(ev: HipsEvent) {
    let description = ev.description();
    info!("HIPS event: {}", description);
    let mut queue = HIPS_EVENT_QUEUE.lock().unwrap();
    if queue.len() >= HIPS_EVENT_QUEUE_LIMIT {
        queue.pop_front();
        HIPS_EVENT_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    queue.push_back(ev);
}

fn start_driver_review_worker() {
    let mut sender = DRIVER_REVIEW_TX.lock().unwrap();
    if sender.is_some() {
        return;
    }
    let (tx, rx) = mpsc::sync_channel(DRIVER_REVIEW_QUEUE_LIMIT);
    *sender = Some(tx);
    thread::spawn(move || driver_review_loop(rx));
}

fn emit_event(ev: HipsEvent) {
    if !protection_state::r3_enabled() {
        return;
    }
    let pid = ev.process_id();
    let description = ev.description();
    {
        let now = Instant::now();
        let mut seen = HIPS_EVENT_LAST_SEEN.lock().unwrap();
        seen.retain(|_, last| now.duration_since(*last) < HIPS_EVENT_DEDUP_COOLDOWN);
        if seen
            .get(&description)
            .is_some_and(|last| now.duration_since(*last) < HIPS_EVENT_DEDUP_COOLDOWN)
        {
            return;
        }
        seen.insert(description.clone(), now);
    }
    let urgent = ev.requires_immediate_driver_review();
    crate::stealer_guard::observe_hips_event(&ev);
    record_event(ev);
    start_driver_review_worker();

    let sender = DRIVER_REVIEW_TX.lock().unwrap().clone();
    let Some(sender) = sender else {
        return;
    };
    match sender.try_send(DriverReviewEvent {
        pid,
        description,
        urgent,
    }) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            DRIVER_REVIEW_DROPPED.fetch_add(1, Ordering::Relaxed);
            warn!(
                "driver behavior review queue is full; low-level HIPS event was retained in telemetry"
            );
        }
        Err(TrySendError::Disconnected(_)) => {
            warn!("driver behavior review worker is unavailable");
        }
    }
}

fn driver_review_loop(rx: Receiver<DriverReviewEvent>) {
    let bridge = DriverBridge::new();
    let mut retry_after = Instant::now();
    while let Ok(first) = rx.recv() {
        let mut batch = vec![first];
        if !batch[0].urgent {
            let deadline = Instant::now() + DRIVER_REVIEW_WINDOW;
            while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                match rx.recv_timeout(remaining) {
                    Ok(event) => batch.push(event),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
        }

        if !protection_state::driver_enabled() || Instant::now() < retry_after {
            continue;
        }

        let mut grouped: HashMap<u32, Vec<String>> = HashMap::new();
        for event in batch {
            let descriptions = grouped.entry(event.pid).or_default();
            if !descriptions.contains(&event.description) {
                descriptions.push(event.description);
            }
        }

        for (pid, descriptions) in grouped {
            let mut payload = descriptions.join("\n");
            if payload.len() > 3500 {
                payload.truncate(3500);
                payload.push_str("\n[truncated]");
            }
            match bridge.submit_behavior(&format!("pid:{pid}"), payload.as_bytes()) {
                Ok(verdict) if verdict.blocked => {
                    warn!(
                        "driver blocked aggregated HIPS event pid={} request={} action={}",
                        pid, verdict.request_id, verdict.action
                    );
                    record_event(HipsEvent::DriverBlocked {
                        pid,
                        request_id: verdict.request_id,
                        action: verdict.action,
                    });
                }
                Ok(verdict) => {
                    info!(
                        "driver reviewed aggregated HIPS event pid={} request={} threat={} action={}",
                        pid, verdict.request_id, verdict.threat, verdict.action
                    );
                }
                Err(error) if error.is_unavailable() => {
                    retry_after = Instant::now() + DRIVER_RETRY_COOLDOWN;
                    protection_state::set_driver_enabled(false);
                    log::debug!(
                        "driver review disabled because the device is unavailable: {}",
                        error.unavailable_message()
                    );
                }
                Err(error) => warn!("driver review unavailable for pid={pid}: {error}"),
            }
        }
    }
}

pub fn drain_hips_events() -> Vec<HipsEvent> {
    let mut queue = HIPS_EVENT_QUEUE.lock().unwrap();
    queue.drain(..).collect()
}

pub fn drain_event_dropped() -> (u64, u64) {
    (
        HIPS_EVENT_DROPPED.swap(0, Ordering::AcqRel),
        DRIVER_REVIEW_DROPPED.swap(0, Ordering::AcqRel),
    )
}

#[cfg(target_os = "windows")]
fn enumerate_processes() -> std::io::Result<Vec<(u32, String, u32)>> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut results = Vec::new();
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let exe = {
                    let slice = &entry.szExeFile;
                    let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                    OsString::from_wide(&slice[..len])
                        .to_string_lossy()
                        .into_owned()
                };
                results.push((entry.th32ProcessID, exe, entry.th32ParentProcessID));
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        Ok(results)
    }
}

#[cfg(target_os = "windows")]
fn scan_process(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if process.is_null() {
            return;
        }

        // module path checks
        let mut process_image_path: Option<String> = None;
        let module_snapshot =
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if !module_snapshot.is_null() {
            let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
            module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
            if Module32FirstW(module_snapshot, &mut module_entry) != 0 {
                loop {
                    let path = {
                        let slice = &module_entry.szExePath;
                        let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                        OsString::from_wide(&slice[..len])
                            .to_string_lossy()
                            .into_owned()
                    };
                    let lower = path.to_lowercase();
                    let base_addr = module_entry.modBaseAddr as usize;
                    if process_image_path.is_none() && is_executable_path(&path) {
                        process_image_path = Some(path.clone());
                    }
                    if lower.contains("\\temp\\")
                        || lower.contains("appdata")
                        || lower.contains("local\\temp")
                    {
                        emit_event(HipsEvent::SuspiciousDllLoad {
                            pid,
                            dll_path: path.clone(),
                        });
                    }
                    if let Some(process_path) = process_image_path.as_deref() {
                        if let Some(reason) = module_baseline_violation_reason(process_path, &path)
                        {
                            emit_event(HipsEvent::SuspiciousModuleBaseline {
                                pid,
                                process_path: process_path.to_string(),
                                dll_path: path.clone(),
                                reason: reason.to_string(),
                            });
                        }
                        if let Some(reason) = ctf_hijack_dll_reason(process_path, &path) {
                            emit_event(HipsEvent::CtfHijackDllLoad {
                                pid,
                                process_path: process_path.to_string(),
                                dll_path: path.clone(),
                                reason: reason.to_string(),
                            });
                            emit_event(HipsEvent::WhiteBlackSideLoad {
                                pid,
                                process_path: process_path.to_string(),
                                dll_path: path.clone(),
                                reason: "ctfmon-ctf-hijack-module-origin".to_string(),
                            });
                        }
                        if looks_like_white_black_side_load(process_path, &path) {
                            emit_event(HipsEvent::WhiteBlackSideLoad {
                                pid,
                                process_path: process_path.to_string(),
                                dll_path: path.clone(),
                                reason: "same-directory-user-writable-module".to_string(),
                            });
                        }
                    }
                    if lower.contains("\\windows\\system32\\")
                        || lower.contains("\\windows\\syswow64\\")
                    {
                        scan_module_api_patches(pid, process, base_addr, &path);
                    }
                    if Module32NextW(module_snapshot, &mut module_entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(module_snapshot);
        }

        if let Some(process_path) = process_image_path.as_deref() {
            if let Some(protection_level) = query_ppl_protection(pid) {
                if !looks_like_system_ppl_path(process_path) {
                    emit_event(HipsEvent::SuspiciousPplProcess {
                        pid,
                        process_path: process_path.to_string(),
                        protection_level,
                    });
                }
            }
            let process_name = process_path
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(process_path);
            if !is_browser_process_name(process_name) {
                let cookie_score = analyze_cookie_process_image(std::path::Path::new(process_path));
                if cookie_score.high_confidence() || is_known_cookie_tool_name(process_name) {
                    let mut indicators = cookie_score.indicators;
                    if indicators.is_empty() {
                        indicators.push("known_browser_data_tool_name".to_string());
                    }
                    emit_event(HipsEvent::CookieTheftSuspected {
                        pid,
                        process_path: process_path.to_string(),
                        indicators,
                    });
                }
            }
        }

        // memory RWX scanning
        let mut address: usize = 0;
        let mut entropy_checks = 0usize;
        while address < 0x7FFF_FFFF_FFFF {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQueryEx(
                process,
                address as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if result == 0 {
                break;
            }
            let protect = mbi.Protect;
            let is_rwx = matches!(
                protect & 0xff,
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            );
            if mbi.State == MEM_COMMIT && is_rwx {
                emit_event(HipsEvent::SuspiciousRwxRegion {
                    pid,
                    addr: mbi.BaseAddress as usize,
                    size: mbi.RegionSize,
                });
                if mbi.Type == MEM_PRIVATE {
                    let region_address = mbi.BaseAddress as usize;
                    if protect & 0xff == PAGE_EXECUTE_READWRITE {
                        if let Some(mz_offset) =
                            private_executable_mz_offset(process, region_address, mbi.RegionSize)
                        {
                            emit_event(HipsEvent::SuspiciousReflectivePe {
                                pid,
                                addr: region_address,
                                size: mbi.RegionSize,
                                mz_offset,
                            });
                        }
                        for (indicator, token) in [
                            ("QueueUserAPC", b"QueueUserAPC".as_slice()),
                            ("NtQueueApcThread", b"NtQueueApcThread".as_slice()),
                            ("NtQueueApcThreadEx", b"NtQueueApcThreadEx".as_slice()),
                        ] {
                            if private_executable_memory_indicator(
                                process,
                                region_address,
                                mbi.RegionSize,
                                token,
                            ) {
                                emit_event(HipsEvent::SuspiciousApcInjection {
                                    pid,
                                    tid: 0,
                                    indicator: indicator.to_string(),
                                });
                                break;
                            }
                        }
                        for (indicator, token) in [
                            ("CreateThreadpoolWork", b"CreateThreadpoolWork".as_slice()),
                            ("SubmitThreadpoolWork", b"SubmitThreadpoolWork".as_slice()),
                            ("TpAllocWork", b"TpAllocWork".as_slice()),
                            ("TpPostWork", b"TpPostWork".as_slice()),
                            ("TpAllocTimer", b"TpAllocTimer".as_slice()),
                            ("TpSetTimer", b"TpSetTimer".as_slice()),
                        ] {
                            if private_executable_memory_indicator(
                                process,
                                region_address,
                                mbi.RegionSize,
                                token,
                            ) {
                                emit_event(HipsEvent::SuspiciousThreadPoolInjection {
                                    pid,
                                    addr: region_address,
                                    size: mbi.RegionSize,
                                    indicator: indicator.to_string(),
                                });
                                break;
                            }
                        }
                    }
                    if entropy_checks < 16 {
                        entropy_checks += 1;
                        if let Some(entropy) =
                            private_executable_entropy(process, region_address, mbi.RegionSize)
                        {
                            if entropy >= 7.2 {
                                emit_event(HipsEvent::SuspiciousMemoryLoad {
                                    pid,
                                    addr: region_address,
                                    size: mbi.RegionSize,
                                    entropy,
                                });
                            }
                        }
                    }
                }
            }
            address = address.saturating_add(mbi.RegionSize);
            if address == 0 {
                break;
            }
        }

        CloseHandle(process);
    }
}

#[cfg(target_os = "windows")]
fn query_ppl_protection(pid: u32) -> Option<u8> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    #[repr(C)]
    struct ProcessProtectionInformation {
        protection_level: u8,
        reserved: [u8; 7],
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process_handle: windows_sys::Win32::Foundation::HANDLE,
            process_information_class: u32,
            process_information: *mut core::ffi::c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut information = ProcessProtectionInformation {
        protection_level: 0,
        reserved: [0; 7],
    };
    let mut returned = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            61, // ProcessProtectionInformation
            (&mut information as *mut ProcessProtectionInformation).cast(),
            std::mem::size_of::<ProcessProtectionInformation>() as u32,
            &mut returned,
        )
    };
    unsafe { CloseHandle(process) };
    (status >= 0 && returned >= 1 && information.protection_level != 0)
        .then_some(information.protection_level)
}

#[cfg(target_os = "windows")]
fn looks_like_system_ppl_path(path: &str) -> bool {
    let lower = path.replace('/', "\\").to_ascii_lowercase();
    lower.contains("\\windows\\system32\\") || lower.contains("\\windows\\syswow64\\")
}

#[cfg(target_os = "windows")]
fn private_executable_entropy(
    process: windows_sys::Win32::Foundation::HANDLE,
    address: usize,
    size: usize,
) -> Option<f32> {
    use std::collections::HashSet;
    const MAX_SAMPLE: usize = 64 * 1024;
    let sample_size = size.min(MAX_SAMPLE);
    if sample_size < 256 {
        return None;
    }
    let mut bytes = vec![0u8; sample_size];
    let mut read = 0usize;
    let ok = unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            process,
            address as *const core::ffi::c_void,
            bytes.as_mut_ptr().cast(),
            sample_size,
            &mut read,
        )
    } != 0;
    if !ok || read < 256 {
        return None;
    }
    bytes.truncate(read);
    let unique = bytes.iter().copied().collect::<HashSet<_>>().len();
    if unique < 32 || bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[byte as usize] += 1;
    }
    let total = read as f32;
    let entropy = counts
        .iter()
        .filter(|count| **count != 0)
        .map(|count| {
            let probability = *count as f32 / total;
            -probability * probability.log2()
        })
        .sum();
    Some(entropy)
}

#[cfg(target_os = "windows")]
fn private_executable_memory_indicator(
    process: windows_sys::Win32::Foundation::HANDLE,
    address: usize,
    size: usize,
    token: &[u8],
) -> bool {
    const MAX_SAMPLE: usize = 64 * 1024;
    if token.is_empty() || size < token.len() {
        return false;
    }
    let sample_size = size.min(MAX_SAMPLE);
    let mut bytes = vec![0u8; sample_size];
    let mut read = 0usize;
    let ok = unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            process,
            address as *const core::ffi::c_void,
            bytes.as_mut_ptr().cast(),
            sample_size,
            &mut read,
        )
    } != 0;
    if !ok || read < token.len() {
        return false;
    }
    bytes[..read]
        .windows(token.len())
        .any(|window| window.eq_ignore_ascii_case(token))
}

#[cfg(target_os = "windows")]
fn private_executable_mz_offset(
    process: windows_sys::Win32::Foundation::HANDLE,
    address: usize,
    size: usize,
) -> Option<usize> {
    const MAX_SAMPLE: usize = 64 * 1024;
    if size < 2 {
        return None;
    }
    let sample_size = size.min(MAX_SAMPLE);
    let mut bytes = vec![0u8; sample_size];
    let mut read = 0usize;
    let ok = unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            process,
            address as *const core::ffi::c_void,
            bytes.as_mut_ptr().cast(),
            sample_size,
            &mut read,
        )
    } != 0;
    if !ok || read < 2 {
        return None;
    }
    bytes[..read].windows(2).position(|window| window == b"MZ")
}

#[cfg(target_os = "windows")]
fn scan_module_api_patches(
    pid: u32,
    process: windows_sys::Win32::Foundation::HANDLE,
    module_base: usize,
    module_path: &str,
) {
    const WATCHED_APIS: &[&str] = &[
        "AmsiOpenSession",
        "AmsiScanBuffer",
        "EtwEventWrite",
        "EtwWriteTrace",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "OpenProcess",
        "VirtualAllocEx",
        "QueueUserAPC",
        "NtQueueApcThread",
        "NtQueueApcThreadEx",
        "CreateThreadpoolWork",
        "SubmitThreadpoolWork",
        "TpAllocWork",
        "TpPostWork",
        "TpAllocTimer",
        "TpSetTimer",
    ];

    let file_bytes = match fs::read(module_path) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };

    let pe = match PE::parse(&file_bytes) {
        Ok(pe) => pe,
        Err(_) => return,
    };
    // goblin's PE exports are in pe.exports as Vec<Export>
    let exports = &pe.exports;

    // helper to map RVA -> file offset using section headers
    fn rva_to_file_offset(pe: &PE, rva: usize) -> Option<usize> {
        for sec in &pe.sections {
            let va = sec.virtual_address as usize;
            let vsz = sec.virtual_size as usize;
            if rva >= va && rva < va.saturating_add(vsz) {
                return Some((rva - va) + sec.pointer_to_raw_data as usize);
            }
        }
        None
    }

    for watched in WATCHED_APIS {
        if let Some(export) = exports.iter().find(|exp| {
            exp.name
                .as_ref()
                .is_some_and(|n| n.eq_ignore_ascii_case(watched))
        }) {
            let rva = export.rva;
            let rva_usize = rva;
            if let Some(file_offset) = rva_to_file_offset(&pe, rva_usize) {
                let target_bytes =
                    &file_bytes[file_offset..file_offset.saturating_add(16).min(file_bytes.len())];
                let address = (module_base + rva_usize) as *const core::ffi::c_void;
                let mut actual_bytes = vec![0u8; target_bytes.len()];
                let mut read = 0;
                let success = unsafe {
                    windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                        process,
                        address,
                        actual_bytes.as_mut_ptr() as *mut core::ffi::c_void,
                        actual_bytes.len(),
                        &mut read,
                    ) != 0
                };
                if success && read == target_bytes.len() && actual_bytes != target_bytes {
                    emit_event(HipsEvent::SuspiciousApiPatch {
                        pid,
                        module: module_path.to_string(),
                        function: watched.to_string(),
                        addr: module_base + rva,
                    });
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn analyze_threads_for_process(pid: u32) {
    use std::ptr::null;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        StackWalk64, SymCleanup, SymFunctionTableAccess64, SymGetModuleBase64, SymInitializeW,
        SymSetOptions, ADDRESS64, CONTEXT, CONTEXT_FULL_AMD64, CONTEXT_FULL_X86, STACKFRAME64,
        SYMOPT_DEFERRED_LOADS,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
    };

    const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;
    const IMAGE_FILE_MACHINE_I386: u32 = 0x014c;
    const MAX_THREADS_TO_INSPECT: usize = 8;

    fn has_private_executable_frame(
        process: windows_sys::Win32::Foundation::HANDLE,
        frames: &[usize],
    ) -> bool {
        for frame in frames {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            let queried = unsafe {
                VirtualQueryEx(
                    process,
                    *frame as *const _,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if queried == 0 || mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE {
                continue;
            }
            let protection = mbi.Protect & 0xff;
            if matches!(
                protection,
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            ) {
                return true;
            }
        }
        false
    }

    unsafe extern "system" fn read_memory64(
        hprocess: HANDLE,
        qwbaseaddress: u64,
        lpbuffer: *mut core::ffi::c_void,
        nsize: u32,
        lpnumberofbytesread: *mut u32,
    ) -> windows_sys::core::BOOL {
        let mut bytes_read = 0;
        let ok = ReadProcessMemory(
            hprocess,
            qwbaseaddress as *const core::ffi::c_void,
            lpbuffer,
            nsize as usize,
            &mut bytes_read,
        );
        if !lpnumberofbytesread.is_null() {
            *lpnumberofbytesread = bytes_read as u32;
        }
        ok
    }

    unsafe extern "system" fn function_table_access64(
        hprocess: HANDLE,
        addr_base: u64,
    ) -> *mut core::ffi::c_void {
        SymFunctionTableAccess64(hprocess, addr_base)
    }

    unsafe extern "system" fn get_module_base64(hprocess: HANDLE, address: u64) -> u64 {
        SymGetModuleBase64(hprocess, address)
    }

    unsafe extern "system" fn translate_address64(
        _hprocess: HANDLE,
        _hthread: HANDLE,
        lpaddr: *const ADDRESS64,
    ) -> u64 {
        if lpaddr.is_null() {
            return 0;
        }
        (*lpaddr).Offset
    }

    unsafe {
        let process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if process.is_null() {
            return;
        }
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap.is_null() {
            CloseHandle(process);
            return;
        }

        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        // We can initialize symbols for the current process; stack walk uses callbacks.
        let symbols_ready = SymInitializeW(process, null(), 0) != 0;
        if !symbols_ready {
            // proceed without symbol module loading
        } else {
            SymSetOptions(SYMOPT_DEFERRED_LOADS);
        }

        let mut inspected_threads = 0usize;
        if Thread32First(snap, &mut entry) != 0 {
            loop {
                if entry.th32OwnerProcessID == pid && inspected_threads < MAX_THREADS_TO_INSPECT {
                    inspected_threads += 1;
                    let tid = entry.th32ThreadID;
                    let thread = OpenThread(
                        THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                        0,
                        tid,
                    );
                    if !thread.is_null() {
                        let previous_suspend = SuspendThread(thread);
                        if previous_suspend != u32::MAX {
                            let mut context: CONTEXT = std::mem::zeroed();
                            context.ContextFlags = if cfg!(target_arch = "x86_64") {
                                CONTEXT_FULL_AMD64
                            } else {
                                CONTEXT_FULL_X86
                            };

                            if windows_sys::Win32::System::Diagnostics::Debug::GetThreadContext(
                                thread,
                                &mut context,
                            ) != 0
                            {
                                let mut frame: STACKFRAME64 = std::mem::zeroed();
                                // ADDRESS_MODE constants may be represented as integers; use flat mode (0)
                                frame.AddrPC.Mode = 0;
                                frame.AddrFrame.Mode = 0;
                                frame.AddrStack.Mode = 0;
                                #[cfg(target_arch = "x86_64")]
                                {
                                    frame.AddrPC.Offset = context.Rip;
                                    frame.AddrFrame.Offset = context.Rbp;
                                    frame.AddrStack.Offset = context.Rsp;
                                }
                                #[cfg(target_arch = "x86")]
                                {
                                    frame.AddrPC.Offset = context.Eip as u64;
                                    frame.AddrFrame.Offset = context.Ebp as u64;
                                    frame.AddrStack.Offset = context.Esp as u64;
                                }
                                let mut stack = Vec::new();
                                let machine_type = if cfg!(target_arch = "x86_64") {
                                    IMAGE_FILE_MACHINE_AMD64
                                } else {
                                    IMAGE_FILE_MACHINE_I386
                                };
                                for _ in 0..8 {
                                    let ok = StackWalk64(
                                        machine_type,
                                        process,
                                        thread,
                                        &mut frame,
                                        &mut context as *mut _ as *mut core::ffi::c_void,
                                        Some(read_memory64),
                                        Some(function_table_access64),
                                        Some(get_module_base64),
                                        Some(translate_address64),
                                    );
                                    if ok == 0 {
                                        break;
                                    }
                                    stack.push(frame.AddrPC.Offset as usize);
                                }
                                if !stack.is_empty()
                                    && has_private_executable_frame(process, &stack)
                                {
                                    emit_event(HipsEvent::SuspiciousThreadStack {
                                        pid,
                                        tid,
                                        ip: stack[0],
                                        stack,
                                    });
                                }
                            }
                            let _ = ResumeThread(thread);
                        }
                        CloseHandle(thread);
                    }
                }
                if Thread32Next(snap, &mut entry) == 0 {
                    break;
                }
            }
        }

        if symbols_ready {
            SymCleanup(process);
        }
        CloseHandle(snap);
        CloseHandle(process);
    }
}

#[cfg(not(target_os = "windows"))]
fn enumerate_processes() -> std::io::Result<Vec<(u32, String, u32)>> {
    // Fallback: no-op on non-Windows hosts for now.
    Ok(Vec::new())
}

/// Start a simple HIPS monitor thread. Currently uses periodic process
/// enumeration to detect suspicious parent->child chains (e.g. cmd.exe -> schtasks).
pub fn start_hips_monitor() {
    start_driver_review_worker();
    let mut running = HIPS_RUNNING.lock().unwrap();
    if *running {
        return;
    }
    *running = true;
    drop(running);

    thread::spawn(|| {
        info!("HIPS monitor started");
        const DEEP_RESCAN_INTERVAL: Duration = Duration::from_secs(15);
        let mut seen: HashSet<u32> = HashSet::new();
        let mut last_deep_scan: HashMap<u32, Instant> = HashMap::new();
        loop {
            if !protection_state::r3_enabled() {
                seen.clear();
                last_deep_scan.clear();
                thread::sleep(Duration::from_millis(500));
                continue;
            }
            match enumerate_processes() {
                Ok(list) => {
                    for (pid, exe, ppid) in list.iter() {
                        // The first tuple field is the process id and the
                        // third field is that process' parent id. The previous
                        // lookup compared the child's parent id with the
                        // candidate parent's parent id.
                        let is_new = seen.insert(*pid);
                        let parent = parent_process_name(&list, *ppid);
                        let chain_suspicious = exe.eq_ignore_ascii_case("schtasks.exe")
                            && (parent.eq_ignore_ascii_case("cmd.exe")
                                || parent.eq_ignore_ascii_case("powershell.exe"));
                        if is_new && chain_suspicious {
                            emit_event(HipsEvent::SuspiciousProcessChain {
                                parent,
                                child: exe.clone(),
                                pid: *pid,
                            });
                        }
                        // Full module/RWX inspection is expensive. Restrict
                        // it to LOLBin/script-host families, then rescan only
                        // at a low frequency so later DLL loads are visible.
                        let cookie_tool_name = is_known_cookie_tool_name(exe);
                        let deep_scan = chain_suspicious
                            || cookie_tool_name
                            || matches!(
                                exe.to_ascii_lowercase().as_str(),
                                "powershell.exe"
                                    | "pwsh.exe"
                                    | "cmd.exe"
                                    | "wscript.exe"
                                    | "cscript.exe"
                                    | "mshta.exe"
                                    | "rundll32.exe"
                                    | "regsvr32.exe"
                                    | "ctfmon.exe"
                                    | "schtasks.exe"
                                    | "explorer.exe"
                                    | "svchost.exe"
                                    | "runtimebroker.exe"
                                    | "dllhost.exe"
                                    | "spoolsv.exe"
                            );
                        let deep_scan_due = last_deep_scan
                            .get(pid)
                            .map(|last| last.elapsed() >= DEEP_RESCAN_INTERVAL)
                            .unwrap_or(true);
                        if deep_scan && (is_new || deep_scan_due) {
                            scan_process(*pid);
                            if is_new && chain_suspicious {
                                analyze_threads_for_process(*pid);
                            }
                            last_deep_scan.insert(*pid, Instant::now());
                        }
                    }
                    let current: HashSet<u32> = list.iter().map(|(pid, _, _)| *pid).collect();
                    seen.retain(|pid| current.contains(pid));
                    last_deep_scan.retain(|pid, _| current.contains(pid));
                }
                Err(err) => {
                    warn!("HIPS enumerate error: {}", err);
                }
            }
            thread::sleep(Duration::from_millis(3000));
        }
    });
}

/// Trigger a targeted inspection from the high-priority ETW path. The
/// function is intentionally read-only and delegates any enforcement to the
/// existing HIPS/fusion/driver-review pipeline.
#[cfg(target_os = "windows")]
pub fn scan_process_on_demand(pid: u32) {
    if protection_state::r3_enabled() {
        scan_process(pid);
    }
}

#[cfg(not(target_os = "windows"))]
pub fn scan_process_on_demand(_pid: u32) {}

fn parent_process_name(list: &[(u32, String, u32)], parent_pid: u32) -> String {
    list.iter()
        .find(|(candidate_pid, _, _)| *candidate_pid == parent_pid)
        .map(|(_, name, _)| name.clone())
        .unwrap_or_default()
}

fn normalized_path_directory(path: &str) -> Option<String> {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    normalized
        .rsplit_once('\\')
        .map(|(directory, _)| directory.to_string())
}

fn is_user_writable_path(path: &str) -> bool {
    let normalized = format!("\\{}\\", path.replace('/', "\\").to_ascii_lowercase());
    [
        "\\appdata\\",
        "\\local\\temp\\",
        "\\temp\\",
        "\\downloads\\",
        "\\programdata\\",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn is_windows_drivers_path(path: &str) -> bool {
    let normalized = format!("\\{}\\", path.replace('/', "\\").to_ascii_lowercase());
    normalized.contains("\\system32\\drivers\\") || normalized.contains("\\syswow64\\drivers\\")
}

fn is_dynamic_library_path(path: &str) -> bool {
    path.rsplit(['\\', '/'])
        .next()
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(".dll"))
}

fn is_executable_path(path: &str) -> bool {
    path.rsplit(['\\', '/'])
        .next()
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(".exe"))
}

fn ctf_hijack_dll_reason(process_path: &str, dll_path: &str) -> Option<&'static str> {
    if !is_dynamic_library_path(dll_path) {
        return None;
    }
    let process_lower = process_path.to_ascii_lowercase();
    let process_name = process_lower.rsplit(['\\', '/']).next().unwrap_or_default();
    if process_name != "ctfmon.exe" {
        return None;
    }
    if is_windows_drivers_path(dll_path) {
        Some("ctfmon-loaded-module-from-drivers-directory")
    } else if is_user_writable_path(dll_path) {
        Some("ctfmon-loaded-module-from-user-writable-directory")
    } else {
        None
    }
}

fn module_baseline_violation_reason(process_path: &str, dll_path: &str) -> Option<&'static str> {
    if !is_dynamic_library_path(dll_path) {
        return None;
    }
    let process_name = process_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let protected_loader = matches!(
        process_name.as_str(),
        "ctfmon.exe"
            | "explorer.exe"
            | "svchost.exe"
            | "runtimebroker.exe"
            | "dllhost.exe"
            | "spoolsv.exe"
    );
    if protected_loader && !(is_system_module_path(dll_path) || is_windows_drivers_path(dll_path)) {
        Some("protected-system-process-loaded-module-outside-system-roots")
    } else {
        None
    }
}

fn is_system_module_path(path: &str) -> bool {
    let normalized = format!("\\{}\\", path.replace('/', "\\").to_ascii_lowercase());
    normalized.contains("\\windows\\system32\\") || normalized.contains("\\windows\\syswow64\\")
}

fn looks_like_white_black_side_load(process_path: &str, dll_path: &str) -> bool {
    if !is_executable_path(process_path) || !is_dynamic_library_path(dll_path) {
        return false;
    }
    let process_lower = process_path.to_ascii_lowercase();
    let loader_name = process_lower
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&process_lower);
    let trusted_loader = matches!(
        loader_name,
        "rundll32.exe"
            | "regsvr32.exe"
            | "mshta.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "notepad.exe"
            | "werfault.exe"
            | "msiexec.exe"
    );
    let writable_dll = is_user_writable_path(dll_path);
    let same_writable_directory = is_user_writable_path(process_path)
        && writable_dll
        && normalized_path_directory(process_path) == normalized_path_directory(dll_path);
    same_writable_directory || (trusted_loader && writable_dll)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hips_event_description() {
        let ev = HipsEvent::SuspiciousProcessChain {
            parent: "cmd.exe".to_string(),
            child: "schtasks.exe".to_string(),
            pid: 1234,
        };
        let s = ev.description();
        assert!(s.contains("cmd.exe"));
        assert!(s.contains("schtasks.exe"));
    }

    #[test]
    fn parent_lookup_uses_process_id_not_parent_parent_id() {
        let processes = vec![
            (100, "cmd.exe".to_string(), 1),
            (200, "schtasks.exe".to_string(), 100),
            (300, "other.exe".to_string(), 200),
        ];
        assert_eq!(parent_process_name(&processes, 100), "cmd.exe");
        assert_eq!(parent_process_name(&processes, 999), "");
    }

    #[test]
    fn white_black_side_load_requires_same_writable_directory_and_dll() {
        assert!(looks_like_white_black_side_load(
            r"C:\Users\Alice\AppData\Local\Temp\trusted.exe",
            r"C:\Users\Alice\AppData\Local\Temp\version.dll"
        ));
        assert!(!looks_like_white_black_side_load(
            r"C:\Users\Alice\AppData\Local\Temp\trusted.exe",
            r"C:\Windows\System32\version.dll"
        ));
        assert!(!looks_like_white_black_side_load(
            r"C:\Users\Alice\AppData\Local\Temp\trusted.exe",
            r"C:\Users\Alice\AppData\Local\Temp\payload.exe"
        ));
    }

    #[test]
    fn ctf_hijack_rule_flags_ctfmon_loading_driver_directory_dll() {
        assert_eq!(
            ctf_hijack_dll_reason(
                r"C:\Windows\System32\ctfmon.exe",
                r"C:\Windows\System32\drivers\winmm.dll"
            ),
            Some("ctfmon-loaded-module-from-drivers-directory")
        );
        assert_eq!(
            ctf_hijack_dll_reason(
                r"C:\Windows\System32\ctfmon.exe",
                r"C:\Users\Alice\AppData\Local\Temp\msctf.dll"
            ),
            Some("ctfmon-loaded-module-from-user-writable-directory")
        );
        assert!(ctf_hijack_dll_reason(
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\drivers\winmm.dll"
        )
        .is_none());
    }

    #[test]
    fn protected_process_baseline_flags_non_system_module_origin() {
        assert_eq!(
            module_baseline_violation_reason(
                r"C:\Windows\System32\svchost.exe",
                r"C:\Users\Alice\AppData\Local\Temp\payload.dll"
            ),
            Some("protected-system-process-loaded-module-outside-system-roots")
        );
        assert!(module_baseline_violation_reason(
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows\System32\kernel32.dll"
        )
        .is_none());
    }

    #[test]
    fn advanced_injection_events_keep_distinct_descriptions() {
        let apc = HipsEvent::SuspiciousApcInjection {
            pid: 11,
            tid: 0,
            indicator: "QueueUserAPC".to_string(),
        };
        let pool = HipsEvent::SuspiciousThreadPoolInjection {
            pid: 11,
            addr: 0x1000,
            size: 0x2000,
            indicator: "TpAllocWork".to_string(),
        };
        let reflective = HipsEvent::SuspiciousReflectivePe {
            pid: 11,
            addr: 0x3000,
            size: 0x4000,
            mz_offset: 0,
        };
        assert!(apc.description().contains("APC injection"));
        assert!(pool.description().contains("PoolParty"));
        assert!(reflective.description().contains("Reflective PE"));
    }
}
