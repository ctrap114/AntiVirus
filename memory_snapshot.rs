//! Bounded memory evidence collection for sandboxed unpacking.
//!
//! This module is deliberately a recovery *evidence* layer, not a debugger or
//! a general-purpose dumper. It only reads a small, fixed amount of memory
//! from the AppContainer child process, looks for structurally valid PE
//! headers, and reports candidate image bases and entry-point RVAs. It never
//! executes bytes recovered from memory and never writes a recovered payload to
//! the host filesystem.

use serde::{Deserialize, Serialize};

/// A serializable summary attached to a [`crate::sandbox::SandboxReport`].
///
/// `status` is intentionally a small set of stable values:
/// `not_available`, `no_candidate`, `candidate`, and `recovered_candidate`.
/// A missing candidate is not evidence that a protected sample is benign.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SandboxUnpackingReport {
    pub status: String,
    pub regions_scanned: u32,
    pub executable_regions: u32,
    pub candidate_images: u32,
    pub recovered_entry_points: u32,
    pub observed_execution_points: u32,
    pub snapshot_rounds: u32,
    pub triggered_snapshots: u32,
    pub adaptive_timeout_ms: u64,
    pub bytes_captured: u64,
    pub truncated: bool,
    pub confidence: f32,
    pub candidates: Vec<MemoryImageCandidate>,
    pub notes: Vec<String>,
}

impl Default for SandboxUnpackingReport {
    fn default() -> Self {
        Self::unavailable("memory snapshot was not started")
    }
}

impl SandboxUnpackingReport {
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            status: "not_available".to_string(),
            regions_scanned: 0,
            executable_regions: 0,
            candidate_images: 0,
            recovered_entry_points: 0,
            observed_execution_points: 0,
            snapshot_rounds: 0,
            triggered_snapshots: 0,
            adaptive_timeout_ms: 0,
            bytes_captured: 0,
            truncated: false,
            confidence: 0.0,
            candidates: Vec::new(),
            notes: vec![reason.into()],
        }
    }

    pub fn no_candidate(reason: impl Into<String>) -> Self {
        Self {
            status: "no_candidate".to_string(),
            notes: vec![reason.into()],
            ..Self::default()
        }
    }
}

/// A PE image candidate found in executable memory. This is metadata only;
/// raw bytes are intentionally not included in the public report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryImageCandidate {
    pub region_base: u64,
    pub header_offset: u32,
    pub image_base: u64,
    pub image_size: u32,
    pub entry_point_rva: u32,
    pub entry_point_address: u64,
    pub observed_execution_address: Option<u64>,
    pub reconstruction_verified: bool,
    pub source: String,
    pub confidence: u8,
}

#[cfg(not(target_family = "windows"))]
pub struct MemorySnapshotCollector;

#[cfg(not(target_family = "windows"))]
impl MemorySnapshotCollector {
    pub fn unavailable() -> SandboxUnpackingReport {
        SandboxUnpackingReport::unavailable("memory snapshot requires Windows AppContainer")
    }
}

#[cfg(target_family = "windows")]
mod windows_impl {
    use super::{MemoryImageCandidate, SandboxUnpackingReport};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::thread::{self, JoinHandle};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
    #[cfg(target_arch = "x86_64")]
    use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64;
    #[cfg(target_arch = "x86")]
    use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_X86;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetThreadContext, ReadProcessMemory, CONTEXT,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS,
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows_sys::Win32::System::Threading::{
        OpenThread, THREAD_ACCESS_RIGHTS, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    };

    const POLL_INTERVAL: Duration = Duration::from_millis(180);
    const MAX_CAPTURE_BYTES: u64 = 32 * 1024 * 1024;
    const MAX_REGION_BYTES: usize = 4 * 1024 * 1024;
    const MAX_QUERY_REGIONS: u32 = 32_768;
    const MAX_EXECUTABLE_REGIONS: u32 = 96;
    const MAX_CANDIDATES: usize = 32;
    const MAX_IMAGE_SIZE: u32 = 512 * 1024 * 1024;
    const MAX_RECONSTRUCTED_IMAGE_BYTES: u32 = 16 * 1024 * 1024;
    const PAGE_MASK: u32 = 0xff;
    const PAGE_GUARD: u32 = 0x100;
    #[cfg(target_arch = "x86_64")]
    const CONTEXT_CONTROL_AMD64_VALUE: u32 = CONTEXT_CONTROL_AMD64;
    #[cfg(target_arch = "x86")]
    const CONTEXT_CONTROL_X86_VALUE: u32 = CONTEXT_CONTROL_X86;

    #[derive(Debug)]
    pub struct MemorySnapshotCollector {
        stop: Arc<AtomicBool>,
        trigger: Arc<AtomicBool>,
        join: Option<JoinHandle<CollectorState>>,
    }

    #[derive(Debug, Default)]
    struct CollectorState {
        regions_scanned: u32,
        executable_regions: u32,
        bytes_captured: u64,
        snapshot_rounds: u32,
        triggered_snapshots: u32,
        adaptive_timeout_ms: u64,
        truncated: bool,
        candidates: Vec<MemoryImageCandidate>,
        thread_ips: Vec<u64>,
        read_failures: u32,
    }

    impl MemorySnapshotCollector {
        pub fn start(process: HANDLE, pid: u32, trigger: Arc<AtomicBool>, timeout_ms: u64) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let worker_trigger = Arc::clone(&trigger);
            let process_value = process as usize;
            let join = thread::Builder::new()
                .name(format!("heliosav-unpack-{pid}"))
                .spawn(move || {
                    collect_until_stopped(
                        process_value as HANDLE,
                        pid,
                        worker_stop,
                        worker_trigger,
                        timeout_ms,
                    )
                })
                .ok();
            Self {
                stop,
                trigger,
                join,
            }
        }

        pub fn finish(mut self) -> SandboxUnpackingReport {
            self.stop.store(true, Ordering::Release);
            let Some(join) = self.join.take() else {
                return SandboxUnpackingReport::unavailable(
                    "memory snapshot worker could not start",
                );
            };
            match join.join() {
                Ok(state) => state.into_report(),
                Err(_) => SandboxUnpackingReport::unavailable("memory snapshot worker panicked"),
            }
        }

        pub fn trigger_now(&self) {
            self.trigger.store(true, Ordering::Release);
        }
    }

    impl Drop for MemorySnapshotCollector {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn collect_until_stopped(
        process: HANDLE,
        pid: u32,
        stop: Arc<AtomicBool>,
        trigger: Arc<AtomicBool>,
        timeout_ms: u64,
    ) -> CollectorState {
        let mut state = CollectorState::default();
        state.adaptive_timeout_ms = timeout_ms;
        log::info!("UNPACKING_MEMORY_SNAPSHOT_STARTED pid={pid} max_bytes={MAX_CAPTURE_BYTES}");
        let mut next_round = std::time::Instant::now();
        while !stop.load(Ordering::Acquire) {
            let event_triggered = trigger.swap(false, Ordering::AcqRel);
            if event_triggered || std::time::Instant::now() >= next_round {
                state.snapshot_rounds = state.snapshot_rounds.saturating_add(1);
                if event_triggered {
                    state.triggered_snapshots = state.triggered_snapshots.saturating_add(1);
                }
                collect_once(process, &mut state);
                next_round = std::time::Instant::now()
                    + if event_triggered {
                        Duration::from_millis(60)
                    } else {
                        Duration::from_millis(220)
                    };
            }
            if state.truncated || state.candidates.len() >= MAX_CANDIDATES {
                // Keep a small polling window after the first candidate. This
                // lets a later thread instruction pointer corroborate the PE
                // candidate without continuously reading more memory.
                thread::sleep(POLL_INTERVAL);
                collect_thread_ips(pid, &mut state.thread_ips);
                break;
            }
            thread::sleep(Duration::from_millis(40));
        }
        collect_thread_ips(pid, &mut state.thread_ips);
        log::info!(
            "UNPACKING_MEMORY_SNAPSHOT_FINISHED pid={pid} regions={} executable_regions={} candidates={} bytes={} truncated={}",
            state.regions_scanned,
            state.executable_regions,
            state.candidates.len(),
            state.bytes_captured,
            state.truncated
        );
        state
    }

    fn collect_once(process: HANDLE, state: &mut CollectorState) {
        if state.truncated || state.regions_scanned >= MAX_QUERY_REGIONS {
            state.truncated = true;
            return;
        }
        let mut address = 0usize;
        let mut info = MEMORY_BASIC_INFORMATION::default();
        while state.regions_scanned < MAX_QUERY_REGIONS
            && state.executable_regions < MAX_EXECUTABLE_REGIONS
            && state.bytes_captured < MAX_CAPTURE_BYTES
        {
            let queried = unsafe {
                VirtualQueryEx(
                    process,
                    address as *const core::ffi::c_void,
                    &mut info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if queried == 0 || info.RegionSize == 0 {
                break;
            }
            state.regions_scanned = state.regions_scanned.saturating_add(1);
            let next = address.saturating_add(info.RegionSize);
            if next <= address {
                break;
            }
            address = next;

            let image_region = info.Type == MEM_IMAGE;
            let suspicious_mapped_image = image_region && is_writable_executable(info.Protect);
            if info.State != MEM_COMMIT
                || !is_executable(info.Protect)
                || (info.Type != MEM_PRIVATE && !suspicious_mapped_image)
            {
                continue;
            }
            state.executable_regions = state.executable_regions.saturating_add(1);
            let remaining = (MAX_CAPTURE_BYTES - state.bytes_captured) as usize;
            let read_len = info.RegionSize.min(MAX_REGION_BYTES).min(remaining);
            if read_len == 0 {
                state.truncated = true;
                break;
            }
            let mut bytes = vec![0u8; read_len];
            let mut read = 0usize;
            let ok = unsafe {
                ReadProcessMemory(
                    process,
                    info.BaseAddress as *const core::ffi::c_void,
                    bytes.as_mut_ptr().cast(),
                    read_len,
                    &mut read,
                )
            };
            if ok == 0 || read < 0x40 {
                state.read_failures = state.read_failures.saturating_add(1);
                continue;
            }
            bytes.truncate(read);
            state.bytes_captured = state.bytes_captured.saturating_add(read as u64);
            let region_base = info.BaseAddress as usize as u64;
            for candidate in find_pe_candidates(&bytes, region_base, image_region) {
                if state.candidates.iter().any(|existing| {
                    existing.region_base == candidate.region_base
                        && existing.header_offset == candidate.header_offset
                        && existing.entry_point_address == candidate.entry_point_address
                }) {
                    continue;
                }
                state.candidates.push(candidate);
                if state.candidates.len() >= MAX_CANDIDATES {
                    state.truncated = true;
                    break;
                }
            }
            if info.RegionSize > read_len || state.bytes_captured >= MAX_CAPTURE_BYTES {
                state.truncated = true;
                break;
            }
        }
        if state.regions_scanned >= MAX_QUERY_REGIONS
            || state.executable_regions >= MAX_EXECUTABLE_REGIONS
            || state.bytes_captured >= MAX_CAPTURE_BYTES
        {
            state.truncated = true;
        }
    }

    fn is_executable(protect: u32) -> bool {
        let base = protect & PAGE_MASK;
        matches!(
            base,
            PAGE_EXECUTE
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
                | PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
        ) && base != PAGE_NOACCESS
            && protect & PAGE_GUARD == 0
            && matches!(
                base,
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            )
    }

    fn is_writable_executable(protect: u32) -> bool {
        matches!(
            protect & PAGE_MASK,
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        ) && protect & PAGE_GUARD == 0
    }

    fn find_pe_candidates(
        bytes: &[u8],
        region_base: u64,
        image_region: bool,
    ) -> Vec<MemoryImageCandidate> {
        let mut candidates = Vec::new();
        for (offset, window) in bytes.windows(2).enumerate() {
            if window != b"MZ" || offset + 0x40 > bytes.len() {
                continue;
            }
            let Some(candidate) = parse_pe_candidate(bytes, offset, region_base, image_region)
            else {
                continue;
            };
            candidates.push(candidate);
            if candidates.len() >= 8 {
                break;
            }
        }
        candidates
    }

    fn parse_pe_candidate(
        bytes: &[u8],
        offset: usize,
        region_base: u64,
        image_region: bool,
    ) -> Option<MemoryImageCandidate> {
        let e_lfanew = read_u32(bytes, offset.checked_add(0x3c)?)? as usize;
        let pe_offset = offset.checked_add(e_lfanew)?;
        if pe_offset.checked_add(24)? > bytes.len() || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0"
        {
            return None;
        }
        let section_count = read_u16(bytes, pe_offset + 6)?;
        let optional_size = read_u16(bytes, pe_offset + 20)? as usize;
        if !(1..=96).contains(&section_count) || optional_size < 64 {
            return None;
        }
        let optional = pe_offset.checked_add(24)?;
        if optional.checked_add(optional_size)? > bytes.len() {
            return None;
        }
        let magic = read_u16(bytes, optional)?;
        let image_base = match magic {
            0x10b => read_u32(bytes, optional + 28)? as u64,
            0x20b => read_u64(bytes, optional + 24)?,
            _ => return None,
        };
        let entry_rva = read_u32(bytes, optional + 16)?;
        let image_size = read_u32(bytes, optional + 56)?;
        let headers_size = read_u32(bytes, optional + 60)?;
        if image_size == 0 || image_size > MAX_IMAGE_SIZE || entry_rva >= image_size {
            return None;
        }
        let section_table = optional.checked_add(optional_size)?;
        let section_table_size = (section_count as usize).checked_mul(40)?;
        if section_table.checked_add(section_table_size)? > bytes.len()
            || headers_size == 0
            || headers_size > image_size
            || offset.checked_add(headers_size as usize)? > bytes.len()
        {
            return None;
        }
        let mut reconstruction_verified = true;
        for index in 0..section_count as usize {
            let section = section_table.checked_add(index.checked_mul(40)?)?;
            let virtual_size = read_u32(bytes, section + 8)?.max(1);
            let virtual_address = read_u32(bytes, section + 12)?;
            let section_end = virtual_address.checked_add(virtual_size)?;
            if virtual_address >= image_size || section_end > image_size {
                return None;
            }
            if offset
                .checked_add(virtual_address as usize)?
                .checked_add(virtual_size as usize)?
                > bytes.len()
            {
                reconstruction_verified = false;
            }
        }
        if reconstruction_verified
            && image_size <= MAX_RECONSTRUCTED_IMAGE_BYTES
            && !reconstruct_image_in_memory(
                bytes,
                offset,
                headers_size as usize,
                section_table,
                section_count as usize,
                image_size as usize,
            )
        {
            reconstruction_verified = false;
        }
        let mapped_base = region_base.checked_add(offset as u64)?;
        let entry_point_address = mapped_base.checked_add(entry_rva as u64)?;
        Some(MemoryImageCandidate {
            region_base,
            header_offset: offset as u32,
            image_base,
            image_size,
            entry_point_rva: entry_rva,
            entry_point_address,
            observed_execution_address: None,
            reconstruction_verified,
            source: if image_region {
                "mapped_image".to_string()
            } else {
                "private_executable_memory".to_string()
            },
            confidence: if image_region { 82 } else { 74 },
        })
    }

    /// Rebuild a mapped PE image in memory only. The returned buffer is
    /// dropped before the candidate leaves this function; no payload is
    /// persisted and no reconstructed code is ever invoked.
    fn reconstruct_image_in_memory(
        bytes: &[u8],
        offset: usize,
        headers_size: usize,
        section_table: usize,
        section_count: usize,
        image_size: usize,
    ) -> bool {
        let mut image = vec![0u8; image_size];
        let header_source = match offset.checked_add(headers_size) {
            Some(end) if end <= bytes.len() && headers_size <= image.len() => end,
            _ => return false,
        };
        image[..headers_size].copy_from_slice(&bytes[offset..header_source]);
        for index in 0..section_count {
            let Some(section) = section_table.checked_add(index.saturating_mul(40)) else {
                return false;
            };
            let Some(virtual_size) = read_u32(bytes, section + 8).map(|size| size.max(1)) else {
                return false;
            };
            let Some(virtual_address) = read_u32(bytes, section + 12) else {
                return false;
            };
            let destination = virtual_address as usize;
            let size = virtual_size as usize;
            let Some(source) = offset.checked_add(destination) else {
                return false;
            };
            let Some(source_end) = source.checked_add(size) else {
                return false;
            };
            let Some(destination_end) = destination.checked_add(size) else {
                return false;
            };
            if source_end > bytes.len() || destination_end > image.len() {
                return false;
            }
            image[destination..destination_end].copy_from_slice(&bytes[source..source_end]);
        }
        image.len() >= 2 && &image[..2] == b"MZ"
    }

    fn collect_thread_ips(pid: u32, output: &mut Vec<u64>) {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot.is_null() || snapshot == (-1isize as HANDLE) {
            return;
        }
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut has_entry = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        while has_entry {
            if entry.th32OwnerProcessID == pid {
                let access: THREAD_ACCESS_RIGHTS = THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;
                let thread = unsafe { OpenThread(access, FALSE, entry.th32ThreadID) };
                if !thread.is_null() {
                    if let Some(ip) = read_thread_ip(thread) {
                        if ip != 0 && !output.contains(&ip) {
                            output.push(ip);
                        }
                    }
                    unsafe { CloseHandle(thread) };
                }
            }
            has_entry = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        unsafe { CloseHandle(snapshot) };
    }

    #[cfg(target_arch = "x86_64")]
    fn read_thread_ip(thread: HANDLE) -> Option<u64> {
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_CONTROL_AMD64_VALUE,
            ..Default::default()
        };
        let ok = unsafe { GetThreadContext(thread, &mut context) } != 0;
        ok.then_some(context.Rip)
    }

    #[cfg(target_arch = "x86")]
    fn read_thread_ip(thread: HANDLE) -> Option<u64> {
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_CONTROL_X86_VALUE,
            ..Default::default()
        };
        let ok = unsafe { GetThreadContext(thread, &mut context) } != 0;
        ok.then_some(context.Eip as u64)
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn read_thread_ip(_thread: HANDLE) -> Option<u64> {
        None
    }

    impl CollectorState {
        fn into_report(mut self) -> SandboxUnpackingReport {
            let mut observed = 0u32;
            for candidate in &mut self.candidates {
                if let Some(ip) = self.thread_ips.iter().copied().find(|ip| {
                    let end = candidate
                        .entry_point_address
                        .saturating_sub(candidate.entry_point_rva as u64)
                        .saturating_add(candidate.image_size as u64);
                    *ip >= candidate
                        .entry_point_address
                        .saturating_sub(candidate.entry_point_rva as u64)
                        && *ip < end
                }) {
                    candidate.observed_execution_address = Some(ip);
                    candidate.confidence = candidate.confidence.saturating_add(12).min(100);
                    observed = observed.saturating_add(1);
                }
            }
            for candidate in &mut self.candidates {
                if candidate.reconstruction_verified {
                    candidate.confidence = candidate.confidence.saturating_add(8).min(100);
                }
            }
            let recovered = self
                .candidates
                .iter()
                .filter(|candidate| candidate.reconstruction_verified)
                .count() as u32;
            let status = if recovered > 0 {
                "recovered_candidate"
            } else {
                "candidate"
            };
            let confidence = self
                .candidates
                .iter()
                .map(|candidate| candidate.confidence as f32 / 100.0)
                .fold(0.0, f32::max);
            let mut notes = Vec::new();
            if self.truncated {
                notes.push("capture_budget_reached".to_string());
            }
            if self.read_failures > 0 {
                notes.push(format!("memory_read_failures:{}", self.read_failures));
            }
            if observed > 0 {
                notes.push("thread_instruction_pointer_correlated".to_string());
            }
            if recovered > 0 {
                notes.push("pe_image_reconstructed_in_memory_only".to_string());
            }
            if self.candidates.is_empty() {
                notes.push("no_structurally_valid_pe_in_executable_memory".to_string());
            }
            SandboxUnpackingReport {
                status: if self.candidates.is_empty() {
                    "no_candidate".to_string()
                } else {
                    status.to_string()
                },
                regions_scanned: self.regions_scanned,
                executable_regions: self.executable_regions,
                candidate_images: self.candidates.len() as u32,
                recovered_entry_points: recovered,
                observed_execution_points: observed,
                snapshot_rounds: self.snapshot_rounds,
                triggered_snapshots: self.triggered_snapshots,
                adaptive_timeout_ms: self.adaptive_timeout_ms,
                bytes_captured: self.bytes_captured,
                truncated: self.truncated,
                confidence,
                candidates: self.candidates,
                notes,
            }
        }
    }

    #[cfg(test)]
    #[allow(clippy::items_after_test_module)]
    mod tests {
        use super::*;

        #[test]
        fn validates_and_reconstructs_bounded_pe_image() {
            let mut bytes = vec![0u8; 0x4000];
            bytes[0..2].copy_from_slice(b"MZ");
            bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
            bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
            bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
            bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
            let optional = 0x98;
            bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
            bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
            bytes[optional + 24..optional + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
            bytes[optional + 56..optional + 60].copy_from_slice(&0x3000u32.to_le_bytes());
            bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
            let section = optional + 0xf0;
            bytes[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
            bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
            bytes[0x1000] = 0xcc;

            let candidate = parse_pe_candidate(&bytes, 0, 0x10000000, false)
                .expect("synthetic PE should be structurally valid");
            assert_eq!(candidate.entry_point_address, 0x10001000);
            assert!(candidate.reconstruction_verified);
        }

        #[test]
        fn rejects_section_outside_image_bounds() {
            let mut bytes = vec![0u8; 0x4000];
            bytes[0..2].copy_from_slice(b"MZ");
            bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
            bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
            bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
            let optional = 0x98;
            bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
            bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
            bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
            bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
            let section = optional + 0xf0;
            bytes[section + 8..section + 12].copy_from_slice(&0x2000u32.to_le_bytes());
            bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());

            assert!(parse_pe_candidate(&bytes, 0, 0x10000000, false).is_none());
        }
    }

    fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
        let end = offset.checked_add(2)?;
        bytes
            .get(offset..end)
            .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
        let end = offset.checked_add(4)?;
        let slice = bytes.get(offset..end)?;
        Some(u32::from_le_bytes(slice.try_into().ok()?))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
        let end = offset.checked_add(8)?;
        let slice = bytes.get(offset..end)?;
        Some(u64::from_le_bytes(slice.try_into().ok()?))
    }
}

#[cfg(target_family = "windows")]
pub use windows_impl::MemorySnapshotCollector;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_report_is_explicit() {
        let report = SandboxUnpackingReport::unavailable("guest pid unavailable");
        assert_eq!(report.status, "not_available");
        assert_eq!(report.candidate_images, 0);
        assert_eq!(report.notes, vec!["guest pid unavailable"]);
    }

    #[test]
    fn candidate_metadata_round_trips_without_raw_bytes() {
        let report = SandboxUnpackingReport {
            status: "recovered_candidate".to_string(),
            regions_scanned: 2,
            executable_regions: 1,
            candidate_images: 1,
            recovered_entry_points: 1,
            observed_execution_points: 1,
            snapshot_rounds: 2,
            triggered_snapshots: 1,
            adaptive_timeout_ms: 30000,
            bytes_captured: 4096,
            truncated: false,
            confidence: 0.86,
            candidates: vec![MemoryImageCandidate {
                region_base: 0x1000,
                header_offset: 0,
                image_base: 0x400000,
                image_size: 0x2000,
                entry_point_rva: 0x1000,
                entry_point_address: 0x401000,
                observed_execution_address: Some(0x401000),
                reconstruction_verified: true,
                source: "private_executable_memory".to_string(),
                confidence: 86,
            }],
            notes: vec!["thread_instruction_pointer_correlated".to_string()],
        };
        let json = serde_json::to_string(&report).expect("serialize report");
        assert!(!json.contains("raw_bytes"));
        let restored: SandboxUnpackingReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, report);
    }
}
