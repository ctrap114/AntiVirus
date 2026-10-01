//! User-mode control-plane bridge for the optional EverbloomSecurity WDM driver.
//!
//! The bridge is deliberately fail-closed for the request format but
//! fail-open for availability: if the optional driver is absent, the Rust
//! HIPS/fusion path remains authoritative and reports the degraded mode.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use thiserror::Error;

pub const IOCTL_AMSI_SCAN_BUFFER: u32 = 0x8000_2010;
pub const IOCTL_SCAN_FILE: u32 = 0x8000_2020;
pub const IOCTL_NET_INSPECT: u32 = 0x8000_3010;
pub const IOCTL_BEHAVIOR_ANALYZE: u32 = 0x8000_4010;
pub const IOCTL_POLICY_UPDATE: u32 = 0x8000_5010;
pub const IOCTL_POLICY_CLEAR: u32 = 0x8000_5020;
pub const IOCTL_PROTECTION_UPDATE: u32 = 0x8000_5030;
pub const IOCTL_EVENT_READ: u32 = 0x8000_6010;
pub const IOCTL_CAPABILITIES_QUERY: u32 = 0x8000_6020;
const PROTOCOL_VERSION: u32 = 1;
const POLICY_VERSION: u32 = 1;
const POLICY_KIND_PROCESS: u32 = 1;
const POLICY_KIND_FILE: u32 = 2;
const POLICY_KIND_NETWORK: u32 = 3;
const POLICY_KIND_REGISTRY: u32 = 4;
const POLICY_KIND_RAW_DISK: u32 = 5;
const POLICY_ACTION_BLOCK: u32 = 1;
const PROTECTION_PROTOCOL_VERSION: u32 = 1;
const MAX_TARGET_CHARS: usize = 260;
const MAX_PAYLOAD: usize = 4096;
const DRIVER_EVENT_VERSION: u32 = 1;
const EVENT_MAX_BATCH: usize = 32;
const MAX_EVENT_REASON_CHARS: usize = 128;
const CAPABILITIES_VERSION: u32 = 1;
const CAPABILITY_SCAN_FILE: u64 = 0x0000_0001;
const CAPABILITY_BEHAVIOR_ANALYZE: u64 = 0x0000_0002;
const CAPABILITY_POLICY_UPDATE: u64 = 0x0000_0004;
const CAPABILITY_PROTECTION_UPDATE: u64 = 0x0000_0008;
const CAPABILITY_EVENT_READ: u64 = 0x0000_0010;
const CAPABILITY_REGISTRY_POLICY: u64 = 0x0000_0020;
const CAPABILITY_RAW_DISK_POLICY: u64 = 0x0000_0040;
const CAPABILITY_NETWORK_POLICY: u64 = 0x0000_0080;
/// Set when the driver has an inference model linked in, i.e. when
/// `EVERBLOOM_EVENT_KIND_MODEL_SCORE` events can actually be emitted. A build
/// without a model never sets it, so nothing here waits on scores that cannot
/// arrive.
const CAPABILITY_KERNEL_MODEL: u64 = 0x0000_0100;
const VULNERABLE_DRIVER_UPDATE_MAX_BYTES: u64 = 256 * 1024;

/// Known vulnerable or abuse-prone driver image names. This list is used by
/// the user-mode scanner as a detection signal; the kernel has a matching
/// fixed list for file-open blocking and load telemetry. Names are basenames,
/// never arbitrary path fragments, to keep the rule auditable.
pub const VULNERABLE_DRIVER_NAMES: &[&str] = &[
    "BdApiUtil64.sys",
    "zam64.sys",
    "BootRepair.sys",
    "EnPortv.sys",
    "wsftprm.sys",
    "TrueSightKiller.sys",
    "llama.sys",
    "ollama.sys",
];

static VULNERABLE_DRIVER_OVERRIDES: OnceLock<RwLock<Vec<String>>> = OnceLock::new();

fn vulnerable_driver_overrides() -> &'static RwLock<Vec<String>> {
    VULNERABLE_DRIVER_OVERRIDES.get_or_init(|| RwLock::new(Vec::new()))
}

pub fn known_vulnerable_driver_name(path_or_name: &str) -> Option<String> {
    let basename = path_or_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path_or_name);
    if let Some(name) = VULNERABLE_DRIVER_NAMES
        .iter()
        .copied()
        .find(|candidate| basename.eq_ignore_ascii_case(candidate))
    {
        return Some(name.to_string());
    }
    vulnerable_driver_overrides().read().ok().and_then(|names| {
        names
            .iter()
            .find(|candidate| basename.eq_ignore_ascii_case(candidate))
            .cloned()
    })
}

/// Return the validated basename list that should be mirrored into the
/// kernel file-policy table. The list is intentionally basename-only; the
/// kernel performs the final device-path normalization before denying a
/// driver image.
pub fn vulnerable_driver_names() -> Vec<String> {
    let mut names = VULNERABLE_DRIVER_NAMES
        .iter()
        .map(|name| (*name).to_string())
        .collect::<Vec<_>>();
    if let Ok(overrides) = vulnerable_driver_overrides().read() {
        for name in overrides.iter() {
            if !names
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(name))
            {
                names.push(name.clone());
            }
        }
    }
    names
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VulnerableDriverUpdate {
    Array(Vec<String>),
    Object {
        drivers: Option<Vec<String>>,
        vulnerable_drivers: Option<Vec<String>>,
    },
}

pub fn reload_vulnerable_driver_names_from_file<P: AsRef<Path>>(
    path: P,
    expected_sha256: Option<&str>,
) -> Result<usize, String> {
    let path = path.as_ref();
    let metadata = fs::metadata(path)
        .map_err(|error| format!("vulnerable driver list is not accessible: {error}"))?;
    if !metadata.is_file() {
        return Err("vulnerable driver list path is not a regular file".to_string());
    }
    if metadata.len() > VULNERABLE_DRIVER_UPDATE_MAX_BYTES {
        return Err(format!(
            "vulnerable driver list exceeds {} KiB",
            VULNERABLE_DRIVER_UPDATE_MAX_BYTES / 1024
        ));
    }
    let bytes = fs::read(path).map_err(|error| format!("unable to read driver list: {error}"))?;
    if let Some(expected) = expected_sha256
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let actual = hex::encode(Sha256::digest(&bytes));
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "vulnerable driver list SHA256 mismatch: expected {expected}, got {actual}"
            ));
        }
    }

    let update: VulnerableDriverUpdate = serde_json::from_slice(&bytes)
        .map_err(|error| format!("unable to parse vulnerable driver list JSON: {error}"))?;
    let supplied = match update {
        VulnerableDriverUpdate::Array(names) => names,
        VulnerableDriverUpdate::Object {
            drivers,
            vulnerable_drivers,
        } => drivers.or(vulnerable_drivers).unwrap_or_default(),
    };

    let mut merged = Vec::new();
    for raw in supplied {
        let basename = raw
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(raw.as_str())
            .trim()
            .trim_matches('"')
            .to_string();
        if basename.is_empty()
            || basename.contains('*')
            || basename.contains('?')
            || basename.contains(':')
            || basename.len() > 128
        {
            continue;
        }
        if VULNERABLE_DRIVER_NAMES
            .iter()
            .any(|builtin| builtin.eq_ignore_ascii_case(&basename))
            || merged
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(&basename))
        {
            continue;
        }
        merged.push(basename);
    }

    let count = merged.len();
    *vulnerable_driver_overrides()
        .write()
        .map_err(|_| "vulnerable driver list lock poisoned".to_string())? = merged;
    Ok(count + VULNERABLE_DRIVER_NAMES.len())
}

pub fn reload_vulnerable_driver_names_from_default_locations() -> Result<Option<usize>, String> {
    let expected = std::env::var("EVERBLOOM_VULNERABLE_DRIVERS_SHA256").ok();
    let configured = std::env::var_os("EVERBLOOM_VULNERABLE_DRIVERS_FILE").map(PathBuf::from);
    let mut candidates = Vec::new();
    if let Some(path) = configured {
        candidates.push(path);
    } else {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                candidates.push(parent.join("data").join("vulnerable_drivers.json"));
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join("data").join("vulnerable_drivers.json"));
        }
    }

    for candidate in candidates {
        if candidate.is_file() {
            return reload_vulnerable_driver_names_from_file(candidate, expected.as_deref())
                .map(Some);
        }
    }
    Ok(None)
}

#[derive(Debug, Error)]
pub enum DriverBridgeError {
    #[error("driver bridge is unavailable on this platform")]
    Unsupported,
    #[error("driver I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("driver returned an invalid response")]
    InvalidResponse,
}
impl DriverBridgeError {
    /// Missing service/device and access-denied cases are an expected
    /// deployment state for the optional kernel layer. Callers should disable
    /// only the driver layer and keep R3 scanning/protection active.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unsupported)
            || matches!(
                self,
                Self::Io(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(2 | 3 | 5 | 1060 | 1168 | 1223)
                    )
            )
    }

    pub fn unavailable_message(&self) -> String {
        match self {
            Self::Unsupported => "driver bridge is unsupported on this platform".to_string(),
            Self::Io(error) if self.is_unavailable() => {
                format!("driver device is unavailable: {error}")
            }
            _ => self.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverVerdict {
    pub request_id: u64,
    pub blocked: bool,
    pub threat: u32,
    pub action: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverEvent {
    pub kind: u32,
    pub status: u32,
    pub caller_pid: u32,
    pub sequence: u64,
    pub timestamp: i64,
    pub target: String,
    pub reason: String,
}

/// One destructive read from the kernel audit ring. `dropped` is part of the
/// transport result rather than a log-only side effect so the NDJSON/UI path
/// can expose an incomplete event stream explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DriverEventBatch {
    pub events: Vec<DriverEvent>,
    pub dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverCapabilities {
    pub protocol_version: u32,
    pub policy_version: u32,
    pub protection_protocol_version: u32,
    pub event_version: u32,
    pub max_target_chars: u32,
    pub max_payload_bytes: u32,
    pub max_event_batch: u32,
    pub capability_flags: u64,
}

impl DriverCapabilities {
    pub fn is_compatible(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
            && self.policy_version == POLICY_VERSION
            && self.protection_protocol_version == PROTECTION_PROTOCOL_VERSION
            && self.event_version == DRIVER_EVENT_VERSION
            && self.max_target_chars as usize >= MAX_TARGET_CHARS
            && self.max_payload_bytes as usize >= MAX_PAYLOAD
            && self.max_event_batch as usize >= EVENT_MAX_BATCH
            && self.has(CAPABILITY_SCAN_FILE)
            && self.has(CAPABILITY_POLICY_UPDATE)
            && self.has(CAPABILITY_PROTECTION_UPDATE)
            && self.has(CAPABILITY_EVENT_READ)
    }

    pub fn summary(&self) -> String {
        let mut flags = Vec::new();
        if self.has(CAPABILITY_SCAN_FILE) {
            flags.push("scan_file");
        }
        if self.has(CAPABILITY_BEHAVIOR_ANALYZE) {
            flags.push("behavior");
        }
        if self.has(CAPABILITY_POLICY_UPDATE) {
            flags.push("policy");
        }
        if self.has(CAPABILITY_PROTECTION_UPDATE) {
            flags.push("protection");
        }
        if self.has(CAPABILITY_EVENT_READ) {
            flags.push("events");
        }
        if self.has(CAPABILITY_REGISTRY_POLICY) {
            flags.push("registry");
        }
        if self.has(CAPABILITY_RAW_DISK_POLICY) {
            flags.push("raw_disk");
        }
        if self.has(CAPABILITY_NETWORK_POLICY) {
            flags.push("network");
        }
        if self.has(CAPABILITY_KERNEL_MODEL) {
            flags.push("kernel_model");
        }
        format!(
            "protocol={} policy={} protection={} events={} target={} payload={} event_batch={} flags={}",
            self.protocol_version,
            self.policy_version,
            self.protection_protocol_version,
            self.event_version,
            self.max_target_chars,
            self.max_payload_bytes,
            self.max_event_batch,
            flags.join("|")
        )
    }

    /// True when the loaded driver reported `EVERBLOOM_CAPABILITY_KERNEL_MODEL`.
    ///
    /// The driver only advertises this bit when an integer model is actually
    /// linked into the image, so it is the authoritative answer to "will the
    /// kernel score process launches on this machine". A driver built without
    /// a model never sets it, which is why user mode must not wait for scores
    /// unconditionally.
    pub fn has_kernel_model(&self) -> bool {
        self.has(CAPABILITY_KERNEL_MODEL)
    }

    fn has(&self, flag: u64) -> bool {
        self.capability_flags & flag != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DriverRequest {
    version: u32,
    operation: u32,
    request_id: u64,
    caller_pid: u32,
    payload_length: u32,
    target: [u16; MAX_TARGET_CHARS],
    payload: [u8; MAX_PAYLOAD],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DriverResponse {
    version: u32,
    verdict: u32,
    threat: u32,
    action: u32,
    request_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PolicyCommand {
    version: u32,
    kind: u32,
    action: u32,
    ipv4_address: u32,
    port: u16,
    reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProtectionCommand {
    version: u32,
    r3_enabled: u32,
    driver_enabled: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EventQuery {
    version: u32,
    max_events: u32,
    reserved: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DriverEventRecord {
    version: u32,
    kind: u32,
    status: u32,
    caller_pid: u32,
    sequence: u64,
    timestamp: i64,
    target: [u16; MAX_TARGET_CHARS],
    reason: [u16; MAX_EVENT_REASON_CHARS],
}

impl Default for DriverEventRecord {
    fn default() -> Self {
        Self {
            version: 0,
            kind: 0,
            status: 0,
            caller_pid: 0,
            sequence: 0,
            timestamp: 0,
            target: [0; MAX_TARGET_CHARS],
            reason: [0; MAX_EVENT_REASON_CHARS],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventReadResponse {
    version: u32,
    count: u32,
    dropped: u64,
    events: [DriverEventRecord; EVENT_MAX_BATCH],
}

impl Default for EventReadResponse {
    fn default() -> Self {
        Self {
            version: 0,
            count: 0,
            dropped: 0,
            events: [DriverEventRecord::default(); EVENT_MAX_BATCH],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilitiesQuery {
    version: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilitiesResponse {
    version: u32,
    protocol_version: u32,
    policy_version: u32,
    protection_protocol_version: u32,
    event_version: u32,
    max_target_chars: u32,
    max_payload_bytes: u32,
    max_event_batch: u32,
    capability_flags: u64,
}

static NEXT_REQUEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[cfg(windows)]
struct DriverSession {
    handle: isize,
}

#[cfg(windows)]
impl Drop for DriverSession {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(
                self.handle as windows_sys::Win32::Foundation::HANDLE,
            );
        }
    }
}

#[cfg(not(windows))]
struct DriverSession;

/// Driver bridge with a lazily opened, shared device session. Keeping one
/// handle for a review worker avoids CreateFileW/CloseHandle on every HIPS
/// event while the mutex serializes request/response pairs on that handle.
#[derive(Clone)]
pub struct DriverBridge {
    session: Arc<Mutex<Option<DriverSession>>>,
}

impl Default for DriverBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl DriverBridge {
    pub fn new() -> Self {
        Self {
            session: Arc::new(Mutex::new(None)),
        }
    }

    pub fn submit_behavior(
        &self,
        target: &str,
        payload: &[u8],
    ) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit(IOCTL_BEHAVIOR_ANALYZE, target, payload)
    }

    /// Ask the kernel policy layer for the authoritative verdict for a file
    /// before reusing a user-mode scan result. This is a read-only policy
    /// check; it does not add or remove a rule.
    pub fn scan_file(&self, file_path: &str) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit(IOCTL_SCAN_FILE, file_path, &[])
    }

    /// Query the optional kernel driver for a read-only ABI/capability
    /// description. New drivers answer this directly; old drivers return an
    /// I/O/invalid-device error and the caller should continue in degraded
    /// fail-open mode instead of blocking user-mode scans.
    pub fn probe_capabilities(&self) -> Result<DriverCapabilities, DriverBridgeError> {
        #[cfg(windows)]
        {
            query_capabilities_windows(&self.session)
        }
        #[cfg(not(windows))]
        {
            Err(DriverBridgeError::Unsupported)
        }
    }

    pub fn submit(
        &self,
        operation: u32,
        target: &str,
        payload: &[u8],
    ) -> Result<DriverVerdict, DriverBridgeError> {
        #[cfg(windows)]
        {
            submit_windows(&self.session, operation, target, payload)
        }
        #[cfg(not(windows))]
        {
            let _ = (operation, target, payload);
            Err(DriverBridgeError::Unsupported)
        }
    }

    pub fn block_process(&self, image_path: &str) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit_policy(IOCTL_POLICY_UPDATE, POLICY_KIND_PROCESS, image_path, 0, 0)
    }

    pub fn clear_process(&self, image_path: &str) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit_policy(IOCTL_POLICY_CLEAR, POLICY_KIND_PROCESS, image_path, 0, 0)
    }

    pub fn block_file(&self, file_path: &str) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit_policy(IOCTL_POLICY_UPDATE, POLICY_KIND_FILE, file_path, 0, 0)
    }

    /// Mirror the signed/validated vulnerable-driver basename set into the
    /// kernel's bounded file-policy table. This complements the driver's
    /// built-in list and lets an authenticated threat-intelligence update take
    /// effect without changing kernel code. A failed submission is returned so
    /// callers do not report the update as active when the driver is absent or
    /// incompatible.
    pub fn install_vulnerable_driver_policies(&self) -> Result<usize, DriverBridgeError> {
        let names = vulnerable_driver_names();
        let mut installed = 0usize;
        for name in names {
            self.block_file(&name)?;
            installed += 1;
        }
        Ok(installed)
    }

    pub fn clear_file(&self, file_path: &str) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit_policy(IOCTL_POLICY_CLEAR, POLICY_KIND_FILE, file_path, 0, 0)
    }

    pub fn block_network(
        &self,
        address: Ipv4Addr,
        port: Option<u16>,
    ) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit_policy(
            IOCTL_POLICY_UPDATE,
            POLICY_KIND_NETWORK,
            "",
            // WFP exposes FWPS_UINT32 IPv4 fields in host order, and the
            // policy table stores that value unchanged.
            u32::from_ne_bytes(address.octets()),
            port.unwrap_or(0),
        )
    }

    pub fn clear_network(
        &self,
        address: Ipv4Addr,
        port: Option<u16>,
    ) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit_policy(
            IOCTL_POLICY_CLEAR,
            POLICY_KIND_NETWORK,
            "",
            // Keep clear and update in the same host-order representation.
            u32::from_ne_bytes(address.octets()),
            port.unwrap_or(0),
        )
    }

    pub fn block_registry(&self, key_path: &str) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit_policy(IOCTL_POLICY_UPDATE, POLICY_KIND_REGISTRY, key_path, 0, 0)
    }

    pub fn clear_registry(&self, key_path: &str) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit_policy(IOCTL_POLICY_CLEAR, POLICY_KIND_REGISTRY, key_path, 0, 0)
    }

    pub fn block_raw_disk(&self, device_path: &str) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit_policy(IOCTL_POLICY_UPDATE, POLICY_KIND_RAW_DISK, device_path, 0, 0)
    }

    pub fn clear_raw_disk(&self, device_path: &str) -> Result<DriverVerdict, DriverBridgeError> {
        self.submit_policy(IOCTL_POLICY_CLEAR, POLICY_KIND_RAW_DISK, device_path, 0, 0)
    }

    pub fn set_protection_modes(
        &self,
        r3_enabled: bool,
        driver_enabled: bool,
    ) -> Result<DriverVerdict, DriverBridgeError> {
        let command = ProtectionCommand {
            version: PROTECTION_PROTOCOL_VERSION,
            r3_enabled: u32::from(r3_enabled),
            driver_enabled: u32::from(driver_enabled),
            reserved: 0,
        };
        let payload = unsafe {
            std::slice::from_raw_parts(
                (&command as *const ProtectionCommand).cast::<u8>(),
                std::mem::size_of::<ProtectionCommand>(),
            )
        };
        self.submit(IOCTL_PROTECTION_UPDATE, "", payload)
    }

    /// Drain bounded kernel enforcement events into the user-mode audit/log
    /// pipeline. Reading is destructive from the ring, so callers should poll
    /// periodically and persist the returned records immediately.
    pub fn read_events(&self) -> Result<DriverEventBatch, DriverBridgeError> {
        #[cfg(windows)]
        {
            read_events_windows(&self.session)
        }
        #[cfg(not(windows))]
        {
            Err(DriverBridgeError::Unsupported)
        }
    }

    fn submit_policy(
        &self,
        operation: u32,
        kind: u32,
        target: &str,
        ipv4_address: u32,
        port: u16,
    ) -> Result<DriverVerdict, DriverBridgeError> {
        let command = PolicyCommand {
            version: POLICY_VERSION,
            kind,
            action: POLICY_ACTION_BLOCK,
            ipv4_address,
            port,
            reserved: 0,
        };
        let payload = unsafe {
            std::slice::from_raw_parts(
                (&command as *const PolicyCommand).cast::<u8>(),
                std::mem::size_of::<PolicyCommand>(),
            )
        };
        self.submit(operation, target, payload)
    }
}

#[cfg(windows)]
fn submit_windows(
    session: &Arc<Mutex<Option<DriverSession>>>,
    operation: u32,
    target: &str,
    payload: &[u8],
) -> Result<DriverVerdict, DriverBridgeError> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let mut session_guard = session.lock().map_err(|_| {
        DriverBridgeError::Io(std::io::Error::other("driver session lock poisoned"))
    })?;
    if session_guard.is_none() {
        let endpoint: Vec<u16> = r"\\.\EverbloomSecurity"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                endpoint.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                0 as _,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        *session_guard = Some(DriverSession {
            handle: handle as isize,
        });
    }
    let handle = session_guard
        .as_ref()
        .expect("driver session was initialized")
        .handle as _;

    let mut request = DriverRequest {
        version: PROTOCOL_VERSION,
        operation,
        request_id: NEXT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        caller_pid: unsafe { GetCurrentProcessId() },
        payload_length: payload.len().min(MAX_PAYLOAD) as u32,
        target: [0; MAX_TARGET_CHARS],
        payload: [0; MAX_PAYLOAD],
    };
    let target_utf16: Vec<u16> = target.encode_utf16().take(MAX_TARGET_CHARS - 1).collect();
    request.target[..target_utf16.len()].copy_from_slice(&target_utf16);
    request.payload[..request.payload_length as usize]
        .copy_from_slice(&payload[..request.payload_length as usize]);

    let mut response = DriverResponse::default();
    let mut returned = 0u32;
    let result = unsafe {
        DeviceIoControl(
            handle,
            operation,
            &request as *const DriverRequest as *const _,
            std::mem::size_of::<DriverRequest>() as u32,
            &mut response as *mut DriverResponse as *mut _,
            std::mem::size_of::<DriverResponse>() as u32,
            &mut returned,
            null_mut(),
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        // Drop the cached handle when the device disappears so the next
        // eligible batch can reconnect instead of reusing a stale handle.
        let stale_handle = [
            windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE as i32,
            windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND as i32,
            windows_sys::Win32::Foundation::ERROR_DEVICE_NOT_CONNECTED as i32,
        ]
        .contains(&error.raw_os_error().unwrap_or_default());
        if stale_handle {
            session_guard.take();
        }
        return Err(error.into());
    }
    if returned < std::mem::size_of::<DriverResponse>() as u32
        || response.version != PROTOCOL_VERSION
        || response.request_id != request.request_id
    {
        return Err(DriverBridgeError::InvalidResponse);
    }

    Ok(DriverVerdict {
        request_id: response.request_id,
        blocked: response.verdict != 0,
        threat: response.threat,
        action: response.action,
    })
}

#[cfg(windows)]
fn query_capabilities_windows(
    session: &Arc<Mutex<Option<DriverSession>>>,
) -> Result<DriverCapabilities, DriverBridgeError> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let mut session_guard = session.lock().map_err(|_| {
        DriverBridgeError::Io(std::io::Error::other("driver session lock poisoned"))
    })?;
    if session_guard.is_none() {
        let endpoint: Vec<u16> = r"\\.\EverbloomSecurity"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                endpoint.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                0 as _,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        *session_guard = Some(DriverSession {
            handle: handle as isize,
        });
    }
    let handle = session_guard
        .as_ref()
        .expect("driver session was initialized")
        .handle as _;

    let query = CapabilitiesQuery {
        version: CAPABILITIES_VERSION,
        reserved: 0,
    };
    let mut response = CapabilitiesResponse::default();
    let mut returned = 0u32;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_CAPABILITIES_QUERY,
            &query as *const CapabilitiesQuery as *const _,
            std::mem::size_of::<CapabilitiesQuery>() as u32,
            &mut response as *mut CapabilitiesResponse as *mut _,
            std::mem::size_of::<CapabilitiesResponse>() as u32,
            &mut returned,
            null_mut(),
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        let stale_handle = [
            windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE as i32,
            windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND as i32,
            windows_sys::Win32::Foundation::ERROR_DEVICE_NOT_CONNECTED as i32,
        ]
        .contains(&error.raw_os_error().unwrap_or_default());
        if stale_handle {
            session_guard.take();
        }
        return Err(error.into());
    }
    if returned < std::mem::size_of::<CapabilitiesResponse>() as u32
        || response.version != CAPABILITIES_VERSION
    {
        return Err(DriverBridgeError::InvalidResponse);
    }

    Ok(DriverCapabilities {
        protocol_version: response.protocol_version,
        policy_version: response.policy_version,
        protection_protocol_version: response.protection_protocol_version,
        event_version: response.event_version,
        max_target_chars: response.max_target_chars,
        max_payload_bytes: response.max_payload_bytes,
        max_event_batch: response.max_event_batch,
        capability_flags: response.capability_flags,
    })
}

#[cfg(windows)]
fn read_events_windows(
    session: &Arc<Mutex<Option<DriverSession>>>,
) -> Result<DriverEventBatch, DriverBridgeError> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let mut session_guard = session.lock().map_err(|_| {
        DriverBridgeError::Io(std::io::Error::other("driver session lock poisoned"))
    })?;
    if session_guard.is_none() {
        let endpoint: Vec<u16> = r"\\.\EverbloomSecurity"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                endpoint.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                0 as _,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        *session_guard = Some(DriverSession {
            handle: handle as isize,
        });
    }
    let handle = session_guard
        .as_ref()
        .expect("driver session was initialized")
        .handle as _;
    let query = EventQuery {
        version: DRIVER_EVENT_VERSION,
        max_events: EVENT_MAX_BATCH as u32,
        reserved: 0,
    };
    let mut response = EventReadResponse::default();
    let mut returned = 0u32;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_EVENT_READ,
            &query as *const EventQuery as *const _,
            std::mem::size_of::<EventQuery>() as u32,
            &mut response as *mut EventReadResponse as *mut _,
            std::mem::size_of::<EventReadResponse>() as u32,
            &mut returned,
            null_mut(),
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if response.version != DRIVER_EVENT_VERSION
        || response.count as usize > EVENT_MAX_BATCH
        || returned < std::mem::size_of::<EventReadResponse>() as u32
    {
        return Err(DriverBridgeError::InvalidResponse);
    }
    if response.dropped > 0 {
        // The kernel ring intentionally drops the oldest record under load.
        // Preserve that fact in the durable user-mode log instead of silently
        // presenting an incomplete event stream to HIPS/GUI consumers.
        log::error!(
            "kernel event ring overflow: {} enforcement event(s) were dropped",
            response.dropped
        );
    }
    let to_string = |value: &[u16]| {
        let length = value
            .iter()
            .position(|item| *item == 0)
            .unwrap_or(value.len());
        String::from_utf16_lossy(&value[..length])
    };
    let events = response.events[..response.count as usize]
        .iter()
        .filter(|event| event.version == DRIVER_EVENT_VERSION)
        .map(|event| DriverEvent {
            kind: event.kind,
            status: event.status,
            caller_pid: event.caller_pid,
            sequence: event.sequence,
            timestamp: event.timestamp,
            target: to_string(&event.target),
            reason: to_string(&event.reason),
        })
        .collect();
    Ok(DriverEventBatch {
        events,
        dropped: response.dropped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_constants_match_driver_contract() {
        assert_eq!(IOCTL_AMSI_SCAN_BUFFER, 0x8000_2010);
        assert_eq!(IOCTL_SCAN_FILE, 0x8000_2020);
        assert_eq!(IOCTL_NET_INSPECT, 0x8000_3010);
        assert_eq!(IOCTL_BEHAVIOR_ANALYZE, 0x8000_4010);
        assert_eq!(IOCTL_POLICY_UPDATE, 0x8000_5010);
        assert_eq!(IOCTL_POLICY_CLEAR, 0x8000_5020);
        assert_eq!(IOCTL_PROTECTION_UPDATE, 0x8000_5030);
        assert_eq!(IOCTL_EVENT_READ, 0x8000_6010);
        assert_eq!(IOCTL_CAPABILITIES_QUERY, 0x8000_6020);
        assert_eq!(std::mem::size_of::<DriverResponse>(), 24);
        assert_eq!(std::mem::size_of::<PolicyCommand>(), 20);
        assert_eq!(std::mem::size_of::<ProtectionCommand>(), 16);
        assert_eq!(std::mem::size_of::<CapabilitiesQuery>(), 8);
        assert_eq!(std::mem::size_of::<CapabilitiesResponse>(), 40);
    }

    #[test]
    fn vulnerable_driver_list_matches_only_basenames() {
        assert_eq!(
            known_vulnerable_driver_name(r"C:\Windows\System32\drivers\zam64.sys"),
            Some("zam64.sys".to_string())
        );
        assert!(known_vulnerable_driver_name("zam64.sys.backup").is_none());
        assert!(known_vulnerable_driver_name("safe-zam64.sys").is_none());
    }

    #[test]
    fn vulnerable_driver_update_merges_external_basenames() {
        let directory = tempfile::tempdir().expect("tempdir");
        let update = directory.path().join("drivers.json");
        std::fs::write(
            &update,
            r#"{"drivers":["C:/drivers/newbad.sys","zam64.sys","bad:name.sys","*.sys"]}"#,
        )
        .expect("write update");

        let count = reload_vulnerable_driver_names_from_file(&update, None).expect("reload");

        assert_eq!(count, VULNERABLE_DRIVER_NAMES.len() + 1);
        assert_eq!(
            known_vulnerable_driver_name("C:/Windows/System32/drivers/newbad.sys"),
            Some("newbad.sys".to_string())
        );
        assert!(known_vulnerable_driver_name("bad:name.sys").is_none());
    }

    #[test]
    fn missing_driver_errors_are_classified_as_expected_degradation() {
        let error = DriverBridgeError::Io(std::io::Error::from_raw_os_error(2));
        assert!(error.is_unavailable());
        assert!(error
            .unavailable_message()
            .contains("driver device is unavailable"));

        let protocol_error = DriverBridgeError::Io(std::io::Error::from_raw_os_error(87));
        assert!(!protocol_error.is_unavailable());
    }
    #[cfg(not(windows))]
    #[test]
    fn bridge_is_explicitly_unavailable_without_windows_driver() {
        let result = DriverBridge::new().submit_behavior("sample", b"test");
        assert!(matches!(result, Err(DriverBridgeError::Unsupported)));
    }
}
