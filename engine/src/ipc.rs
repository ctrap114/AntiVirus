use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use bytes::{BufMut, BytesMut};
use prost::{Enumeration, Message};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinHandle;

use crate::driver_bridge::DriverBridge;
use crate::scanner::{ScanError, ScanProgress, ScanRequest, ScanVerdict, Scanner};

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
const MAX_ACTIVE_SCANS: usize = 2;

fn should_emit_scan_response(malicious: bool, has_error: bool, verdict: ScanVerdict) -> bool {
    malicious || has_error || verdict == ScanVerdict::Suspicious
}

#[cfg(test)]
mod scan_response_tests {
    use super::{should_emit_scan_response, IpcScanResponse, ScanVerdict};
    use crate::scanner::ScanResult;
    use std::path::PathBuf;

    #[test]
    fn legacy_ipc_emits_suspicious_results_without_counting_them_as_threats() {
        let suspicious_result = ScanResult {
            path: PathBuf::from("sample.bin"),
            malicious: false,
            reason: "fusion:static:stage=correlate:heuristic=0.70:ai=0.72".to_string(),
            yara_matches: Vec::new(),
            heuristic_score: Some(0.70),
            heuristic_indicators: Vec::new(),
            ai_score: Some(0.72),
            ai_components: Vec::new(),
            ai_fallback_reason: None,
            behavior_score: None,
            sequence_matches: None,
            sandbox: None,
            process_state: None,
            rollback_record: None,
            rollback_actions: None,
            static_sandbox: None,
            error: None,
            duration_ms: 1,
        };
        let verdict = suspicious_result.verdict();
        let response = IpcScanResponse::from(suspicious_result);
        assert_eq!(verdict, ScanVerdict::Suspicious);
        assert!(should_emit_scan_response(
            response.malicious,
            !response.error.is_empty(),
            verdict,
        ));
        assert!(!response.malicious);
        assert_eq!(response.status, "suspicious");

        // The protocol summary keeps its historical meaning: only a
        // Malicious intervention contributes to threat_count. Suspicious is a
        // per-file response status, not an intervention count.
        let threat_count = [verdict, ScanVerdict::Malicious]
            .iter()
            .filter(|verdict| **verdict == ScanVerdict::Malicious)
            .count();
        assert_eq!(threat_count, 1);
    }
}

type ModelCommand = Arc<dyn Fn(String) -> Result<String, String> + Send + Sync>;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protobuf error: {0}")]
    Proto(#[from] prost::DecodeError),
    #[error("encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("scan error: {0}")]
    Scan(#[from] ScanError),
    #[error("IPC frame is too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("shutdown received")]
    Shutdown,
    #[error("config reload failed: {0}")]
    Config(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("server unavailable")]
    Unavailable,
}

/// IPC server bound to a named pipe on Windows or Unix socket on Unix.
pub struct IpcServer {
    endpoint: PathBuf,
    scanner: Arc<Scanner>,
    config_reload: Option<Arc<dyn Fn() -> Result<(), String> + Send + Sync>>,
    model_command: Option<ModelCommand>,
    hash_import_command: Option<ModelCommand>,
    scan_slots: Arc<Semaphore>,
}

impl IpcServer {
    pub fn new<P: AsRef<Path>>(
        endpoint: P,
        scanner: Arc<Scanner>,
        config_reload: Option<Arc<dyn Fn() -> Result<(), String> + Send + Sync>>,
    ) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_path_buf(),
            scanner,
            config_reload,
            model_command: None,
            hash_import_command: None,
            scan_slots: Arc::new(Semaphore::new(MAX_ACTIVE_SCANS)),
        }
    }

    pub fn with_model_command(mut self, callback: ModelCommand) -> Self {
        self.model_command = Some(callback);
        self
    }

    pub fn with_hash_import_command(mut self, callback: ModelCommand) -> Self {
        self.hash_import_command = Some(callback);
        self
    }

    /// Start the IPC server and run until shutdown or client disconnect.
    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), IpcError> {
        let server = Arc::new(self);

        #[cfg(unix)]
        {
            if server.endpoint.exists() {
                let _ = tokio::fs::remove_file(&server.endpoint).await;
            }
            let listener = tokio::net::UnixListener::bind(&server.endpoint)?;
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { return Ok(()); }
                    }
                    accept = listener.accept() => {
                        let (stream, _) = accept?;
                        let connection_server = server.clone();
                        tokio::spawn(async move {
                            let _ = connection_server.handle_connection(stream).await;
                        });
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ServerOptions;
            let mut first_pipe_instance = true;
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { return Ok(()); }
                    }
                    result = async {
                        let mut options = ServerOptions::new();
                        options
                            .first_pipe_instance(first_pipe_instance)
                            .reject_remote_clients(true);
                        let pipe =
                            options.create(server.endpoint.to_string_lossy().as_ref())?;
                        first_pipe_instance = false;
                        pipe.connect().await?;
                        Ok::<_, std::io::Error>(pipe)
                    } => {
                        let stream = result?;
                        let connection_server = server.clone();
                        tokio::spawn(async move {
                            let _ = connection_server.handle_connection(stream).await;
                        });
                    }
                }
            }
        }
    }

    async fn handle_connection<S>(&self, stream: S) -> Result<(), IpcError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut stream = stream;
        loop {
            let request = match read_message::<IpcEnvelope, _>(&mut stream).await {
                Ok(envelope) => envelope,
                Err(IpcError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(())
                }
                Err(e) => return Err(e),
            };

            if let Some(payload) = request.payload {
                match payload {
                    ipc_envelope::Payload::ScanRequest(req) => {
                        self.handle_scan_request(req, &mut stream).await?;
                    }
                    ipc_envelope::Payload::ConfigUpdate(update) => {
                        self.handle_config_update(update, &mut stream).await?;
                    }
                    ipc_envelope::Payload::Shutdown(_) => {
                        let ack = IpcEnvelope {
                            payload: Some(ipc_envelope::Payload::ShutdownAck(ShutdownAck {})),
                        };
                        send_message(&mut stream, &ack).await?;
                        return Ok(());
                    }
                    ipc_envelope::Payload::Heartbeat(_) => {
                        let response = IpcEnvelope {
                            payload: Some(ipc_envelope::Payload::Heartbeat(Heartbeat {})),
                        };
                        send_message(&mut stream, &response).await?;
                    }
                    _ => {
                        // ignore messages not expected from client
                    }
                }
            }
        }
    }

    async fn handle_scan_request<S>(
        &self,
        req: IpcScanRequest,
        stream: &mut S,
    ) -> Result<(), IpcError>
    where
        S: AsyncWrite + Unpin + Send,
    {
        log::info!(
            "legacy IPC scan request received: paths={} timeout_ms={} sandbox={} yara={} ai={} heuristic={}",
            req.paths.len(),
            req.timeout_ms,
            req.sandbox_enabled,
            req.yara_enabled,
            req.ai_enabled,
            req.heuristic_enabled
        );
        let _scan_permit = match self.scan_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let summary = IpcScanProgress {
                    path: String::new(),
                    stage: IpcStage::Error as i32,
                    completed: true,
                    error: "engine scan queue is full; retry later".to_string(),
                    total_files: 0,
                    processed_files: 0,
                    threat_count: 0,
                    error_count: 1,
                    batch_completed: true,
                    cancelled: false,
                };
                let envelope = IpcEnvelope {
                    payload: Some(ipc_envelope::Payload::ScanProgress(summary)),
                };
                send_message(stream, &envelope).await?;
                return Ok(());
            }
        };
        let (progress_tx, mut progress_rx) = mpsc::channel(2048);
        let cancelled = Arc::new(AtomicBool::new(false));
        // The legacy IPC contract has no ClamAV field. Deployments opt in
        // through EVERBLOOM_CLAMAV so the second opinion runs for all scans.
        let clamav_enabled =
            crate::ndjson::env_var_flag("EVERBLOOM_CLAMAV", false) && self.scanner.clamav.is_some();
        let scan_req = ScanRequest {
            paths: req.paths.iter().map(PathBuf::from).collect(),
            timeout_ms: req.timeout_ms as u64,
            sandbox_enabled: req.sandbox_enabled,
            yara_enabled: req.yara_enabled,
            ai_enabled: req.ai_enabled,
            heuristic_enabled: req.heuristic_enabled,
            clamav_enabled,
            ai_threshold: req.ai_threshold,
            maximum_file_size: req.maximum_file_size,
            cloud_enabled: req.cloud_enabled,
            cancelled: cancelled.clone(),
            progress_tx: Some(progress_tx),
        };

        let scanner = self.scanner.clone();
        let accepted = IpcScanProgress {
            path: String::new(),
            stage: IpcStage::Started as i32,
            completed: false,
            error: String::new(),
            total_files: 0,
            processed_files: 0,
            threat_count: 0,
            error_count: 0,
            batch_completed: false,
            cancelled: false,
        };
        let envelope = IpcEnvelope {
            payload: Some(ipc_envelope::Payload::ScanProgress(accepted)),
        };
        send_message(stream, &envelope).await?;
        let mut scan_task: JoinHandle<Result<Vec<crate::scanner::ScanResult>, ScanError>> =
            tokio::spawn(async move { scanner.scan_request(scan_req).await });
        let mut total_files: u64 = 0;
        let mut processed_files: u64 = 0;
        let mut observed_error_count: u64 = 0;

        loop {
            tokio::select! {
                progress = progress_rx.recv() => {
                    if let Some(progress) = progress {
                        match &progress {
                            ScanProgress::Enumerating(_, discovered_files) => {
                                total_files = total_files.max(*discovered_files as u64);
                            }
                            ScanProgress::BatchStarted(discovered_files) => {
                                total_files = *discovered_files as u64;
                                processed_files = 0;
                            }
                            ScanProgress::Completed(_) => {
                                processed_files = processed_files.saturating_add(1);
                                if total_files > 0 {
                                    processed_files = processed_files.min(total_files);
                                } else {
                                    total_files = processed_files;
                                }
                            }
                            ScanProgress::FileError(_, _) => {
                                observed_error_count = observed_error_count.saturating_add(1);
                            }
                            ScanProgress::BatchCompleted {
                                total_files: batch_total,
                                processed_files: batch_processed,
                                error_count,
                                ..
                            } => {
                                total_files = *batch_total as u64;
                                processed_files = *batch_processed as u64;
                                observed_error_count = *error_count as u64;
                            }
                            ScanProgress::Started(_) | ScanProgress::LayerCompleted(_, _) => {}
                        }
                        let mut update = IpcScanProgress::from(progress);
                        if !update.batch_completed {
                            update.total_files = total_files;
                            update.processed_files = processed_files;
                            update.error_count = observed_error_count;
                        }
                        let envelope = IpcEnvelope { payload: Some(ipc_envelope::Payload::ScanProgress(update)) };
                        if let Err(error) = send_message(stream, &envelope).await {
                            cancelled.store(true, Ordering::Relaxed);
                            scan_task.abort();
                            return Err(error);
                        }
                    } else {
                        break;
                    }
                }
                result = &mut scan_task => {
                    let scan_results = result.map_err(|e| IpcError::Internal(format!("scan task failed: {}", e)))??;
                    let total_files = scan_results.len();
                    // Keep threat_count as intervention-level Malicious only;
                    // Suspicious items are sent as ScanResponse with status
                    // "suspicious" but do not inflate the legacy threat count.
                    let threat_count = scan_results.iter().filter(|item| item.malicious).count();
                    let error_count = scan_results
                        .iter()
                        .filter(|item| item.error.is_some() && item.reason != "cancelled")
                        .count();
                    for item in scan_results
                        .into_iter()
                        .filter(|item| {
                            should_emit_scan_response(
                                item.malicious,
                                item.error.is_some(),
                                item.verdict(),
                            )
                        })
                    {
                        let response = IpcScanResponse::from(item);
                        let envelope = IpcEnvelope { payload: Some(ipc_envelope::Payload::ScanResponse(response)) };
                        send_message(stream, &envelope).await?;
                    }
                    let summary = IpcScanProgress {
                        path: String::new(),
                        stage: IpcStage::Completed as i32,
                        completed: true,
                        error: String::new(),
                        total_files: total_files as u64,
                        processed_files: total_files as u64,
                        threat_count: threat_count as u64,
                        error_count: error_count as u64,
                        batch_completed: true,
                        cancelled: cancelled.load(Ordering::Relaxed),
                    };
                    let envelope = IpcEnvelope {
                        payload: Some(ipc_envelope::Payload::ScanProgress(summary)),
                    };
                    send_message(stream, &envelope).await?;
                    log::info!(
                        "legacy IPC scan request completed: total={} threats={} errors={}",
                        total_files,
                        threat_count,
                        error_count
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_config_update<S>(
        &self,
        update: IpcConfigUpdate,
        stream: &mut S,
    ) -> Result<(), IpcError>
    where
        S: AsyncWrite + Unpin + Send,
    {
        let (success, message) = if update.command != "reload_hash_database"
            && !update.command.starts_with("set_protection_modes:")
            && !update.command.starts_with("block_file:")
            && !update.command.starts_with("allow_file:")
            && !update.command.starts_with("import_model:")
            && !update.command.starts_with("import_hash_database:")
            && !update.command.starts_with("set_ai_strategy:")
        {
            (
                false,
                format!("unsupported config command: {}", update.command),
            )
        } else if let Some((r3_enabled, driver_enabled)) =
            parse_protection_mode_command(&update.command)
        {
            crate::protection_state::set_r3_enabled(r3_enabled);
            if !driver_enabled {
                crate::protection_state::set_driver_enabled(false);
                self.scanner.invalidate_cache_context();
                (
                    true,
                    format!("R3 mode updated: {}; driver layer is disabled", r3_enabled,),
                )
            } else {
                match DriverBridge::new().set_protection_modes(r3_enabled, driver_enabled) {
                    Ok(_) => {
                        crate::protection_state::set_driver_enabled(driver_enabled);
                        self.scanner.invalidate_cache_context();
                        (
                            true,
                            format!(
                                "protection modes updated: r3={} driver={}",
                                r3_enabled, driver_enabled
                            ),
                        )
                    }
                    Err(error) => {
                        crate::protection_state::set_driver_enabled(false);
                        if error.is_unavailable() {
                            (
                                true,
                                format!(
                                    "R3 protection remains active; driver protection unavailable: {}",
                                    error.unavailable_message()
                                ),
                            )
                        } else {
                            (false, format!("driver protection update failed: {error}"))
                        }
                    }
                }
            }
        } else if let Some(path) = parse_block_file_command(&update.command) {
            match DriverBridge::new().block_file(path) {
                Ok(verdict) => {
                    self.scanner.invalidate_cache_context();
                    (
                        true,
                        format!(
                            "file block policy submitted: {} request={}",
                            path, verdict.request_id
                        ),
                    )
                }
                Err(error) if error.is_unavailable() => {
                    crate::protection_state::set_driver_enabled(false);
                    (
                        true,
                        format!(
                            "R3 protection remains active; driver file policy unavailable: {}",
                            error.unavailable_message()
                        ),
                    )
                }
                Err(error) => (false, format!("file block policy unavailable: {error}")),
            }
        } else if let Some(path) = parse_allow_file_command(&update.command) {
            match DriverBridge::new().clear_file(path) {
                Ok(verdict) => {
                    self.scanner.invalidate_cache_context();
                    (
                        true,
                        format!(
                            "file allow policy submitted: {} request={}",
                            path, verdict.request_id
                        ),
                    )
                }
                Err(error) if error.is_unavailable() => {
                    crate::protection_state::set_driver_enabled(false);
                    (
                        true,
                        format!(
                            "R3 protection remains active; driver file policy unavailable: {}",
                            error.unavailable_message()
                        ),
                    )
                }
                Err(error) => (false, format!("file allow policy unavailable: {error}")),
            }
        } else if update.command.starts_with("import_model:")
            || update.command.starts_with("set_ai_strategy:")
        {
            match &self.model_command {
                Some(importer) => match importer(update.command.clone()) {
                    Ok(message) => (true, message),
                    Err(message) => (false, message),
                },
                None => (false, "model import is not configured".to_string()),
            }
        } else if update.command.starts_with("import_hash_database:") {
            match &self.hash_import_command {
                Some(importer) => match importer(update.command.clone()) {
                    Ok(message) => (true, message),
                    Err(message) => (false, message),
                },
                None => (false, "hash database import is not configured".to_string()),
            }
        } else {
            match &self.config_reload {
                Some(reloader) => match reloader() {
                    Ok(()) => (true, "ok".to_string()),
                    Err(message) => (false, message),
                },
                None => (false, "no reload callback configured".to_string()),
            }
        };

        let ack = IpcConfigAck { success, message };
        let envelope = IpcEnvelope {
            payload: Some(ipc_envelope::Payload::ConfigAck(ack)),
        };
        send_message(stream, &envelope).await?;
        Ok(())
    }
}

fn parse_protection_mode_command(command: &str) -> Option<(bool, bool)> {
    let values = command.strip_prefix("set_protection_modes:")?;
    let mut r3 = None;
    let mut driver = None;
    for item in values.split(';') {
        let (name, value) = item.split_once('=')?;
        let parsed = match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "on" => true,
            "0" | "false" | "off" => false,
            _ => return None,
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "r3" => r3 = Some(parsed),
            "driver" => driver = Some(parsed),
            _ => return None,
        }
    }
    Some((r3?, driver?))
}

fn parse_block_file_command(command: &str) -> Option<&str> {
    let path = command.strip_prefix("block_file:")?.trim();
    (!path.is_empty()).then_some(path)
}

fn parse_allow_file_command(command: &str) -> Option<&str> {
    let path = command.strip_prefix("allow_file:")?.trim();
    (!path.is_empty()).then_some(path)
}

async fn read_message<T: Message + Default, R>(reader: &mut R) -> Result<T, IpcError>
where
    R: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(IpcError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let msg = T::decode(&*buf)?;
    Ok(msg)
}

async fn send_message<W>(writer: &mut W, message: &IpcEnvelope) -> Result<(), IpcError>
where
    W: AsyncWrite + Unpin + Send,
{
    let message_len = message.encoded_len();
    if message_len > MAX_FRAME_SIZE {
        return Err(IpcError::FrameTooLarge(message_len));
    }
    let mut buf = BytesMut::with_capacity(message_len + 4);
    buf.put_u32(message_len as u32);
    message.encode(&mut buf)?;
    writer.write_all(&buf).await?;
    Ok(())
}

#[derive(Clone, PartialEq, Message)]
pub struct IpcEnvelope {
    #[prost(oneof = "ipc_envelope::Payload", tags = "1,2,3,4,5,6,7,8")]
    pub payload: Option<ipc_envelope::Payload>,
}

pub mod ipc_envelope {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "1")]
        ScanRequest(super::IpcScanRequest),
        #[prost(message, tag = "2")]
        ScanProgress(super::IpcScanProgress),
        #[prost(message, tag = "3")]
        ScanResponse(super::IpcScanResponse),
        #[prost(message, tag = "4")]
        ConfigUpdate(super::IpcConfigUpdate),
        #[prost(message, tag = "5")]
        ConfigAck(super::IpcConfigAck),
        #[prost(message, tag = "6")]
        Shutdown(super::Shutdown),
        #[prost(message, tag = "7")]
        ShutdownAck(super::ShutdownAck),
        #[prost(message, tag = "8")]
        Heartbeat(super::Heartbeat),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct IpcScanRequest {
    #[prost(string, repeated, tag = "1")]
    pub paths: Vec<String>,
    #[prost(uint32, tag = "2")]
    pub timeout_ms: u32,
    #[prost(bool, tag = "3")]
    pub sandbox_enabled: bool,
    #[prost(bool, tag = "4")]
    pub yara_enabled: bool,
    #[prost(bool, tag = "5")]
    pub ai_enabled: bool,
    #[prost(bool, tag = "6")]
    pub heuristic_enabled: bool,
    #[prost(float, tag = "7")]
    pub ai_threshold: f32,
    #[prost(uint64, tag = "8")]
    pub maximum_file_size: u64,
    #[prost(bool, tag = "9")]
    pub cloud_enabled: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct IpcScanProgress {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(enumeration = "IpcStage", tag = "2")]
    pub stage: i32,
    #[prost(bool, tag = "3")]
    pub completed: bool,
    #[prost(string, tag = "4")]
    pub error: String,
    #[prost(uint64, tag = "5")]
    pub total_files: u64,
    #[prost(uint64, tag = "6")]
    pub processed_files: u64,
    #[prost(uint64, tag = "7")]
    pub threat_count: u64,
    #[prost(uint64, tag = "8")]
    pub error_count: u64,
    #[prost(bool, tag = "9")]
    pub batch_completed: bool,
    #[prost(bool, tag = "10")]
    pub cancelled: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct IpcScanResponse {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(bool, tag = "2")]
    pub malicious: bool,
    #[prost(string, tag = "3")]
    pub reason: String,
    #[prost(string, repeated, tag = "4")]
    pub yara_matches: Vec<String>,
    #[prost(float, tag = "5")]
    pub heuristic_score: f32,
    #[prost(float, tag = "6")]
    pub ai_score: f32,
    #[prost(bool, tag = "7")]
    pub timed_out: bool,
    #[prost(string, repeated, tag = "8")]
    pub files_changed: Vec<String>,
    #[prost(string, repeated, tag = "9")]
    pub registry_writes: Vec<String>,
    #[prost(string, repeated, tag = "10")]
    pub network_connections: Vec<String>,
    #[prost(string, repeated, tag = "11")]
    pub processes: Vec<String>,
    #[prost(uint64, tag = "12")]
    pub duration_ms: u64,
    #[prost(string, tag = "13")]
    pub error: String,
    #[prost(string, tag = "14")]
    pub status: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct IpcConfigUpdate {
    #[prost(string, tag = "1")]
    pub command: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct IpcConfigAck {
    #[prost(bool, tag = "1")]
    pub success: bool,
    #[prost(string, tag = "2")]
    pub message: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Shutdown {}

#[derive(Clone, PartialEq, Message)]
pub struct ShutdownAck {}

#[derive(Clone, PartialEq, Message)]
pub struct Heartbeat {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
pub enum IpcStage {
    Unknown = 0,
    Started = 1,
    Hash = 2,
    Yara = 3,
    Heuristic = 4,
    Ai = 5,
    Sandbox = 6,
    Completed = 7,
    Error = 8,
}

pub type IpcMessage = IpcEnvelope;

impl From<ScanProgress> for IpcScanProgress {
    fn from(progress: ScanProgress) -> Self {
        match progress {
            ScanProgress::Enumerating(path, discovered_files) => IpcScanProgress {
                path: path.to_string_lossy().into_owned(),
                stage: IpcStage::Unknown as i32,
                completed: false,
                total_files: discovered_files as u64,
                processed_files: 0,
                ..Default::default()
            },
            ScanProgress::BatchStarted(total_files) => IpcScanProgress {
                path: String::new(),
                stage: IpcStage::Started as i32,
                completed: false,
                total_files: total_files as u64,
                ..Default::default()
            },
            ScanProgress::Started(path) => IpcScanProgress {
                path: path.to_string_lossy().into_owned(),
                stage: IpcStage::Started as i32,
                completed: false,
                ..Default::default()
            },
            ScanProgress::LayerCompleted(path, layer) => {
                let stage = match layer.as_str() {
                    "hash" => IpcStage::Hash,
                    "yara" => IpcStage::Yara,
                    "heuristic" => IpcStage::Heuristic,
                    "ai" => IpcStage::Ai,
                    "sandbox" => IpcStage::Sandbox,
                    _ => IpcStage::Unknown,
                };
                IpcScanProgress {
                    path: path.to_string_lossy().into_owned(),
                    stage: stage as i32,
                    completed: false,
                    ..Default::default()
                }
            }
            ScanProgress::FileError(path, error) => IpcScanProgress {
                path: path.to_string_lossy().into_owned(),
                stage: IpcStage::Error as i32,
                completed: false,
                error,
                ..Default::default()
            },
            ScanProgress::Completed(path) => IpcScanProgress {
                path: path.to_string_lossy().into_owned(),
                stage: IpcStage::Completed as i32,
                completed: true,
                ..Default::default()
            },
            ScanProgress::BatchCompleted {
                total_files,
                processed_files,
                threat_count,
                error_count,
                cancelled,
            } => IpcScanProgress {
                path: String::new(),
                stage: IpcStage::Completed as i32,
                completed: true,
                total_files: total_files as u64,
                processed_files: processed_files as u64,
                threat_count: threat_count as u64,
                error_count: error_count as u64,
                batch_completed: true,
                cancelled,
                ..Default::default()
            },
        }
    }
}

impl From<crate::scanner::ScanResult> for IpcScanResponse {
    fn from(result: crate::scanner::ScanResult) -> Self {
        let status = result.verdict().as_str().to_string();
        IpcScanResponse {
            path: result.path.to_string_lossy().into_owned(),
            malicious: result.malicious,
            reason: result.reason,
            yara_matches: result
                .yara_matches
                .into_iter()
                .map(|m| m.rule_name)
                .collect(),
            heuristic_score: result.heuristic_score.unwrap_or_default(),
            ai_score: result.ai_score.unwrap_or_default(),
            timed_out: result.sandbox.as_ref().is_some_and(|r| r.timed_out),
            files_changed: result.sandbox.as_ref().map_or(Vec::new(), |r| {
                r.files_changed
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect()
            }),
            registry_writes: result
                .sandbox
                .as_ref()
                .map_or(Vec::new(), |r| r.registry_writes.clone()),
            network_connections: result
                .sandbox
                .as_ref()
                .map_or(Vec::new(), |r| r.network_connections.clone()),
            processes: result
                .sandbox
                .as_ref()
                .map_or(Vec::new(), |r| r.processes.clone()),
            duration_ms: result.duration_ms as u64,
            error: result.error.unwrap_or_default(),
            status,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    use tokio::sync::watch;
    use tokio::time::sleep;

    #[cfg(unix)]
    #[tokio::test]
    async fn test_ipc_scan_request_and_shutdown() {
        let temp_dir = tempdir().expect("create tempdir");
        let socket_path = temp_dir.path().join("everbloom-ipc.sock");

        let scanner = Arc::new(Scanner::new());
        let config_reload = Arc::new(|| Ok(()));
        let server = IpcServer::new(socket_path.clone(), scanner, Some(config_reload));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_handle = tokio::spawn(async move {
            server.run(shutdown_rx).await.expect("server run");
        });

        sleep(Duration::from_millis(50)).await;
        let mut stream = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("connect");
        let mut read_stream = stream.try_clone().expect("clone stream");

        let request = IpcEnvelope {
            payload: Some(ipc_envelope::Payload::ScanRequest(IpcScanRequest {
                paths: vec!["/tmp/does_not_exist.bin".to_string()],
                timeout_ms: 500,
                sandbox_enabled: false,
                yara_enabled: false,
                ai_enabled: false,
                heuristic_enabled: true,
                ai_threshold: 0.9,
                maximum_file_size: 1024 * 1024 * 1024,
                cloud_enabled: false,
            })),
        };
        send_message(&mut stream, &request)
            .await
            .expect("send request");

        let shutdown_envelope = IpcEnvelope {
            payload: Some(ipc_envelope::Payload::Shutdown(Shutdown {})),
        };

        let read_task = tokio::spawn(async move {
            let mut progress_messages = 0;
            let mut shutdown_received = false;
            loop {
                match read_message::<IpcEnvelope, _>(&mut read_stream).await {
                    Ok(envelope) => {
                        if let Some(payload) = envelope.payload {
                            match payload {
                                ipc_envelope::Payload::ScanProgress(_) => progress_messages += 1,
                                ipc_envelope::Payload::ScanResponse(_) => {}
                                ipc_envelope::Payload::ShutdownAck(_) => {
                                    shutdown_received = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            (progress_messages, shutdown_received)
        });

        sleep(Duration::from_millis(50)).await;
        send_message(&mut stream, &shutdown_envelope)
            .await
            .expect("send shutdown");
        let (progress_messages, shutdown_received) = read_task.await.expect("read task");
        assert!(shutdown_received);
        assert!(progress_messages > 0);

        shutdown_tx.send(true).unwrap();
        server_handle.await.expect("join server");
    }
}
