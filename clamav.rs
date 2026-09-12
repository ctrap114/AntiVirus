//! Client for a local, resident ClamAV clamd service.
//!
//! HeliosAV deliberately talks to clamd over its local TCP protocol instead
//! of linking libclamav into the engine. This keeps the Rust engine process
//! isolated from ClamAV native ABI and lets freshclam own the signature
//! database lifecycle. The endpoint is restricted to loopback by default;
//! deployments must not expose an unauthenticated clamd TCP port to a network.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use log::debug;

const DEFAULT_ENDPOINT: &str = "127.0.0.1:3310";
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_millis(750);
const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_MAX_STREAM_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const DEFAULT_MAX_INFLIGHT: usize = 2;
const DEFAULT_RETRY_COOLDOWN: Duration = Duration::from_secs(300);
const STREAM_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClamAvVerdict {
    Clean,
    Found { signature: String },
    Unavailable { message: String },
}

impl ClamAvVerdict {
    #[cfg(test)]
    fn message_contains(&self, needle: &str) -> bool {
        match self {
            Self::Unavailable { message } => message.contains(needle),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClamAvStatus {
    pub available: bool,
    pub version: Option<String>,
    pub database_version: Option<String>,
    pub message: String,
}

#[derive(Debug)]
struct ConcurrencyGate {
    available: Mutex<usize>,
    changed: Condvar,
}

impl ConcurrencyGate {
    fn new(capacity: usize) -> Self {
        Self {
            available: Mutex::new(capacity.max(1)),
            changed: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> GatePermit {
        let mut available = self.available.lock().expect("clamav gate poisoned");
        while *available == 0 {
            available = self
                .changed
                .wait(available)
                .expect("clamav gate poisoned while waiting");
        }
        *available -= 1;
        GatePermit {
            gate: Arc::clone(self),
        }
    }
}

struct GatePermit {
    gate: Arc<ConcurrencyGate>,
}

impl Drop for GatePermit {
    fn drop(&mut self) {
        if let Ok(mut available) = self.gate.available.lock() {
            *available += 1;
            self.gate.changed.notify_one();
        }
    }
}

/// A small synchronous client for a local clamd daemon.
#[derive(Debug)]
pub struct ClamAvClient {
    endpoint: String,
    connect_timeout: Duration,
    scan_timeout: Duration,
    max_stream_bytes: u64,
    retry_cooldown: Duration,
    gate: Arc<ConcurrencyGate>,
    unavailable_since: Mutex<Option<Instant>>,
    status: Mutex<ClamAvStatus>,
}

impl ClamAvClient {
    /// Build a client without connecting. A scan only attempts a connection
    /// when the request explicitly enables ClamAV.
    pub fn from_environment() -> Self {
        let endpoint = std::env::var("HELIOSAV_CLAMD_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let connect_timeout =
            env_duration_ms("HELIOSAV_CLAMD_CONNECT_TIMEOUT_MS").unwrap_or(DEFAULT_CONNECT_TIMEOUT);
        let scan_timeout =
            env_duration_ms("HELIOSAV_CLAMD_SCAN_TIMEOUT_MS").unwrap_or(DEFAULT_SCAN_TIMEOUT);
        let max_stream_bytes = std::env::var("HELIOSAV_CLAMD_MAX_STREAM_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_MAX_STREAM_BYTES);
        let max_inflight = std::env::var("HELIOSAV_CLAMD_MAX_INFLIGHT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_MAX_INFLIGHT);
        let retry_cooldown = std::env::var("HELIOSAV_CLAMD_RETRY_COOLDOWN_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_RETRY_COOLDOWN);
        Self::new(
            endpoint,
            connect_timeout,
            scan_timeout,
            max_stream_bytes,
            max_inflight,
            retry_cooldown,
        )
    }

    pub fn new(
        endpoint: String,
        connect_timeout: Duration,
        scan_timeout: Duration,
        max_stream_bytes: u64,
        max_inflight: usize,
        retry_cooldown: Duration,
    ) -> Self {
        Self {
            endpoint,
            connect_timeout,
            scan_timeout,
            max_stream_bytes: max_stream_bytes.max(1),
            retry_cooldown,
            gate: Arc::new(ConcurrencyGate::new(max_inflight)),
            unavailable_since: Mutex::new(None),
            status: Mutex::new(ClamAvStatus {
                message: "not probed".to_string(),
                ..ClamAvStatus::default()
            }),
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn status(&self) -> ClamAvStatus {
        self.status
            .lock()
            .map(|status| status.clone())
            .unwrap_or_else(|_| ClamAvStatus {
                message: "status lock poisoned".to_string(),
                ..ClamAvStatus::default()
            })
    }

    /// Probe clamd and cache a human-readable status for UI/diagnostic use.
    /// Unlike scans this bypasses the retry cooldown so an explicit probe can
    /// observe a daemon that just came back online.
    pub fn probe(&self) -> ClamAvStatus {
        let status = match self.query_version() {
            Ok(version) => {
                if let Ok(mut since) = self.unavailable_since.lock() {
                    *since = None;
                }
                ClamAvStatus {
                    available: true,
                    database_version: extract_database_version(&version),
                    version: Some(version.clone()),
                    message: format!("clamd ready at {}", self.endpoint),
                }
            }
            Err(error) => {
                if let Ok(mut since) = self.unavailable_since.lock() {
                    *since = Some(Instant::now());
                }
                ClamAvStatus {
                    available: false,
                    message: format!("clamd unavailable at {}: {error}", self.endpoint),
                    ..ClamAvStatus::default()
                }
            }
        };
        self.publish_status(status)
    }

    fn publish_status(&self, status: ClamAvStatus) -> ClamAvStatus {
        if let Ok(mut current) = self.status.lock() {
            *current = status.clone();
        }
        status
    }

    /// True when a previous connection attempt failed recently. Scans skip
    /// the network attempt during the cooldown window so a batch scan never
    /// pays the connect timeout once per file while clamd is down.
    fn in_retry_cooldown(&self) -> Option<Duration> {
        let since = *self
            .unavailable_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        since.map(|since| {
            self.retry_cooldown
                .saturating_sub(since.elapsed())
        })
    }

    fn note_connect_result(&self, result: &io::Result<TcpStream>) {
        match result {
            Ok(_) => {
                if let Ok(mut since) = self.unavailable_since.lock() {
                    *since = None;
                }
            }
            Err(_) => {
                if let Ok(mut since) = self.unavailable_since.lock() {
                    *since = Some(Instant::now());
                }
            }
        }
    }

    pub fn scan_path(&self, path: &Path) -> ClamAvVerdict {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return ClamAvVerdict::Unavailable {
                    message: format!("unable to read metadata: {error}"),
                }
            }
        };
        if metadata.len() > self.max_stream_bytes {
            return ClamAvVerdict::Unavailable {
                message: format!(
                    "file size {} exceeds clamd stream limit {}",
                    metadata.len(),
                    self.max_stream_bytes
                ),
            };
        }
        if let Some(remaining) = self.in_retry_cooldown() {
            return ClamAvVerdict::Unavailable {
                message: format!(
                    "clamd unavailable; retrying in {}s",
                    remaining.as_secs().max(1)
                ),
            };
        }

        let _permit = self.gate.acquire();
        let result = self.scan_path_inner(path);
        match &result {
            ClamAvVerdict::Found { signature } => {
                self.publish_status(ClamAvStatus {
                    available: true,
                    message: format!("threat found: {signature}"),
                    ..ClamAvStatus::default()
                });
            }
            ClamAvVerdict::Clean => {
                self.publish_status(ClamAvStatus {
                    available: true,
                    message: "last scan clean".to_string(),
                    ..ClamAvStatus::default()
                });
            }
            ClamAvVerdict::Unavailable { message } => {
                debug!("ClamAV scan unavailable for {}: {}", path.display(), message);
            }
        }
        result
    }

    fn query_version(&self) -> io::Result<String> {
        let mut stream = self.connect()?;
        stream.write_all(b"nVERSION\n")?;
        stream.flush()?;
        read_response(&mut stream).map(|response| trim_clamd_response(&response))
    }

    fn scan_path_inner(&self, path: &Path) -> ClamAvVerdict {
        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) => {
                return ClamAvVerdict::Unavailable {
                    message: format!("unable to open file: {error}"),
                }
            }
        };
        let mut stream = match self.connect() {
            Ok(stream) => stream,
            Err(error) => {
                return ClamAvVerdict::Unavailable {
                    message: format!("connection failed: {error}"),
                }
            }
        };
        if let Err(error) = stream.write_all(b"zINSTREAM\0") {
            return ClamAvVerdict::Unavailable {
                message: format!("unable to start clamd stream: {error}"),
            };
        }

        let mut buffer = vec![0_u8; STREAM_CHUNK_SIZE];
        loop {
            let read = match file.read(&mut buffer) {
                Ok(read) => read,
                Err(error) => {
                    return ClamAvVerdict::Unavailable {
                        message: format!("unable to read file: {error}"),
                    }
                }
            };
            if read == 0 {
                break;
            }
            let length = (read as u32).to_be_bytes();
            if let Err(error) = stream
                .write_all(&length)
                .and_then(|_| stream.write_all(&buffer[..read]))
            {
                return ClamAvVerdict::Unavailable {
                    message: format!("unable to send file to clamd: {error}"),
                };
            }
        }
        if let Err(error) = stream
            .write_all(&0_u32.to_be_bytes())
            .and_then(|_| stream.flush())
        {
            return ClamAvVerdict::Unavailable {
                message: format!("unable to finish clamd stream: {error}"),
            };
        }
        let response = match read_response(&mut stream) {
            Ok(response) => trim_clamd_response(&response),
            Err(error) => {
                return ClamAvVerdict::Unavailable {
                    message: format!("clamd response failed: {error}"),
                }
            }
        };
        parse_scan_response(&response)
    }

    fn connect(&self) -> io::Result<TcpStream> {
        let mut addresses = self.endpoint.to_socket_addrs()?;
        let address = addresses.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "clamd endpoint has no address")
        })?;
        let stream = TcpStream::connect_timeout(&address, self.connect_timeout);
        self.note_connect_result(&stream);
        let stream = stream?;
        stream.set_read_timeout(Some(self.scan_timeout))?;
        stream.set_write_timeout(Some(self.scan_timeout))?;
        Ok(stream)
    }
}

fn env_duration_ms(name: &str) -> Option<Duration> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
}

fn read_response(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut response = Vec::with_capacity(128);
    let mut buffer = [0_u8; 512];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
        if response.contains(&0) || response.contains(&b'\n') {
            break;
        }
        if response.len() >= MAX_RESPONSE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "clamd response exceeds limit",
            ));
        }
    }
    if response.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "clamd returned an empty response",
        ));
    }
    Ok(response)
}

fn trim_clamd_response(response: &[u8]) -> String {
    String::from_utf8_lossy(response)
        .trim_matches(|character: char| {
            character == '\0' || character == '\r' || character == '\n'
        })
        .trim()
        .to_string()
}

fn parse_scan_response(response: &str) -> ClamAvVerdict {
    let normalized = response.trim();
    if normalized.ends_with(" OK") || normalized == "OK" {
        return ClamAvVerdict::Clean;
    }
    if let Some(signature) = normalized.strip_suffix(" FOUND") {
        let signature = signature
            .strip_prefix("stream: ")
            .unwrap_or(signature)
            .trim();
        if !signature.is_empty() {
            return ClamAvVerdict::Found {
                signature: signature.to_string(),
            };
        }
    }
    ClamAvVerdict::Unavailable {
        message: format!("clamd returned: {normalized}"),
    }
}

fn extract_database_version(version: &str) -> Option<String> {
    version
        .split_whitespace()
        .find(|part| {
            part.starts_with("daily.")
                || part.starts_with("main.")
                || part.starts_with("bytecode.")
        })
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::{parse_scan_response, ClamAvClient, ClamAvVerdict};
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    #[test]
    fn parses_clean_response() {
        assert_eq!(parse_scan_response("stream: OK"), ClamAvVerdict::Clean);
    }

    #[test]
    fn parses_found_response() {
        assert_eq!(
            parse_scan_response("stream: Win.Trojan.Test FOUND"),
            ClamAvVerdict::Found {
                signature: "Win.Trojan.Test".to_string()
            }
        );
    }

    #[test]
    fn keeps_errors_explicit() {
        assert!(matches!(
            parse_scan_response("stream: ERROR"),
            ClamAvVerdict::Unavailable { .. }
        ));
    }

    #[test]
    fn failed_connection_starts_retry_cooldown() {
        let directory = tempdir().expect("temporary directory");
        let sample = directory.path().join("sample.bin");
        std::fs::write(&sample, b"ordinary bytes").expect("sample fixture");

        // Port 1 on loopback refuses connections immediately.
        let client = ClamAvClient::new(
            "127.0.0.1:1".to_string(),
            Duration::from_millis(250),
            Duration::from_millis(500),
            1024 * 1024,
            1,
            Duration::from_secs(300),
        );

        let first = client.scan_path(&sample);
        assert!(
            first.message_contains("connection failed"),
            "unexpected first verdict message: {:?}",
            first
        );
        assert!(!client.status().available);

        // The second attempt must short-circuit without another TCP attempt.
        let started = Instant::now();
        let second = client.scan_path(&sample);
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "cooldown fast path did not skip the connect attempt"
        );
        assert!(
            second.message_contains("retrying in"),
            "unexpected cooldown verdict message: {:?}",
            second
        );

        // An explicit probe bypasses the cooldown and refreshes state again.
        let probed = client.probe();
        assert!(!probed.available);
    }
}