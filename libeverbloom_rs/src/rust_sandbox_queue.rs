//! Python-facing queue adapter for the canonical engine sandbox.
//!
//! The Python extension must not carry a second AppContainer/Windows Sandbox
//! implementation.  Keeping this module limited to queueing and report
//! serialization means policy, timeout, cleanup and guest memory collection
//! all come from `everbloom_engine::sandbox`.

use flume::{Receiver, Sender};
use everbloom_engine::sandbox::{run_sandbox, SandboxReport};
use pyo3::prelude::*;
use serde::Serialize;
use sha2::Digest;
use std::fs;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

const DEFAULT_QUEUE_SIZE: usize = 128;
const MIN_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 10 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct SandboxTask {
    pub priority: u8,
    pub path: String,
}

#[derive(Debug, Serialize)]
struct SandboxExecutionReport {
    task_path: String,
    priority: u8,
    exit_code: Option<i32>,
    target_pid: Option<u32>,
    duration_ms: u128,
    timed_out: bool,
    isolation_backend: String,
    isolation_verified: bool,
    cleanup_verified: bool,
    resource_limits: Vec<String>,
    api_calls: Vec<String>,
    files_written: Vec<String>,
    registry_writes: Vec<String>,
    network_connections: Vec<String>,
    processes: Vec<String>,
    stdout: String,
    stderr: String,
    unpacking: everbloom_engine::layers::memory_snapshot::SandboxUnpackingReport,
}

#[pyclass]
pub struct SandboxQueue {
    sender: Sender<SandboxTask>,
    receiver: Arc<Mutex<Receiver<SandboxTask>>>,
    output_dir: Arc<Mutex<Option<PathBuf>>>,
    worker_started: Arc<AtomicBool>,
}

#[pymethods]
impl SandboxQueue {
    #[new]
    pub fn new(buffer_size: Option<usize>) -> Self {
        let (sender, receiver) = flume::bounded(buffer_size.unwrap_or(DEFAULT_QUEUE_SIZE).max(1));
        Self {
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            output_dir: Arc::new(Mutex::new(None)),
            worker_started: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn enqueue(&self, priority: u8, path: String) -> PyResult<bool> {
        match self.sender.try_send(SandboxTask { priority, path }) {
            Ok(()) => Ok(true),
            Err(flume::TrySendError::Full(_)) => Ok(false),
            Err(flume::TrySendError::Disconnected(_)) => {
                Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "sandbox worker queue is disconnected",
                ))
            }
        }
    }

    pub fn set_output_dir(&self, path: String) -> PyResult<()> {
        let output_dir = PathBuf::from(path);
        fs::create_dir_all(&output_dir).map_err(|error| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                "failed to create output dir: {error}"
            ))
        })?;
        *self.output_dir.lock().map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("sandbox output lock poisoned")
        })? = Some(output_dir);
        Ok(())
    }

    pub fn start_worker(&self) {
        if self
            .worker_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let receiver = Arc::clone(&self.receiver);
        let output_dir = Arc::clone(&self.output_dir);
        let worker_started = Arc::clone(&self.worker_started);
        thread::spawn(move || {
            while let Ok(task) = receiver.lock().map(|queue| queue.recv()) {
                let Ok(task) = task else { break };
                let report = execute_sandbox_task(&task);
                if let Some(path) =
                    report_path(&task, output_dir.lock().ok().and_then(|dir| dir.clone()))
                {
                    if let Some(parent) = path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    if let Ok(json) = serde_json::to_string_pretty(&report) {
                        let _ = fs::write(path, json);
                    }
                }
            }
            worker_started.store(false, Ordering::Release);
        });
    }
}

fn execute_sandbox_task(task: &SandboxTask) -> SandboxExecutionReport {
    let timeout = configured_timeout();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return failure_report(
                task,
                &format!("sandbox runtime initialization failed: {error}"),
            );
        }
    };

    match runtime.block_on(run_sandbox(PathBuf::from(&task.path), timeout)) {
        Ok(report) => convert_report(task, report),
        Err(error) => failure_report(task, &error.to_string()),
    }
}

fn convert_report(task: &SandboxTask, report: SandboxReport) -> SandboxExecutionReport {
    SandboxExecutionReport {
        task_path: task.path.clone(),
        priority: task.priority,
        exit_code: report.exit_code,
        target_pid: report.target_pid,
        duration_ms: report.duration_ms,
        timed_out: report.timed_out,
        isolation_backend: report.isolation_backend,
        isolation_verified: report.isolation_verified,
        cleanup_verified: report.cleanup_verified,
        resource_limits: report.resource_limits,
        api_calls: report.api_calls,
        files_written: report
            .files_changed
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        registry_writes: report.registry_writes,
        network_connections: report.network_connections,
        processes: report.processes,
        stdout: String::new(),
        stderr: String::new(),
        unpacking: report.unpacking,
    }
}

fn failure_report(task: &SandboxTask, message: &str) -> SandboxExecutionReport {
    SandboxExecutionReport {
        task_path: task.path.clone(),
        priority: task.priority,
        exit_code: None,
        target_pid: None,
        duration_ms: 0,
        timed_out: false,
        isolation_backend: "none".to_string(),
        isolation_verified: false,
        cleanup_verified: true,
        resource_limits: Vec::new(),
        api_calls: vec!["blocked:no_unified_sandbox_result".to_string()],
        files_written: Vec::new(),
        registry_writes: Vec::new(),
        network_connections: Vec::new(),
        processes: Vec::new(),
        stdout: String::new(),
        stderr: message.to_string(),
        unpacking: everbloom_engine::layers::memory_snapshot::SandboxUnpackingReport::unavailable(
            message.to_string(),
        ),
    }
}

fn configured_timeout() -> Duration {
    let millis = std::env::var("EVERBLOOM_SANDBOX_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(120_000)
        .clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
    Duration::from_millis(millis)
}

fn report_path(task: &SandboxTask, output_dir: Option<PathBuf>) -> Option<PathBuf> {
    let directory = output_dir?;
    let digest = sha2::Sha256::digest(task.path.as_bytes());
    Some(directory.join(format!("{}.json", hex::encode(digest))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_is_clamped_to_safe_bounds() {
        assert!(configured_timeout() >= Duration::from_millis(MIN_TIMEOUT_MS));
        assert!(configured_timeout() <= Duration::from_millis(MAX_TIMEOUT_MS));
    }

    #[test]
    fn report_path_is_stable_and_does_not_use_sample_name() {
        let task = SandboxTask {
            priority: 1,
            path: r"C:\sample.exe".to_string(),
        };
        let first = report_path(&task, Some(PathBuf::from("out"))).unwrap();
        let second = report_path(&task, Some(PathBuf::from("out"))).unwrap();
        assert_eq!(first, second);
        assert!(!first.to_string_lossy().contains("sample.exe"));
    }
}
