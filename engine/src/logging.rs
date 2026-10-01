//! File-only logging for the standalone engine.
//!
//! The engine's stdout and stderr are protocol channels when it runs in
//! NDJSON mode.  This logger deliberately never falls back to either stream.

use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

struct FileLogger {
    file: Mutex<File>,
    level: log::LevelFilter,
}

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let line = format!(
            "{}.{:03} [{}] [{}] {}\n",
            timestamp.as_secs(),
            timestamp.subsec_millis(),
            record.level(),
            record.target(),
            record.args()
        );

        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }

    fn flush(&self) {
        if let Ok(mut file) = self.file.lock() {
            let _ = file.flush();
        }
    }
}

static LOGGER: OnceLock<FileLogger> = OnceLock::new();

fn append_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = std::env::var_os("EVERBLOOM_LOG_FILE") {
        append_unique(&mut paths, PathBuf::from(path));
    }

    if let Ok(current_dir) = std::env::current_dir() {
        append_unique(
            &mut paths,
            current_dir
                .join("data")
                .join("logs")
                .join("everbloom-engine.log"),
        );
    }

    append_unique(
        &mut paths,
        std::env::temp_dir()
            .join("EverbloomSecurity")
            .join("everbloom-engine.log"),
    );
    paths
}

fn open_log_file(path: &Path) -> Option<File> {
    if let Some(parent) = path.parent() {
        if create_dir_all(parent).is_err() {
            return None;
        }
    }

    OpenOptions::new().create(true).append(true).open(path).ok()
}

fn configured_level() -> log::LevelFilter {
    std::env::var("EVERBLOOM_LOG_LEVEL")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(log::LevelFilter::Info)
}

/// Initializes a logger that writes only to a file.
pub fn initialize() {
    if log::max_level() != log::LevelFilter::Off {
        return;
    }

    let level = configured_level();
    for path in candidate_paths() {
        let Some(file) = open_log_file(&path) else {
            continue;
        };

        let logger = LOGGER.get_or_init(|| FileLogger {
            file: Mutex::new(file),
            level,
        });
        if log::set_logger(logger).is_ok() {
            log::set_max_level(level);
        }
        return;
    }
}

/// Routes panic-hook messages to the file logger instead of stderr.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|panic| {
        log::error!("engine panic captured: {}", panic);
    }));
}
