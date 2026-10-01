//! Persistent file quarantine support.
//!
//! Quarantined files are moved out of their original location into a fixed
//! quarantine root, encoded with a small non-executable container format, and
//! paired with durable JSON metadata.  The original file is removed only after
//! the encoded copy has been successfully submitted.
//!
//! The quarantine container uses a portable byte-level encoding (XOR 0xA5) so
//! that payloads can be safely moved across users and systems without relying
//! on Windows DPAPI secrets.  A backup format (`EVERBLOOM-QUARANTINE-BACKUP-v1`)
//! allows the store to be exported (`export_quarantine`) and replayed
//! (`import_quarantine`) on any machine.
//!
//! Optional metadata encryption (via `EVERBLOOM_ENCRYPT_QUARANTINE`) uses the
//! custom EverbloomSecurity stream cipher (`engine/src/crypto.rs`) to produce a
//! `.json.enc` file; the plaintext `.json` remains for recovery and debug.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ENCRYPTION_KEY_ENV: &str = "EVERBLOOM_QUARANTINE_ENCRYPTION_KEY";
            error
        ))
    })?;

    let mut record = QuarantineRecord {
        id: id.clone(),
        original_path: source.to_string_lossy().to_string(),
        file_name,
        quarantine_path: object_path.to_string_lossy().to_string(),
        sha256,
        size,
        reason: reason
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        status: "pending".to_string(),
        quarantined_at: timestamp,
        restored_at: None,
        restored_to: None,
        deleted_at: None,
    };
    write_record(&paths, &record)?;

    if let Err(error) = fs::remove_file(&source) {
        let _ = fs::remove_file(&object_path);
        let _ = fs::remove_file(metadata_path(&paths, &id));
        return Err(QuarantineError::FileAccess(format!(
            "failed to remove original file {} after quarantine copy: {}",
            source.display(),
            error
        )));
    }

    record.status = "active".to_string();
    write_record(&paths, &record)?;
    Ok(QuarantineActionReport {
        action: "quarantine".to_string(),
        message: format!("file quarantined: {}", record.id),
        id: Some(record.id.clone()),
        original_path: Some(record.original_path.clone()),
        quarantine_path: Some(record.quarantine_path.clone()),
        restore_path: None,
        status: Some(record.status.clone()),
        records: vec![record],
    })
}

pub fn restore_quarantine(
    id: &str,
    restore_path: Option<&str>,
    overwrite: bool,
) -> Result<QuarantineActionReport, QuarantineError> {
    let paths = prepare_paths()?;
    let id = validate_record_id(id)?;
    let mut record = read_record(&paths, id)?;
    if record.status != "active" {
        return Err(QuarantineError::InvalidRequest(format!(
            "quarantine item {} is not active",
            id
        )));
    }

    let destination = restore_path
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&record.original_path));
    if destination.exists() && !overwrite {
        return Err(QuarantineError::AlreadyExists(
            destination.display().to_string(),
        ));
    }
    if let Some(parent) = destination
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            QuarantineError::FileAccess(format!(
                "failed to create restore directory {}: {}",
                parent.display(),
                error
            ))
        })?;
    }

    let temp_restore = destination.with_extension(format!(
        "{}.everbloom-restore.tmp",
        destination
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("file")
    ));
    let object_path = PathBuf::from(&record.quarantine_path);
    decode_object_to_path(&object_path, &temp_restore, &record.sha256)?;
    if destination.exists() {
        fs::remove_file(&destination).map_err(|error| {
            let _ = fs::remove_file(&temp_restore);
            QuarantineError::FileAccess(format!(
                "failed to replace existing restore target {}: {}",
                destination.display(),
                error
            ))
        })?;
    }
    fs::rename(&temp_restore, &destination).map_err(|error| {
        let _ = fs::remove_file(&temp_restore);
        QuarantineError::FileAccess(format!(
            "failed to finalize restore to {}: {}",
            destination.display(),
            error
        ))
    })?;

    let _ = fs::remove_file(&object_path);
    record.status = "restored".to_string();
    record.restored_at = Some(unix_seconds());
    record.restored_to = Some(destination.to_string_lossy().to_string());
    write_record(&paths, &record)?;

    Ok(QuarantineActionReport {
        action: "restore".to_string(),
        message: format!("quarantine item restored: {}", record.id),
        id: Some(record.id.clone()),
        original_path: Some(record.original_path.clone()),
        quarantine_path: Some(record.quarantine_path.clone()),
        restore_path: record.restored_to.clone(),
        status: Some(record.status.clone()),
        records: vec![record],
    })
}

pub fn delete_quarantine(id: &str) -> Result<QuarantineActionReport, QuarantineError> {
    let paths = prepare_paths()?;
    let id = validate_record_id(id)?;
    let mut record = read_record(&paths, id)?;
    let object_path = PathBuf::from(&record.quarantine_path);
    if object_path.exists() {
        fs::remove_file(&object_path).map_err(|error| {
            QuarantineError::FileAccess(format!(
                "failed to permanently delete quarantine object {}: {}",
                object_path.display(),
                error
            ))
        })?;
    }
    record.status = "deleted".to_string();
    record.deleted_at = Some(unix_seconds());
    write_record(&paths, &record)?;
    Ok(QuarantineActionReport {
        action: "delete".to_string(),
        message: format!("quarantine item permanently deleted: {}", record.id),
        id: Some(record.id.clone()),
        original_path: Some(record.original_path.clone()),
        quarantine_path: Some(record.quarantine_path.clone()),
        restore_path: None,
        status: Some(record.status.clone()),
        records: vec![record],
    })
}

pub fn list_quarantine(include_inactive: bool) -> Result<QuarantineActionReport, QuarantineError> {
    let paths = prepare_paths()?;
    let mut records = Vec::new();
    let entries = fs::read_dir(&paths.metadata).map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to read quarantine metadata directory {}: {}",
            paths.metadata.display(),
            error
        ))
    })?;
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        match read_record_file(&path) {
            Ok(record) if include_inactive || record.status == "active" => records.push(record),
            Ok(_) => {}
            Err(error) => log::warn!(
                "ignoring unreadable quarantine metadata {}: {}",
                path.display(),
                error
            ),
        }
    }
    records.sort_by(|left, right| {
        right
            .quarantined_at
            .cmp(&left.quarantined_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(QuarantineActionReport {
        action: "list".to_string(),
        message: format!("quarantine records listed: {}", records.len()),
        id: None,
        original_path: None,
        quarantine_path: None,
        restore_path: None,
        status: None,
        records,
    })
}

/// Serializes the active quarantine store into a portable backup file.
///
/// The container is a sequence of length-prefixed records:
/// header, version, u32 record count, then per record:
///   u32 metadata length + metadata JSON, u64 object length + stored bytes.
/// Both the metadata (plaintext JSON) and the encoded object bytes round-trip
/// across users and machines because the quarantine payload is a portable
/// structural transform (see `HEADER`/`XOR_KEY`), not a user DPAPI secret.
pub fn export_quarantine(
    destination: impl AsRef<Path>,
) -> Result<QuarantineActionReport, QuarantineError> {
    let destination = destination.as_ref();
    if let Some(parent) = destination
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            QuarantineError::FileAccess(format!(
                "failed to create backup directory {}: {}",
                parent.display(),
                error
            ))
        })?;
    }
    let file = File::create(destination).map_err(|error| {
        QuarantineError::FileAccess(format!(
            "failed to create backup file {}: {}",
            destination.display(),
            error
        ))
    })?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(BACKUP_HEADER)
        .map_err(|error| format_io_error("failed to write backup header", error))?;
    writer
        .write_all(&BACKUP_FORMAT_VERSION.to_le_bytes())
        .map_err(|error| format_io_error("failed to write backup version", error))?;

    let listed = list_quarantine(true)?;
    let active: Vec<QuarantineRecord> = listed
        .records
        .into_iter()
        .filter(|record| record.status == "active")
        .collect();
    writer
        .write_all(&(active.len() as u32).to_le_bytes())
        .map_err(|error| format_io_error("failed to write backup record count", error))?;

    let mut exported = 0usize;
    for record in &active {
        let metadata_json = serde_json::to_vec(record).map_err(|error| {
            QuarantineError::Storage(format!("failed to serialize quarantine record: {error}"))
        })?;
        if metadata_json.len() as u32 > MAX_BACKUP_METADATA_BYTES {
            return Err(QuarantineError::Storage(
                "quarantine record metadata exceeds backup limit".to_string(),
            ));
        }
        writer
            .write_all(&(metadata_json.len() as u32).to_le_bytes())
            .map_err(|error| format_io_error("failed to write backup metadata length", error))?;
        writer
            .write_all(&metadata_json)
            .map_err(|error| format_io_error("failed to write backup metadata", error))?;

        let object_path = PathBuf::from(&record.quarantine_path);
        let object_bytes = fs::read(&object_path).map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to read quarantine object {} for backup: {}",
                object_path.display(),
                error
            ))
        })?;
        if object_bytes.len() as u64 > MAX_BACKUP_OBJECT_BYTES {
            return Err(QuarantineError::Storage(format!(
                "quarantine object {} exceeds backup size limit",
                object_path.display()
            )));
        }
        writer
            .write_all(&(object_bytes.len() as u64).to_le_bytes())
            .map_err(|error| format_io_error("failed to write backup object length", error))?;
        writer
            .write_all(&object_bytes)
            .map_err(|error| format_io_error("failed to write backup object", error))?;
        exported += 1;
    }
    writer
        .flush()
        .map_err(|error| format_io_error("failed to flush backup", error))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|error| format_io_error("failed to sync backup", error))?;

    Ok(QuarantineActionReport {
        action: "export".to_string(),
        message: format!("quarantine backup exported: {exported} active record(s)"),
        id: None,
        original_path: None,
        quarantine_path: Some(destination.to_string_lossy().to_string()),
        restore_path: None,
        status: None,
        records: active,
    })
}

/// Imports a backup written by `export_quarantine` into the current store.
/// Objects whose id already exists are skipped so a replay cannot overwrite an
/// item that was separately restored or deleted after the backup.
pub fn import_quarantine(
    source: impl AsRef<Path>,
) -> Result<QuarantineActionReport, QuarantineError> {
    let paths = prepare_paths()?;
    let source = source.as_ref();
    let file = File::open(source).map_err(|error| {
        QuarantineError::FileAccess(format!(
            "failed to open quarantine backup {}: {}",
            source.display(),
            error
        ))
    })?;
    let mut reader = BufReader::new(file);

    let mut header = vec![0u8; BACKUP_HEADER.len()];
    reader
        .read_exact(&mut header)
        .map_err(|error| format_io_error("failed to read backup header", error))?;
    if header != BACKUP_HEADER {
        return Err(QuarantineError::InvalidRequest(
            "not a EverbloomSecurity quarantine backup file".to_string(),
        ));
    }
    let mut version = [0u8; 4];
    reader
        .read_exact(&mut version)
        .map_err(|error| format_io_error("failed to read backup version", error))?;
    if u32::from_le_bytes(version) != BACKUP_FORMAT_VERSION {
        return Err(QuarantineError::InvalidRequest(format!(
            "unsupported quarantine backup version: {}",
            u32::from_le_bytes(version)
        )));
    }
    let mut count_bytes = [0u8; 4];
    reader
        .read_exact(&mut count_bytes)
        .map_err(|error| format_io_error("failed to read backup record count", error))?;
    let count = u32::from_le_bytes(count_bytes);

    let mut imported = 0usize;
    let mut skipped = 0usize;
    for _ in 0..count {
        let mut metadata_len = [0u8; 4];
        reader
            .read_exact(&mut metadata_len)
            .map_err(|error| format_io_error("failed to read backup metadata length", error))?;
        let metadata_len = u32::from_le_bytes(metadata_len);
        if metadata_len == 0 || metadata_len > MAX_BACKUP_METADATA_BYTES {
            return Err(QuarantineError::InvalidRequest(
                "quarantine backup contains an invalid metadata length".to_string(),
            ));
        }
        let mut metadata_json = vec![0u8; metadata_len as usize];
        reader
            .read_exact(&mut metadata_json)
            .map_err(|error| format_io_error("failed to read backup metadata", error))?;
        let record: QuarantineRecord = serde_json::from_slice(&metadata_json).map_err(|error| {
            QuarantineError::InvalidRequest(format!(
                "quarantine backup contains invalid metadata: {error}"
            ))
        })?;
        let id = validate_record_id(&record.id)?.to_string();

        let mut object_len = [0u8; 8];
        reader
            .read_exact(&mut object_len)
            .map_err(|error| format_io_error("failed to read backup object length", error))?;
        let object_len = u64::from_le_bytes(object_len);
        if object_len > MAX_BACKUP_OBJECT_BYTES {
            return Err(QuarantineError::InvalidRequest(
                "quarantine backup contains an oversized object".to_string(),
            ));
        }
        let mut object_bytes = vec![0u8; object_len as usize];
        reader
            .read_exact(&mut object_bytes)
            .map_err(|error| format_io_error("failed to read backup object", error))?;

        let object_path = paths.objects.join(format!("{id}.everbloomq"));
        let final_metadata_path = metadata_path(&paths, &id);
        if object_path.exists() || final_metadata_path.exists() {
            skipped += 1;
            continue;
        }
        fs::write(&object_path, &object_bytes).map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to write imported quarantine object {}: {}",
                object_path.display(),
                error
            ))
        })?;
        let mut mutated = record;
        mutated.quarantine_path = object_path.to_string_lossy().to_string();
        mutated.status = "active".to_string();
        write_record(&paths, &mutated)?;
        imported += 1;
    }

    Ok(QuarantineActionReport {
        action: "import".to_string(),
        message: format!("quarantine backup imported: {imported} record(s), {skipped} skipped"),
        id: None,
        original_path: None,
        quarantine_path: Some(source.to_string_lossy().to_string()),
        restore_path: None,
        status: None,
        records: Vec::new(),
    })
}

fn format_io_error(context: &str, error: std::io::Error) -> QuarantineError {
    QuarantineError::Storage(format!("{context}: {error}"))
}

fn prepare_paths() -> Result<QuarantinePaths, QuarantineError> {
    let root = quarantine_root();
    let objects = root.join("objects");
    let metadata = root.join("metadata");
    fs::create_dir_all(&objects).map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to create quarantine object directory {}: {}",
            objects.display(),
            error
        ))
    })?;
    fs::create_dir_all(&metadata).map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to create quarantine metadata directory {}: {}",
            metadata.display(),
            error
        ))
    })?;
    Ok(QuarantinePaths {
        root,
        objects,
        metadata,
    })
}

fn quarantine_root() -> PathBuf {
    if let Some(path) = std::env::var_os("EVERBLOOM_QUARANTINE_DIR") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(path).join("EverbloomSecurity").join("quarantine");
    }
    if let Some(path) = std::env::var_os("PROGRAMDATA") {
        return PathBuf::from(path).join("EverbloomSecurity").join("quarantine");
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("data")
        .join("quarantine")
}

fn canonical_file_path(path: &Path) -> Result<PathBuf, QuarantineError> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        QuarantineError::FileAccess(format!("failed to open {}: {}", path.display(), error))
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        QuarantineError::FileAccess(format!(
            "failed to read metadata for {}: {}",
            canonical.display(),
            error
        ))
    })?;
    if !metadata.is_file() {
        return Err(QuarantineError::InvalidRequest(format!(
            "{} is not a regular file",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn ensure_outside_quarantine(source: &Path, root: &Path) -> Result<(), QuarantineError> {
    let canonical_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    if source.starts_with(&canonical_root) {
        return Err(QuarantineError::InvalidRequest(
            "refusing to quarantine a file that is already inside the quarantine store".to_string(),
        ));
    }
    Ok(())
}

fn copy_encoded_with_hash(
    source: &Path,
    destination: &Path,
) -> Result<(String, u64), QuarantineError> {
    let input = File::open(source).map_err(|error| {
        QuarantineError::FileAccess(format!("failed to read {}: {}", source.display(), error))
    })?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to create quarantine object {}: {}",
                destination.display(),
                error
            ))
        })?;
    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);
    writer.write_all(HEADER).map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to write quarantine header {}: {}",
            destination.display(),
            error
        ))
    })?;

    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            QuarantineError::FileAccess(format!(
                "failed to read {} while quarantining: {}",
                source.display(),
                error
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
        for byte in &mut buffer[..read] {
            *byte ^= XOR_KEY;
        }
        writer.write_all(&buffer[..read]).map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to write encoded quarantine object {}: {}",
                destination.display(),
                error
            ))
        })?;
    }
    writer.flush().map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to flush quarantine object {}: {}",
            destination.display(),
            error
        ))
    })?;
    writer.get_ref().sync_all().map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to sync quarantine object {}: {}",
            destination.display(),
            error
        ))
    })?;
    Ok((format!("{:x}", hasher.finalize()), size))
}

fn decode_object_to_path(
    object_path: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<u64, QuarantineError> {
    let input = File::open(object_path).map_err(|error| {
        QuarantineError::FileAccess(format!(
            "failed to read quarantine object {}: {}",
            object_path.display(),
            error
        ))
    })?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| {
            QuarantineError::FileAccess(format!(
                "failed to create restore target {}: {}",
                destination.display(),
                error
            ))
        })?;
    let mut reader = BufReader::new(input);
    let mut header = vec![0u8; HEADER.len()];
    reader.read_exact(&mut header).map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to read quarantine header {}: {}",
            object_path.display(),
            error
        ))
    })?;
    if header != HEADER {
        return Err(QuarantineError::Storage(format!(
            "invalid quarantine object header: {}",
            object_path.display()
        )));
    }

    let mut writer = BufWriter::new(output);
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to read quarantine payload {}: {}",
                object_path.display(),
                error
            ))
        })?;
        if read == 0 {
            break;
        }
        for byte in &mut buffer[..read] {
            *byte ^= XOR_KEY;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
        writer.write_all(&buffer[..read]).map_err(|error| {
            QuarantineError::FileAccess(format!(
                "failed to write restore target {}: {}",
                destination.display(),
                error
            ))
        })?;
    }
    writer.flush().map_err(|error| {
        QuarantineError::FileAccess(format!(
            "failed to flush restore target {}: {}",
            destination.display(),
            error
        ))
    })?;
    writer.get_ref().sync_all().map_err(|error| {
        QuarantineError::FileAccess(format!(
            "failed to sync restore target {}: {}",
            destination.display(),
            error
        ))
    })?;
    let actual_sha256 = format!("{:x}", hasher.finalize());
    if !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
        let _ = fs::remove_file(destination);
        return Err(QuarantineError::Storage(format!(
            "quarantine object hash mismatch for {}",
            object_path.display()
        )));
    }
    Ok(size)
}

fn write_record(paths: &QuarantinePaths, record: &QuarantineRecord) -> Result<(), QuarantineError> {
    let final_path = metadata_path(paths, &record.id);
    let temp_path = final_path.with_extension("json.tmp");
    let encrypt_quarantine = std::env::var("EVERBLOOM_ENCRYPT_QUARANTINE").is_ok();
    let output_path = if encrypt_quarantine {
        final_path.with_extension("json.enc")
    } else {
        final_path.clone()
    };
    // When encryption is enabled (EVERBLOOM_ENCRYPT_QUARANTINE), serialize the
    // record to JSON bytes, encrypt with the custom stream cipher, and write
    // the ciphertext to the .json.enc file. The original plaintext JSON is
    // kept at the .json path for recovery/debug verification.
    let metadata_bytes = if encrypt_quarantine {
        let plaintext_json = serde_json::to_vec(record).map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to serialize quarantine record for encryption: {error}"
            ))
        })?;
        let cipher = crate::crypto::EverbloomCipher::new_from_seed(b"EVERBLOOM_QUARANTINE_ENCRYPTION_KEY");
        let mut ciphertext = plaintext_json.clone();
        cipher.apply_keystream(&mut ciphertext);
        // Also write the original .json for verification/recovery.
        let original_writer = File::create(&final_path).map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to create original quarantine metadata {}: {}",
                final_path.display(),
                error
            ))
        })?;
        let mut original_buf = BufWriter::new(original_writer);
        serde_json::to_writer_pretty(&mut original_buf, record).map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to write original metadata {}: {}",
                final_path.display(), error
            ))
        })?;
        original_buf.write_all(b"\n").map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to finish original metadata {}: {}",
                final_path.display(), error
            ))
        })?;
        original_buf.flush().map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to flush original metadata {}: {}",
                final_path.display(), error
            ))
        })?;
        original_buf.get_ref().sync_all().map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to sync original metadata {}: {}",
                final_path.display(), error
            ))
        })?;
        ciphertext
    } else {
        serde_json::to_vec(record).map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to serialize quarantine record: {error}"
            ))
        })?
    };

    let encrypted_writer_path = if encrypt_quarantine { &output_path } else { &final_path };
    let encrypted_writer = File::create(&temp_path).map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to create quarantine metadata {}: {}",
            temp_path.display(),
            error
        ))
    })?;
    let mut writer = BufWriter::new(encrypted_writer);
    serde_json::to_writer_pretty(&mut writer, record).map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to serialize quarantine metadata {}: {}",
            temp_path.display(),
            error
        ))
    })?;
    writer.write_all(&bytes_to_write).map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to write quarantine metadata {}: {}",
            temp_path.display(),
            error
        ))
    })?;
    writer.write_all(b"\n").map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to finish quarantine metadata {}: {}",
            temp_path.display(),
            error
        ))
    })?;
    writer.flush().map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to flush quarantine metadata {}: {}",
            temp_path.display(),
            error
        ))
    })?;
    writer.get_ref().sync_all().map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to sync quarantine metadata {}: {}",
            temp_path.display(),
            error
        ))
    })?;
    let rename_target = if encrypt_quarantine {
        final_path.with_extension("json.enc")
    } else {
        final_path.clone()
    };
    if final_path.exists() && !encrypt_quarantine {
        fs::remove_file(&final_path).map_err(|error| {
            let _ = fs::remove_file(&temp_path);
            QuarantineError::Storage(format!(
                "failed to replace quarantine metadata {}: {}",
                final_path.display(),
                error
            ))
        })?;
    }
    fs::rename(&temp_path, &rename_target).map_err(|error| {
        let _ = fs::remove_file(&temp_path);
        QuarantineError::Storage(format!(
            "failed to commit quarantine metadata {}: {}",
            rename_target.display(),
            error
        ))
    })
}

/// Returns the encryption key from the environment variable, if configured.
/// When not set, quarantine metadata is written in plaintext (backward compatible).
fn quarantine_encryption_key() -> Option<Vec<u8>> {
    std::env::var(ENCRYPTION_KEY_ENV).ok().map(|v| v.into_bytes())
}

/// Check if quarantine metadata encryption is enabled.
pub fn quarantine_encryption_enabled() -> bool {
    std::env::var(ENCRYPTION_KEY_ENV).map_or(false, |v| !v.trim().is_empty())
}

