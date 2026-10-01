fn write_record(paths: &QuarantinePaths, record: &QuarantineRecord) -> Result<(), QuarantineError> {
    let final_path = metadata_path(paths, &record.id);
    let temp_path = final_path.with_extension("json.tmp");
    let encrypt_quarantine = std::env::var("EVERBLOOM_ENCRYPT_QUARANTINE").is_ok();

    let serialized = serde_json::to_vec(record).map_err(|error| {
        QuarantineError::Storage(format!("failed to serialize quarantine record: {error}"))
    })?;

    let bytes_to_write = if encrypt_quarantine {
        let cipher = crate::crypto::EverbloomCipher::new_from_seed(b"EVERBLOOM_QUARANTINE_ENCRYPTION_KEY");
        let mut ciphertext = serialized.clone();
        cipher.apply_keystream(&mut ciphertext);
        // Keep the original plaintext JSON at the .json path for recovery/debug.
        let original_writer = File::create(&final_path).map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to create original quarantine metadata {}: {}",
                final_path.display(), error
            ))
        })?;
        let mut original_buf = BufWriter::new(original_writer);
        serde_json::to_writer_pretty(&mut original_buf, record).map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to write original metadata {}: {}", final_path.display(), error
            ))
        })?;
        original_buf.write_all(b"\n").map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to finish original metadata {}: {}", final_path.display(), error
            ))
        })?;
        original_buf.flush().map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to flush original metadata {}: {}", final_path.display(), error
            ))
        })?;
        original_buf.get_ref().sync_all().map_err(|error| {
            QuarantineError::Storage(format!(
                "failed to sync original metadata {}: {}", final_path.display(), error
            ))
        })?;
        ciphertext
    } else {
        serialized
    };

    let output_writer = File::create(&temp_path).map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to create quarantine metadata {}: {}",
            temp_path.display(), error
        ))
    })?;
    let mut writer = BufWriter::new(output_writer);
    writer.write_all(&bytes_to_write).map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to write quarantine metadata {}: {}",
            temp_path.display(), error
        ))
    })?;
    writer.write_all(b"\n").map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to finish quarantine metadata {}: {}",
            temp_path.display(), error
        ))
    })?;
    writer.flush().map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to flush quarantine metadata {}: {}",
            temp_path.display(), error
        ))
    })?;
    writer.get_ref().sync_all().map_err(|error| {
        QuarantineError::Storage(format!(
            "failed to sync quarantine metadata {}: {}",
            temp_path.display(), error
        ))
    })?;

    // If encryption is enabled, the ciphertext file gets the .enc extension;
    // the plaintext JSON remains at .json (already written above).
    if encrypt_quarantine {
        let enc_path = final_path.with_extension("json.enc");
        fs::rename(&temp_path, &enc_path).map_err(|error| {
            let _ = fs::remove_file(&temp_path);
            QuarantineError::Storage(format!(
                "failed to commit encrypted quarantine metadata {}: {}",
                enc_path.display(), error
            ))
        })
    } else {
        if final_path.exists() {
            fs::remove_file(&final_path).map_err(|error| {
                let _ = fs::remove_file(&temp_path);
                QuarantineError::Storage(format!(
                    "failed to replace quarantine metadata {}: {}",
                    final_path.display(), error
                ))
            })?;
        }
        fs::rename(&temp_path, &final_path).map_err(|error| {
            let _ = fs::remove_file(&temp_path);
            QuarantineError::Storage(format!(
                "failed to commit quarantine metadata {}: {}",
                final_path.display(), error
            ))
        })
    }
}
